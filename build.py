#!/usr/bin/env python3
"""Local KN-3013 image builder. Never contacts the configured VPN endpoint."""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import Request, urlopen
import warnings
import zipfile

from lib.client import parse_vless, add_routing
from lib.image import verify_image
from lib.sdk import prepare_sdk

KIT = Path(__file__).resolve().parent


class BuildError(Exception):
    """A safe message that never includes a user's connection parameters."""


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def obtain(spec, destination, source=None):
    """Only write verified bytes; the manifest contains public HTTPS URLs."""
    temporary = destination.with_suffix(destination.suffix + '.partial')
    try:
        if source is not None:
            if not source.is_file() or source.stat().st_size > spec['max_bytes']:
                raise BuildError('Missing or oversized local input file.')
            shutil.copyfile(source, temporary)
        else:
            if not spec['url'].startswith('https://'):
                raise BuildError('Manifest download must use HTTPS.')
            request = Request(spec['url'], headers={'User-Agent': 'kn3013-local-builder/0.1'})
            with urlopen(request, timeout=60) as response, temporary.open('xb') as target:
                if not response.url.startswith('https://'):
                    raise BuildError('An HTTPS download redirected to an insecure URL.')
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > spec['max_bytes']:
                        raise BuildError('Download exceeds the expected size limit.')
                    target.write(chunk)
        if sha256(temporary) != spec['sha256']:
            raise BuildError('Input checksum mismatch. Do not bypass this check.')
        temporary.chmod(0o600)
        temporary.replace(destination)
    except BuildError:
        raise
    except Exception:
        raise BuildError('Could not obtain an input. Check Internet access or use a verified local cache.') from None
    finally:
        if temporary.exists():
            temporary.unlink()


def read_profile(link_file):
    if link_file:
        if not link_file.is_file() or link_file.stat().st_size > 16384:
            raise BuildError('The VLESS link file is missing or too large.')
        try:
            link = link_file.read_text(encoding='utf-8-sig').strip()
        except (OSError, UnicodeError):
            raise BuildError('Could not read the VLESS link file as UTF-8.') from None
    else:
        # Do not fall back to an echoed prompt when no terminal is available.
        if not sys.stdin.isatty():
            raise BuildError('Use an interactive terminal or --link-file PATH; never put the link in command arguments.')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            try:
                link = getpass.getpass('VLESS link (input hidden): ').strip()
            except (getpass.GetPassWarning, EOFError):
                raise BuildError('Hidden input is unavailable. Use --link-file PATH.') from None
    try:
        return parse_vless(link)
    except ValueError:
        raise BuildError('Invalid or unsupported VLESS + Reality TCP/RAW link. See README for supported parameters.') from None


def make_workdir(requested):
    root = requested.expanduser().absolute() if requested else Path.home() / 'kn3013-builds'
    if any(c.isspace() for c in str(root)) or not re.fullmatch(r'[A-Za-z0-9_./-]+', str(root)):
        raise BuildError('The SDK work path must contain only letters, digits, slash, dot, underscore and hyphen.')
    resolved = root.resolve()
    if str(resolved).startswith(('/mnt/', '/media/')) or resolved == Path('/'):
        raise BuildError('Choose a new work directory on the Linux filesystem, outside /mnt and /media.')
    if resolved == KIT or KIT in resolved.parents:
        raise BuildError('Build outside the source repository so private outputs cannot be committed.')
    if requested:
        if root.exists() or root.is_symlink():
            raise BuildError('--work-dir must be NEW. Existing builds are never merged or overwritten.')
        root.mkdir(parents=True, mode=0o700)
    else:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = Path(tempfile.mkdtemp(prefix=datetime.now().strftime('%Y%m%d-%H%M%S-'), dir=root))
    root.chmod(0o700)
    return root.resolve()


def run_logged(command, cwd, logfile, env, label):
    print(f'{label}; local log: {logfile}', flush=True)
    with logfile.open('wb') as log:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        # Logs stay private. Xray errors can contain credentials, so never tail them.
        raise BuildError(f'{label} failed (exit {result.returncode}). Inspect the local log; remove secrets before sharing it.')


def extract_xray(archive, target, expected):
    target.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        for member, output, limit in [('xray_softfloat', 'xray', 50000000), ('LICENSE', 'LICENSE', 100000)]:
            entries = [x for x in bundle.infolist() if x.filename == member]
            if len(entries) != 1 or entries[0].file_size > limit:
                raise BuildError('Unexpected Xray release archive layout.')
            # Exact filenames only: no extractall/path traversal or symlinks.
            (target / output).write_bytes(bundle.read(entries[0]))
    binary = target / 'xray'
    if sha256(binary) != expected:
        raise BuildError('Xray binary checksum mismatch.')
    binary.chmod(0o700)
    return binary


def seed_download_cache(source, sdk):
    if source is None:
        return
    if not source.is_dir():
        raise BuildError('SDK download cache directory does not exist.')
    destination = sdk / 'dl'
    destination.mkdir(exist_ok=True)
    # Only archives in dl/, never rootfs, bin, files, credentials or build_dir.
    for entry in source.iterdir():
        if entry.is_file() and not entry.is_symlink() and re.fullmatch(r'[A-Za-z0-9_.+-]+\.(?:gz|bz2|xz|lz|zst|zip|tgz)', entry.name):
            shutil.copyfile(entry, destination / entry.name)


def build(args):
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise BuildError('Use a regular Linux user in Ubuntu 24.04 / WSL 2, not root.')
    if platform.machine().lower() not in {'x86_64', 'amd64'}:
        raise BuildError('This pinned SDK requires an x86-64 Linux build host.')
    os.umask(0o077)
    if not 1 <= args.jobs <= 32:
        raise BuildError('--jobs must be between 1 and 32.')
    for command in ('git', 'make', 'gcc', 'g++', 'curl', 'getfattr', 'patch', 'qemu-mipsel', 'xz', 'unzip'):
        if shutil.which(command) is None:
            raise BuildError('A required build tool is missing. Run scripts/install-deps.sh first.')
    try:
        import dissect.squashfs  # noqa: F401
    except ImportError:
        raise BuildError('Missing verifier dependency. Start with bash build.sh.') from None
    if time.time() < 1704067200:
        raise BuildError('Set the computer clock correctly before building.')
    manifest = json.loads((KIT / 'manifest.json').read_text())
    config = read_profile(args.link_file)
    work = make_workdir(args.work_dir)
    print(f'Private build directory: {work}', flush=True)
    for directory in ('inputs', 'logs', 'dist'):
        (work / directory).mkdir(mode=0o700)
    inputs, logs = work / 'inputs', work / 'logs'
    print('Obtaining pinned official firmware and Xray; no VPN server connection will be made.', flush=True)
    obtain(manifest['stock'], inputs / 'stock.bin', args.stock)
    obtain(manifest['xray'], inputs / 'xray.zip', args.xray_archive)
    xray = extract_xray(inputs / 'xray.zip', inputs / 'xray', manifest['xray']['binary_sha256'])
    routing = inputs / 'routing'
    routing.mkdir()
    if args.routing == 'ru-direct':
        for spec in manifest['routing']:
            source = args.routing_cache / spec['name'] if args.routing_cache else None
            obtain(spec, routing / spec['name'], source)
    config = add_routing(config, routing, args.routing)
    config_path = inputs / 'client.json'
    config_path.write_text(json.dumps(config, ensure_ascii=True, separators=(',', ':')) + '\n')
    config_path.chmod(0o600)
    env = os.environ.copy()
    env.update(PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               LC_ALL='C.UTF-8', KN_BUILD_JOBS=str(args.jobs),
               DOWNLOAD_MIRROR='https://mirror2.openwrt.org/sources',
               CURL_OPTIONS='--connect-timeout 15 --max-time 180 --retry 2 --silent --show-error --no-insecure')
    # Do not allow inherited build overrides to bypass SDK checks or inject an old overlay.
    for key in ('MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES', 'TOPDIR', 'STAGING_DIR', 'TARGET_DIR', 'CONFIG_SITE'):
        env.pop(key, None)
    run_logged(['qemu-mipsel', str(xray), 'run', '-test', '-config', str(config_path)],
               work, logs / 'xray-check.log', env, 'Validate the MIPS client configuration')
    sdk = work / 'sdk'
    run_logged(['git', '-c', 'core.autocrlf=false', 'clone', '--depth', '1', '--branch', manifest['sdk_ref'],
                manifest['sdk_url'], str(sdk)], work, logs / 'clone.log', env, 'Fetch pinned Keenetic SDK')
    head = subprocess.check_output(['git', '-C', str(sdk), 'rev-parse', 'HEAD'], env=env, text=True).strip()
    if head != manifest['sdk_commit']:
        raise BuildError('SDK tag no longer matches the pinned commit. Build stopped.')
    if (sdk / 'files').exists():
        raise BuildError('Unexpected SDK overlay. A clean clone is required.')
    seed_download_cache(args.sdk_download_cache, sdk)
    # unpack.sh otherwise starts one compiler per logical CPU, ignoring --jobs.
    unpack = sdk / 'unpack.sh'
    source = unpack.read_text()
    anchor = 'NCPU=$(grep processor /proc/cpuinfo | wc -l)'
    if source.count(anchor) != 1:
        raise BuildError('Unexpected SDK unpack script. Review the pinned source.')
    unpack.write_text(source.replace(anchor, 'NCPU=${KN_BUILD_JOBS:-2}'))
    run_logged(['bash', './unpack.sh', str(inputs / 'stock.bin')], sdk, logs / 'unpack.log', env, 'Extract official firmware into clean SDK')
    metadata = {'kit_version': manifest['kit_version'], 'routing_mode': args.routing}
    preparation = prepare_sdk(sdk, config, xray, inputs / 'xray' / 'LICENSE', metadata)
    run_logged(['make', 'defconfig'], sdk, logs / 'defconfig.log', env, 'Resolve SDK component dependencies')
    final_options = set((sdk / '.config').read_text().splitlines())
    required_options = {'CONFIG_TARGET_mt7621_KN_3013=y', 'CONFIG_TARGET_FIRMWARE_SIZE="0x1a40000"',
                        'CONFIG_PACKAGE_busybox=y', 'CONFIG_PACKAGE_ndm-mod-proxy=y',
                        'CONFIG_PACKAGE_ndm-mod-dns-https=y', 'CONFIG_PACKAGE_ndm-mod-opkg=y',
                        'CONFIG_PACKAGE_ndm-mod-pppoe=y'}
    if not required_options <= final_options or any('CONFIG_PACKAGE_' + p + '=y' in final_options
                                                  for p in preparation['removed_packages']):
        raise BuildError('SDK dependency resolution changed required components. Build stopped.')
    run_logged(['make', f'-j{args.jobs}', 'V=s'], sdk, logs / 'build.log', env, 'Build personal firmware')
    images = list((sdk / 'bin' / 'mt7621').glob('*KN-3013*.bin'))
    if len(images) != 1:
        raise BuildError('Expected exactly one KN-3013 output image.')
    print('Verifying the final compressed image and embedded client...', flush=True)
    report = verify_image(images[0], inputs / 'stock.bin', config)
    output = work / 'dist' / 'KN-3013_5.1.8_Xray-26.11.9_PERSONAL.bin'
    shutil.copyfile(images[0], output)
    output.chmod(0o600)
    report.update(kit_version=manifest['kit_version'], sdk_commit=head, routing_mode=args.routing,
                  hardware_boot_tested=False, router_or_vps_modified=False, contains_private_client=True,
                  xray_config_check_passed=True, preparation=preparation)
    # Do not propagate source paths or generated names into the shareable report.
    report['file'] = output.name
    (work / 'dist' / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    digest = sha256(output)
    (work / 'dist' / 'SHA256SUMS').write_text(f'{digest}  {output.name}\n')
    print(f'Completed: {output}\nSHA-256: {digest}', flush=True)
    print('PRIVATE image: contains your VLESS credentials. Do not upload it or the build directory.\n'
          'No device was flashed. Follow docs/INSTALL.md; a successful build is not a hardware boot test.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--link-file', type=Path, help='UTF-8 file containing one VLESS URL; never use a URL as a command argument')
    parser.add_argument('--routing', choices=('ru-direct', 'all-vpn'), default='ru-direct')
    parser.add_argument('--stock', type=Path, help='Optional local official 5.1.8 image matching manifest SHA-256')
    parser.add_argument('--xray-archive', type=Path, help='Optional local pinned Xray release ZIP')
    parser.add_argument('--routing-cache', type=Path, help='Optional directory containing pinned routing lists')
    parser.add_argument('--sdk-download-cache', type=Path, help='Optional trusted SDK dl archive cache (never a built rootfs)')
    parser.add_argument('--work-dir', type=Path, help='New private Linux build directory; must not exist')
    parser.add_argument('--jobs', type=int, default=2, help='Parallel compiler jobs (default: 2)')
    args = parser.parse_args()
    try:
        build(args)
    except (BuildError, ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        message = str(exc) if isinstance(exc, BuildError) else 'Build failed a validation or filesystem check. Inspect local logs; do not share private data.'
        print(f'ERROR: {message}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nBuild interrupted. Its private directory was preserved.', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
