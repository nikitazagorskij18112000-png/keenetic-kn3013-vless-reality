"""Builder boundary tests: no networks, no router, no production credentials."""
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build


class BuilderBoundaryTests(unittest.TestCase):
    def test_bad_hash_is_never_promoted_to_verified_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / 'source.bin', root / 'stock.bin'
            source.write_bytes(b'changed bytes')
            spec = {'max_bytes': 100, 'sha256': '0' * 64}
            with self.assertRaises(build.BuildError):
                build.obtain(spec, target, source)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix('.bin.partial').exists())

    def test_local_checked_input_is_exact_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / 'source.bin', root / 'stock.bin'
            source.write_bytes(b'official public test bytes')
            spec = {'max_bytes': 100, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
            build.obtain(spec, target, source)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            if build.sys.platform == 'linux':
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_http_redirect_is_rejected_without_writing_bytes(self):
        class Response(io.BytesIO):
            url = 'http://example.com/input'
        with tempfile.TemporaryDirectory() as tmp, patch.object(build, 'urlopen', return_value=Response(b'bad')):
            target = Path(tmp) / 'input.bin'
            with self.assertRaises(build.BuildError):
                build.obtain({'url': 'https://example.com/input', 'max_bytes': 10, 'sha256': '0'*64}, target)
            self.assertFalse(target.exists())

    def test_existing_work_directory_is_not_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / 'previous-client.json'
            sentinel.write_text('previous private profile')
            with self.assertRaises(build.BuildError):
                build.make_workdir(root)
            self.assertEqual(sentinel.read_text(), 'previous private profile')

    def test_repository_and_windows_mount_cannot_receive_builds(self):
        for path in (build.KIT / 'dist', Path('/mnt/c/build-test'), Path('/'), Path('/tmp/space test')):
            with self.subTest(path=path), self.assertRaises(build.BuildError):
                build.make_workdir(path)

    def test_link_errors_do_not_echo_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'link.txt'
            private_value = 'DO-NOT-PRINT-THIS-INVALID-LINK'
            path.write_text(private_value)
            with self.assertRaises(build.BuildError) as raised:
                build.read_profile(path)
            self.assertNotIn(private_value, str(raised.exception))

    def test_noninteractive_input_does_not_fall_back_to_echoed_prompt(self):
        with patch.object(build.sys.stdin, 'isatty', return_value=False), patch.object(build.getpass, 'getpass') as prompt:
            with self.assertRaises(build.BuildError):
                build.read_profile(None)
            prompt.assert_not_called()

    def test_cache_does_not_import_a_personal_overlay_or_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, sdk = root / 'cache', root / 'sdk'
            cache.mkdir()
            sdk.mkdir()
            (cache / 'config.json').write_text('not a source archive')
            (cache / 'firmware.bin').write_bytes(b'not a source archive')
            (cache / 'source-1.tar.gz').write_bytes(b'public test archive')
            (cache / 'nested').mkdir()
            if build.sys.platform == 'linux':
                (cache / 'linked.tar.gz').symlink_to(cache / 'config.json')
            build.seed_download_cache(cache, sdk)
            self.assertEqual([p.name for p in (sdk / 'dl').iterdir()], ['source-1.tar.gz'])


if __name__ == '__main__':
    unittest.main()
