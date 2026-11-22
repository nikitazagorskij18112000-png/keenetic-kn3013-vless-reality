"""Inspect a KN-3013 image without booting it or contacting its VPN server.

The returned report contains build metadata, never the client configuration.
Container validation uses only the standard library. Full filesystem validation
also requires ``dissect.squashfs``.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import zlib


BLOCK = 0x20000
LIMIT = 0x1A40000
DEVICE = 0x13308000
TRAILER_SIZE = 60
XRAY_SHA256 = "5058314c99ec5fc4896b5c7bc55e1b3f7752e754c9df95f8244dab3a4dd8e052"
SDK_COMMIT = "5c74fc4d907383c91e8d6af3f5d67501f7acb171"
CONFIG_PATH = "/etc/xray/config.json"
XRAY_FILES = {"config.json", "build-info.json"}
EXECUTABLES = (
    "/bin/busybox",
    "/usr/libexec/kn3013-xray-service",
    "/opt/etc/ndm/ifstatechanged.d/90-kn3013-xray.sh",
    "/opt/etc/ndm/ifipchanged.d/90-kn3013-xray.sh",
    "/opt/etc/ndm/wan.d/90-kn3013-xray.sh",
)
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"PuTTY-User-Key-File-",
)


def _require(condition: bool, message: str) -> None:
    # Assertions must not disappear when the builder is run with python -O.
    if not condition:
        raise ValueError(message)


def check_container(data: bytes) -> tuple[bytes, dict]:
    """Return the bounded SquashFS bytes and non-secret container metadata.

    This validates the container and superblock, not SquashFS inode contents.
    It verifies CRCs, which detect corruption but are not vendor signatures.
    """
    _require(isinstance(data, bytes), "Firmware input must be bytes.")
    _require(64 + TRAILER_SIZE < len(data) <= LIMIT + TRAILER_SIZE,
             "Firmware has an invalid size or exceeds the KN-3013 limit.")
    body_end = len(data) - TRAILER_SIZE
    _require(data[body_end:body_end + 4] == b"ZNBG", "Device trailer is missing.")
    _require(struct.unpack_from(">I", data, body_end + 4)[0] == DEVICE,
             "Wrong device ID; only KN-3013 is supported.")
    _require(body_end % BLOCK == 0, "Image alignment mismatch.")
    _require((zlib.crc32(data[:body_end]) ^ 0xFFFFFFFF)
             == struct.unpack_from("<I", data, len(data) - 4)[0],
             "Firmware CRC mismatch.")
    _require(data[:4] == bytes.fromhex("27051956"), "Kernel image header is missing.")
    header = bytearray(data[:64])
    expected_crc = struct.unpack_from(">I", header, 4)[0]
    header[4:8] = bytes(4)
    _require(zlib.crc32(header) == expected_crc, "Kernel header CRC mismatch.")
    payload_size = struct.unpack_from(">I", data, 12)[0]
    kernel_end = 64 + payload_size
    _require(payload_size > 0 and kernel_end < body_end,
             "Kernel payload is outside the image.")
    _require(zlib.crc32(data[64:kernel_end]) == struct.unpack_from(">I", data, 24)[0],
             "Kernel payload CRC mismatch.")
    _require(data[28:32] == bytes([5, 5, 2, 3]),
             "Expected a Linux/MIPS kernel with LZMA compression.")
    _require(data[32:63].rstrip(b"\0") == b"KN-3013", "Wrong kernel model name.")
    _require(data[63] == 1, "Dual-image kernel flag changed.")

    candidates = []
    for offset in range(BLOCK, body_end, BLOCK):
        if data[offset:offset + 4] != b"hsqs":
            continue
        _require(offset + 96 <= body_end, "Truncated SquashFS superblock.")
        size = struct.unpack_from("<Q", data, offset + 40)[0]
        _require(size >= 96 and size <= body_end - offset,
                 "SquashFS is outside the image.")
        candidates.append((offset, size))
    _require(len(candidates) == 1, "Expected one aligned SquashFS root filesystem.")
    offset, size = candidates[0]
    _require(offset >= kernel_end + BLOCK,
             "Missing reserved metadata block after the kernel.")
    _require(struct.unpack_from("<HH", data, offset + 28) == (4, 0),
             "Wrong SquashFS format.")
    _require(struct.unpack_from("<H", data, offset + 20)[0] == 4,
             "Expected XZ filesystem compression.")
    try:
        version = data[-52:-4].split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("Invalid firmware version encoding.") from None
    _require(bool(version) and all(32 <= ord(char) < 127 for char in version),
             "Invalid firmware version field.")
    tlv_offsets = [pos for pos in range(BLOCK, offset, BLOCK)
                   if data[pos:pos + 8] == b"TLV.NDM."]
    return data[offset:offset + size], {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "model_id": hex(DEVICE),
        "trailer_version": version,
        "kernel_payload_bytes": payload_size,
        "squashfs_offset": offset,
        "squashfs_bytes": size,
        "size_limit_excluding_trailer": LIMIT,
        "space_remaining_bytes": LIMIT - body_end,
        "firmware_crc32_ok": True,
        "kernel_header_crc32_ok": True,
        "kernel_payload_crc32_ok": True,
        "dual_image_flag_preserved": True,
        "tlv_description_present": bool(tlv_offsets),
        "tlv_description_offsets": tlv_offsets,
        "vendor_digital_signature_verified": False,
        "web_ui_upload_requires_tlv_and_vendor_signature": True,
    }


def _check_client_config(actual: dict, expected: dict) -> None:
    """Validate exact client identity without including it in error messages."""
    _require(isinstance(actual, dict) and isinstance(expected, dict),
             "Client configuration must be an object.")
    _require(actual == expected, "Embedded client differs from the requested configuration.")
    inbounds = actual.get("inbounds")
    _require(isinstance(inbounds, list) and len(inbounds) == 1,
             "Expected one local SOCKS inbound.")
    inbound = inbounds[0]
    _require(isinstance(inbound, dict) and inbound.get("listen") == "127.0.0.1"
             and inbound.get("protocol") == "socks" and inbound.get("port") == 1080,
             "SOCKS must listen only on 127.0.0.1:1080.")
    _require(inbound.get("settings", {}).get("udp") is True,
             "SOCKS UDP is not enabled.")
    outbounds = actual.get("outbounds")
    _require(isinstance(outbounds, list) and bool(outbounds)
             and isinstance(outbounds[0], dict)
             and outbounds[0].get("protocol") == "vless"
             and outbounds[0].get("streamSettings", {}).get("security") == "reality",
             "The default outbound must be VLESS + Reality.")
    log = actual.get("log", {})
    _require(isinstance(log, dict), "Invalid logging configuration.")
    _require(log.get("access") in (None, "", "none")
             and log.get("error") in (None, "", "none"),
             "Embedded client must not write persistent log files.")


def _check_build_info(info: dict) -> None:
    """Allow only the exact public metadata schema produced by prepare_sdk."""
    fixed = {
        "device": "Keenetic Speedster KN-3013 EAEU",
        "base_keeneticos": "5.1.8",
        "sdk_commit": SDK_COMMIT,
        "xray_version": "26.11.9",
        "xray_architecture": "linux/mipsle softfloat",
        "client_configuration": "personal profile embedded; do not redistribute image",
        "physical_router_validation": "not performed for this generated image",
    }
    _require(isinstance(info, dict) and set(info) == set(fixed) | {"kit_version", "routing_mode"},
             "Unexpected build metadata fields.")
    _require(all(info[key] == value for key, value in fixed.items()),
             "Build metadata differs from the pinned configuration.")
    _require(info["routing_mode"] in {"ru-direct", "all-vpn"}, "Invalid routing mode metadata.")
    version = info["kit_version"]
    _require(isinstance(version, str) and len(version) <= 40
             and (version == "development"
                  or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-(?:alpha|beta|rc)\.[0-9]+)?", version)),
             "Invalid kit version metadata.")


def _read_file(fs, path: str, *, allow_symlink: bool = False) -> bytes:
    try:
        node = fs.get(path)
        if allow_symlink:
            for _ in range(16):
                if not node.is_symlink():
                    break
                node = node.link_inode
        _require(not node.is_symlink() and node.is_file(),
                 "A required filesystem entry is not a regular file.")
        return node.open().read()
    except (FileNotFoundError, KeyError):
        raise ValueError("A required filesystem file is missing.") from None


def _walk(fs, path: str = "/"):
    for node in fs.get(path).iterdir():
        if node.name in {".", ".."}:
            continue
        entry = path.rstrip("/") + "/" + node.name
        yield entry, node
        if not node.is_symlink() and node.is_dir():
            yield from _walk(fs, entry)


def _is_private_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1].lower()
    return (
        ".ssh" in parts or "private" in parts
        or path.startswith(("/var/log/", "/tmp/", "/var/tmp/"))
        or name in {"startup-config", "running-config", "backup-config", ".env",
                    ".bash_history", ".ash_history", "authorized_keys"}
        or bool(re.fullmatch(r"(?:dropbear_.*_host_key|ssh_host_.*_key)(?:\.pub)?", name))
        or name.endswith((".log", ".bak", ".backup", ".pem", ".key", ".ppk", ".p12", ".pfx"))
    )


def _audit_added_files(fs, stock) -> None:
    """Reject accidental private artifacts while allowing unchanged stock files."""
    stock_entries = dict(_walk(stock))
    for path, node in _walk(fs):
        previous = stock_entries.get(path)
        if node.is_symlink():
            if previous is not None and previous.is_symlink() and node.link == previous.link:
                continue
            _require(not _is_private_path(path) and "vless://" not in node.link.lower(),
                     "A private artifact or client URI was added as a symbolic link.")
            continue
        if not node.is_file():
            continue
        content = None
        if previous is not None and not previous.is_symlink() and previous.is_file():
            content = node.open().read()
            if content == previous.open().read():
                continue
        _require(not _is_private_path(path),
                 "A private, key, backup, or log file was added to the image.")
        if path == "/usr/bin/xray":
            continue  # Its entire binary is checked against the official digest.
        content = content if content is not None else node.open().read()
        _require(not any(marker in content for marker in PRIVATE_KEY_MARKERS),
                 "Private-key material was found in an added or modified file.")
        if path != CONFIG_PATH:
            _require(b"vless://" not in content.lower(),
                     "A client URI was found outside the requested configuration.")


def verify_image(image: Path, stock: Path, expected_config: dict) -> dict:
    """Verify a locally personalized image; do not return its credentials.

    This is not a hardware boot test or a redistribution license check. The
    caller must independently authenticate/pin its stock image and SDK inputs.
    """
    rootfs, report = check_container(Path(image).read_bytes())
    stock_rootfs, stock_report = check_container(Path(stock).read_bytes())
    _require(report["trailer_version"] == stock_report["trailer_version"],
             "Custom image and stock image versions differ.")
    try:
        from dissect.squashfs import SquashFS
    except ImportError:
        raise RuntimeError("Full image verification requires dissect.squashfs.") from None
    fs = SquashFS(io.BytesIO(rootfs))
    original = SquashFS(io.BytesIO(stock_rootfs))
    _require((fs.major, fs.minor) == (4, 0), "Wrong SquashFS format.")
    critical = {"/sbin/init", "/bin/ndm", "/lib/libndmCorePack.so", "/lib/libndmBase.so"}
    for node in original.get("/lib").iterdir():
        if (node.is_file() or node.is_symlink()) and re.match(r"^libndm(?:Ppp|Proxy|Opkg|Exec|Ssh)", node.name):
            critical.add("/lib/" + node.name)
    for path in sorted(critical):
        current, previous = fs.get(path), original.get(path)
        _require(current.is_symlink() == previous.is_symlink(),
                 "A critical stock firmware entry changed type.")
        if previous.is_symlink():
            _require(current.link == previous.link, "A critical stock symlink changed.")
        _require(_read_file(fs, path, allow_symlink=True) == _read_file(original, path, allow_symlink=True),
                 "A critical stock firmware component changed.")

    binary = _read_file(fs, "/usr/bin/xray")
    _require(hashlib.sha256(binary).hexdigest() == XRAY_SHA256,
             "Embedded Xray differs from the pinned verified release.")
    _require(len(binary) >= 20 and binary[:6] == b"\x7fELF\x01\x01"
             and struct.unpack_from("<H", binary, 18)[0] == 8,
             "Wrong Xray CPU architecture.")
    for path in ("/usr/bin/xray",) + EXECUTABLES:
        _read_file(fs, path)
        _require(fs.get(path).mode & 0o111 != 0, "A required file is not executable.")
    opt_bin = fs.get("/opt/bin")
    _require(opt_bin.is_symlink() and opt_bin.link == "/bin", "Missing OPKG interpreter link.")
    names = {node.name for node in fs.get("/etc/xray").iterdir() if node.name not in {".", ".."}}
    _require(names == XRAY_FILES, "Unexpected or missing files in /etc/xray.")
    config_node = fs.get(CONFIG_PATH)
    _require(config_node.mode & 0o777 == 0o600, "Client configuration must have mode 0600.")
    _require(config_node.uid == 0 and config_node.gid == 0,
             "Client configuration must be owned by root.")
    try:
        actual = json.loads(_read_file(fs, CONFIG_PATH))
        build_info = json.loads(_read_file(fs, "/etc/xray/build-info.json"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("An embedded JSON file is invalid.") from None
    _check_build_info(build_info)
    _check_client_config(actual, expected_config)
    _audit_added_files(fs, original)
    report.update({
        "unchanged_core_files_verified": sorted(critical),
        "xray_sha256": XRAY_SHA256,
        "xray_verified_release_embedded": True,
        "embedded_client_matches_expected": True,
        "unexpected_private_artifacts_checked": True,
        "installation_method": "Recovery/TFTP",
        "checks_passed": True,
        "physical_router_boot_tested": False,
        "hardware_wifi_pppoe_memory_tested": False,
        "ready_to_flash": False,
    })
    return report
