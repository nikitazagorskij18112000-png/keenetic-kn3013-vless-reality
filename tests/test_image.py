"""Synthetic container and configuration tests; no router or production keys."""

import copy
import importlib.util
import io
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import zlib


SPEC = importlib.util.spec_from_file_location("public_image", Path(__file__).parents[1] / "lib" / "image.py")
image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(image)


def repair_crcs(data, *, header=True):
    if header:
        data[4:8] = bytes(4)
        struct.pack_into(">I", data, 4, zlib.crc32(data[:64]))
    struct.pack_into("<I", data, len(data) - 4, zlib.crc32(data[:-60]) ^ 0xFFFFFFFF)
    return bytes(data)


def fixture():
    data = bytearray(image.BLOCK * 3 + 60)
    data[:4] = bytes.fromhex("27051956")
    payload = b"synthetic kernel payload"
    struct.pack_into(">I", data, 12, len(payload))
    struct.pack_into(">I", data, 24, zlib.crc32(payload))
    data[28:32] = bytes([5, 5, 2, 3])
    data[32:39] = b"KN-3013"
    data[63] = 1
    data[64:64 + len(payload)] = payload
    offset = image.BLOCK * 2
    data[offset:offset + 4] = b"hsqs"
    struct.pack_into("<H", data, offset + 20, 4)
    struct.pack_into("<HH", data, offset + 28, 4, 0)
    struct.pack_into("<Q", data, offset + 40, 96)
    data[-60:-56] = b"ZNBG"
    struct.pack_into(">I", data, len(data) - 56, image.DEVICE)
    version = b"5.01.C.8.0-2"
    data[-52:-52 + len(version)] = version
    return repair_crcs(data)


class ContainerTests(unittest.TestCase):
    def test_valid_container_returns_only_bounded_rootfs(self):
        rootfs, metadata = image.check_container(fixture())
        self.assertEqual(len(rootfs), 96)
        self.assertEqual(metadata["squashfs_offset"], image.BLOCK * 2)
        self.assertTrue(metadata["firmware_crc32_ok"])
        self.assertFalse(metadata["vendor_digital_signature_verified"])

    def test_truncated_and_oversized_input(self):
        for data in (b"", bytes(64), bytes(image.LIMIT + 61)):
            with self.subTest(length=len(data)), self.assertRaisesRegex(ValueError, "size"):
                image.check_container(data)

    def test_missing_trailer_and_wrong_model_id(self):
        data = bytearray(fixture())
        data[-60:-56] = b"BAD!"
        with self.assertRaisesRegex(ValueError, "trailer"):
            image.check_container(bytes(data))
        data = bytearray(fixture())
        struct.pack_into(">I", data, len(data) - 56, image.DEVICE + 1)
        with self.assertRaisesRegex(ValueError, "device ID"):
            image.check_container(bytes(data))

    def test_firmware_header_and_payload_crc_independently(self):
        data = bytearray(fixture())
        data[90] ^= 1
        with self.assertRaisesRegex(ValueError, "Firmware CRC"):
            image.check_container(bytes(data))
        data = bytearray(fixture())
        data[4] ^= 1
        with self.assertRaisesRegex(ValueError, "header CRC"):
            image.check_container(repair_crcs(data, header=False))
        data = bytearray(fixture())
        data[64] ^= 1
        with self.assertRaisesRegex(ValueError, "payload CRC"):
            image.check_container(repair_crcs(data))

    def test_kernel_bounds(self):
        data = bytearray(fixture())
        struct.pack_into(">I", data, 12, len(data))
        with self.assertRaisesRegex(ValueError, "payload is outside"):
            image.check_container(repair_crcs(data))

    def test_kernel_name_architecture_and_dual_image_flag(self):
        for position, value, error in ((38, ord("4"), "model"), (29, 2, "Linux/MIPS"), (63, 0, "Dual-image")):
            data = bytearray(fixture())
            data[position] = value
            with self.subTest(position=position), self.assertRaisesRegex(ValueError, error):
                image.check_container(repair_crcs(data))

    def test_unaligned_container(self):
        data = fixture()
        with self.assertRaisesRegex(ValueError, "alignment"):
            image.check_container(data[:-60] + b"x" + data[-60:])

    def test_squashfs_bounds_and_duplicate_rootfs(self):
        data = bytearray(fixture())
        struct.pack_into("<Q", data, image.BLOCK * 2 + 40, len(data))
        with self.assertRaisesRegex(ValueError, "SquashFS is outside"):
            image.check_container(repair_crcs(data))
        data = bytearray(fixture())
        data[image.BLOCK:image.BLOCK + 96] = data[image.BLOCK * 2:image.BLOCK * 2 + 96]
        with self.assertRaisesRegex(ValueError, "one aligned"):
            image.check_container(repair_crcs(data))

    def test_squashfs_version_and_compression(self):
        for position, error in ((28, "format"), (20, "XZ")):
            data = bytearray(fixture())
            struct.pack_into("<H", data, image.BLOCK * 2 + position, 3)
            with self.subTest(position=position), self.assertRaisesRegex(ValueError, error):
                image.check_container(repair_crcs(data))


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{"protocol": "vless", "settings": {"server": "192.0.2.1"},
                           "streamSettings": {"security": "reality"}}],
        }

    def test_dummy_config_is_accepted_without_network_access(self):
        image._check_client_config(self.config, copy.deepcopy(self.config))

    def test_disabled_access_log_is_not_a_filename(self):
        self.config["log"] = {"loglevel": "warning", "access": "none"}
        image._check_client_config(self.config, copy.deepcopy(self.config))
        self.config["log"]["access"] = "/var/log/access.log"
        with self.assertRaisesRegex(ValueError, "log files"):
            image._check_client_config(self.config, self.config)

    def test_wrong_profile_error_does_not_disclose_values(self):
        other = copy.deepcopy(self.config)
        other["outbounds"][0]["settings"]["server"] = "sensitive.example"
        with self.assertRaises(ValueError) as caught:
            image._check_client_config(other, self.config)
        self.assertNotIn("sensitive", str(caught.exception))
        self.assertNotIn("192.0.2", str(caught.exception))

    def test_network_exposure_and_missing_udp_rejected(self):
        for key, value in (("listen", "0.0.0.0"), ("port", 1081), ("protocol", "http")):
            candidate = copy.deepcopy(self.config)
            candidate["inbounds"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                image._check_client_config(candidate, candidate)
        candidate = copy.deepcopy(self.config)
        candidate["inbounds"][0]["settings"]["udp"] = False
        with self.assertRaisesRegex(ValueError, "UDP"):
            image._check_client_config(candidate, candidate)

    def test_private_paths(self):
        for path in ("/root/.ssh/id_ed25519", "/etc/dropbear/dropbear_rsa_host_key", "/var/log/xray.log",
                     "/etc/xray/config.json.bak", "/root/startup-config", "/etc/secrets.key"):
            with self.subTest(path=path):
                self.assertTrue(image._is_private_path(path))
        self.assertFalse(image._is_private_path("/etc/xray/config.json"))
        self.assertFalse(image._is_private_path("/usr/share/licenses/xray/LICENSE"))


class AuditTests(unittest.TestCase):
    class File:
        def __init__(self, data):
            self.data = data

        def is_file(self):
            return True

        def is_symlink(self):
            return False

        def open(self):
            return io.BytesIO(self.data)

    def audit(self, current, baseline=()):
        with patch.object(image, "_walk", side_effect=lambda entries: iter(entries)):
            image._audit_added_files(current, baseline)

    def test_unchanged_stock_certificate_is_allowed(self):
        stock_file = ("/etc/vendor.pem", self.File(b"vendor fixture"))
        self.audit([stock_file], [stock_file])

    def test_changed_key_material_in_unremarkable_filename_is_rejected(self):
        before = ("/etc/settings", self.File(b"ordinary fixture"))
        after = ("/etc/settings", self.File(b"-----BEGIN OPENSSH PRIVATE KEY-----\nTEST ONLY\n"))
        with self.assertRaisesRegex(ValueError, "Private-key material"):
            self.audit([after], [before])

    def test_client_uri_outside_config_is_rejected_without_echoing_it(self):
        with self.assertRaises(ValueError) as caught:
            self.audit([("/etc/build-note", self.File(b"vless://test-only@example.invalid"))])
        self.assertNotIn("example.invalid", str(caught.exception))

    def test_added_backup_rejected_even_without_recognizable_secrets(self):
        with self.assertRaisesRegex(ValueError, "backup"):
            self.audit([("/etc/xray/config.json.bak", self.File(b"{}"))])


class BuildMetadataTests(unittest.TestCase):
    def setUp(self):
        self.info = {
            "device": "Keenetic Speedster KN-3013 EAEU",
            "base_keeneticos": "5.1.8",
            "sdk_commit": image.SDK_COMMIT,
            "xray_version": "26.11.9",
            "xray_architecture": "linux/mipsle softfloat",
            "kit_version": "0.1.0",
            "routing_mode": "ru-direct",
            "client_configuration": "personal profile embedded; do not redistribute image",
            "physical_router_validation": "not performed for this generated image",
        }

    def test_public_metadata_accepted_for_both_routing_modes(self):
        image._check_build_info(self.info)
        self.info["routing_mode"] = "all-vpn"
        image._check_build_info(self.info)

    def test_extra_key_and_modified_fixed_value_rejected(self):
        self.info["server"] = "secret.example"
        with self.assertRaises(ValueError) as caught:
            image._check_build_info(self.info)
        self.assertNotIn("secret.example", str(caught.exception))
        del self.info["server"]
        self.info["client_configuration"] = "secret.example"
        with self.assertRaisesRegex(ValueError, "pinned"):
            image._check_build_info(self.info)

    def test_profile_cannot_be_hidden_in_version_field(self):
        for value in ("vless://test@example.invalid", "11111111-1111-1111-1111-111111111111", "192.0.2.1", "host.example", {"private": True}):
            self.info["kit_version"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                image._check_build_info(self.info)


if __name__ == "__main__":
    unittest.main()
