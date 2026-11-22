"""Preparation invariants: isolation, model checks and private-file modes."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lib import sdk


class SdkPreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tree = self.root / "sdk"
        self.tree.mkdir()
        self.original_config = (
            'CONFIG_TARGET_mt7621_KN_3013=y\n'
            'CONFIG_TARGET_FIRMWARE_SIZE="0x1a40000"\n'
            + "".join("CONFIG_PACKAGE_" + name + "=y\n" for name in sdk.REQUIRED_PACKAGES)
            + "CONFIG_PACKAGE_ndm-mod-ntce=y\n"
            + "CONFIG_PACKAGE_ndm-mod-lang-ru=y\n"
            + "CONFIG_PACKAGE_ndm-mod-lang-en=y\n"
            + "CONFIG_PACKAGE_ndm-mod-lang-de=y\n"
            + "CONFIG_PACKAGE_ndw4-fr-locale=y\n"
        )
        (self.tree / ".config").write_text(self.original_config, encoding="utf-8")
        self.bb = self.tree / "package/debug/busybox/configs/debug.config"
        self.bb.parent.mkdir(parents=True)
        self.bb.write_text("# CONFIG_READLINK is not set\n", encoding="utf-8")
        self.recipe = self.tree / "include/image.mk"
        self.recipe.parent.mkdir()
        self.recipe.write_text("# fixture\n" + sdk.IMAGE_ANCHOR + "\n", encoding="utf-8")
        self.binary = self.root / "xray"
        self.binary.write_bytes(b"unit-test-only-not-a-firmware-binary")
        self.license = self.root / "LICENSE"
        self.license.write_text("Mozilla Public License Version 2.0\n", encoding="utf-8")
        self.config = {
            "inbounds": [{"listen": "127.0.0.1", "protocol": "socks", "port": 1080}],
            "outbounds": [{"tag": "vpn", "protocol": "vless",
                           "streamSettings": {"security": "reality"}}],
        }
        self.hash_patch = patch.object(sdk, "XRAY_SHA256", hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)

    def prepare(self, metadata=None):
        return sdk.prepare_sdk(self.tree, self.config, self.binary, self.license,
                               metadata or {"kit_version": "0.1.0", "routing_mode": "ru-direct"})

    @unittest.skipUnless(os.name == "posix", "SDK preparation requires Linux symlinks and modes")
    def test_prepares_exact_overlay_and_keeps_private_config(self):
        report = self.prepare()
        files = self.tree / "files"
        self.assertEqual(json.loads((files / "etc/xray/config.json").read_text()), self.config)
        self.assertEqual((files / "etc/xray/config.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((files / "usr/bin/xray").stat().st_mode & 0o777, 0o755)
        self.assertEqual(os.readlink(files / "opt/bin"), "/bin")
        actual_files = {str(p.relative_to(files)) for p in files.rglob("*") if p.is_file() or p.is_symlink()}
        self.assertEqual(actual_files, set(sdk.SCRIPTS) | {
            "etc/xray/config.json", "etc/xray/build-info.json", "opt/bin",
            "usr/bin/xray", "usr/share/licenses/xray/LICENSE",
        })
        for relative in sdk.SCRIPTS:
            self.assertEqual((files / relative).stat().st_mode & 0o777, 0o755)
            self.assertNotIn(b"\r", (files / relative).read_bytes())
        modified = (self.tree / ".config").read_text()
        self.assertIn("CONFIG_PACKAGE_ndm-mod-lang-ru=y", modified)
        self.assertIn("CONFIG_PACKAGE_ndm-mod-lang-en=y", modified)
        self.assertIn("# CONFIG_PACKAGE_ndm-mod-lang-de is not set", modified)
        self.assertIn("# CONFIG_PACKAGE_ndw4-fr-locale is not set", modified)
        self.assertIn("# CONFIG_PACKAGE_ndm-mod-ntce is not set", modified)
        self.assertIn("CONFIG_PACKAGE_busybox=y", modified)
        for required in sdk.REQUIRED_PACKAGES:
            self.assertIn("CONFIG_PACKAGE_" + required + "=y", modified)
        self.assertEqual(self.recipe.read_text().count(sdk.IMAGE_RESTRICTION), 1)
        self.assertNotIn("outbounds", json.dumps(report))

    def test_even_empty_existing_overlay_is_rejected_without_changes(self):
        (self.tree / "files").mkdir()
        with self.assertRaisesRegex(ValueError, "fresh build directory"):
            self.prepare()
        self.assertEqual((self.tree / ".config").read_text(), self.original_config)

    @unittest.skipUnless(os.name == "posix", "Linux symlink invariant")
    def test_dangling_overlay_symlink_is_rejected(self):
        (self.tree / "files").symlink_to(self.root / "missing", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "fresh build directory"):
            self.prepare()

    def test_wrong_model_is_rejected_before_any_write(self):
        (self.tree / ".config").write_text(self.original_config.replace("KN_3013", "KN_1012"))
        with self.assertRaisesRegex(ValueError, "not configured for KN-3013"):
            self.prepare()
        self.assertFalse((self.tree / "files").exists())

    def test_changed_flash_limit_is_rejected(self):
        (self.tree / ".config").write_text(self.original_config.replace("0x1a40000", "0x3000000"))
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.prepare()

    def test_missing_required_proxy_is_rejected(self):
        (self.tree / ".config").write_text(self.original_config.replace("CONFIG_PACKAGE_ndm-mod-proxy=y\n", ""))
        with self.assertRaisesRegex(ValueError, "required component"):
            self.prepare()

    def test_wrong_xray_is_rejected(self):
        self.binary.write_bytes(b"another binary")
        with self.assertRaisesRegex(ValueError, "pinned release"):
            self.prepare()
        self.assertFalse((self.tree / "files").exists())

    def test_unexpected_image_recipe_is_rejected(self):
        self.recipe.write_text("a different image recipe\n")
        with self.assertRaisesRegex(ValueError, "image recipe"):
            self.prepare()

    def test_previous_permission_patch_is_rejected(self):
        self.recipe.write_text(sdk.IMAGE_RESTRICTION + sdk.IMAGE_ANCHOR)
        with self.assertRaisesRegex(ValueError, "image recipe"):
            self.prepare()

    @unittest.skipUnless(os.name == "posix", "SDK preparation requires Linux")
    def test_arbitrary_metadata_is_not_embedded(self):
        report = self.prepare({"kit_version": "test", "routing_mode": "all-vpn",
                               "private_profile": "DO-NOT-PUBLISH-THIS-VALUE"})
        info = (self.tree / "files/etc/xray/build-info.json").read_text()
        self.assertNotIn("DO-NOT-PUBLISH-THIS-VALUE", info + json.dumps(report))
        self.assertEqual(json.loads(info)["routing_mode"], "all-vpn")

    def test_wildcard_listener_is_rejected(self):
        self.config["inbounds"][0]["listen"] = "0.0.0.0"
        with self.assertRaisesRegex(ValueError, "Invalid local"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
