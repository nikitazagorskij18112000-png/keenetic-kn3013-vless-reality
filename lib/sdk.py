"""Customize a freshly unpacked KN-3013 SDK without reusing an old overlay.

The caller pins/checks the SDK checkout before unpacking the official firmware.
This module never downloads data, invokes a shell, or writes to a router.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil

SDK_COMMIT = "5c74fc4d907383c91e8d6af3f5d67501f7acb171"
XRAY_SHA256 = "5058314c99ec5fc4896b5c7bc55e1b3f7752e754c9df95f8244dab3a4dd8e052"
OVERLAY = Path(__file__).resolve().parents[1] / "overlay"
SCRIPTS = (
    "usr/libexec/kn3013-xray-service",
    "opt/etc/ndm/wan.d/90-kn3013-xray.sh",
    "opt/etc/ndm/ifstatechanged.d/90-kn3013-xray.sh",
    "opt/etc/ndm/ifipchanged.d/90-kn3013-xray.sh",
)
REQUIRED_PACKAGES = (
    "ndm-mod-proxy", "ndm-mod-dns-https", "ndm-mod-pppoe", "ndm-mod-opkg",
)
REMOVED_PACKAGES = {
    "ndm-mod-ntce", "ntce-pace2", "ntce-pace2-flowstat", "pace2", "pace2-csc",
}
BUSYBOX_OPTIONS = (
    "CONFIG_READLINK", "CONFIG_TIMEOUT", "CONFIG_START_STOP_DAEMON",
    "CONFIG_FEATURE_START_STOP_DAEMON_LONG_OPTIONS",
    "CONFIG_FEATURE_START_STOP_DAEMON_FANCY",
)
IMAGE_ANCHOR = "\t$(INSTALL_DIR) $(TARGET_DIR)/tmp\n\tchmod 1777 $(TARGET_DIR)/tmp"
IMAGE_RESTRICTION = (
    "\tif [ -f $(TARGET_DIR)/etc/xray/config.json ]; then "
    "chmod 0600 $(TARGET_DIR)/etc/xray/config.json; fi\n"
)


def _read(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("The SDK input must be a regular file.")
    return path.read_text(encoding="utf-8")


def _write(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # chmod before writing so the credentials are never written world-readable.
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        path.chmod(mode)
        stream.write(text)


def _set_option(text: str, name: str, value: str) -> str:
    pattern = re.compile(
        r"^(?:" + re.escape(name) + r"=.*|# " + re.escape(name) + r" is not set)$",
        re.M,
    )
    matches = list(pattern.finditer(text))
    if len(matches) > 1:
        raise ValueError("Duplicate SDK configuration option.")
    replacement = f"{name}={value}" if value != "n" else f"# {name} is not set"
    if matches:
        return pattern.sub(lambda _: replacement, text)
    return text.rstrip() + "\n" + replacement + "\n"


def _configuration(text: str) -> tuple[str, list[str]]:
    if not re.search(r"^CONFIG_TARGET_mt7621_KN_3013=y$", text, re.M):
        raise ValueError("The unpacked SDK is not configured for KN-3013.")
    if not re.search(r'^CONFIG_TARGET_FIRMWARE_SIZE="0x1a40000"$', text, re.M):
        raise ValueError("Unexpected KN-3013 firmware size limit.")
    for package in REQUIRED_PACKAGES:
        if not re.search(r"^CONFIG_PACKAGE_" + re.escape(package) + r"=y$", text, re.M):
            raise ValueError("The stock component set lacks a required component.")
    removed = set(REMOVED_PACKAGES)
    for package in re.findall(r"^CONFIG_PACKAGE_(\S+)=y$", text, re.M):
        match = re.fullmatch(r"(?:ndm-mod-lang-([a-z]{2})|ndw[34]-([a-z]{2})-locale)", package)
        if match and (match.group(1) or match.group(2)) not in {"ru", "en"}:
            removed.add(package)
    for package in sorted(removed):
        text = _set_option(text, "CONFIG_PACKAGE_" + package, "n")
    return _set_option(text, "CONFIG_PACKAGE_busybox", "y"), sorted(removed)


def prepare_sdk(sdk: Path, config: dict, xray: Path, xray_license: Path,
                metadata: dict) -> dict:
    """Write the private profile and known scripts into a *new* sdk/files tree.

    An existing tree, including an empty directory or dangling symlink, is an
    error. Restart a failed preparation in a new build directory; do not merge
    overlays from different users. Unknown metadata keys are deliberately ignored.
    """
    sdk, xray, xray_license = Path(sdk), Path(xray), Path(xray_license)
    if not sdk.is_dir() or sdk.is_symlink():
        raise ValueError("A real SDK directory is required.")
    files = sdk / "files"
    if files.exists() or files.is_symlink():
        raise ValueError("SDK files already exists; use a fresh build directory.")
    sdk_config, removed = _configuration(_read(sdk / ".config"))
    busybox_path = sdk / "package/debug/busybox/configs/debug.config"
    busybox = _read(busybox_path)
    for option in BUSYBOX_OPTIONS:
        busybox = _set_option(busybox, option, "y")
    image_path = sdk / "include/image.mk"
    image_recipe = _read(image_path)
    if image_recipe.count(IMAGE_ANCHOR) != 1 or IMAGE_RESTRICTION in image_recipe:
        raise ValueError("Unexpected or previously modified SDK image recipe.")
    image_recipe = image_recipe.replace(IMAGE_ANCHOR, IMAGE_RESTRICTION + IMAGE_ANCHOR)
    if xray.is_symlink() or not xray.is_file():
        raise ValueError("A regular Xray binary is required.")
    if hashlib.sha256(xray.read_bytes()).hexdigest() != XRAY_SHA256:
        raise ValueError("Xray binary does not match the pinned release.")
    license_text = _read(xray_license)
    if "Mozilla Public License" not in license_text[:1024]:
        raise ValueError("The Xray license file is missing or unexpected.")
    try:
        inbounds = config["inbounds"]
        if len(inbounds) != 1 or inbounds[0]["listen"] != "127.0.0.1":
            raise ValueError
        if inbounds[0]["protocol"] != "socks" or inbounds[0]["port"] != 1080:
            raise ValueError
        if config["outbounds"][0]["protocol"] != "vless":
            raise ValueError
        if config["outbounds"][0]["streamSettings"]["security"] != "reality":
            raise ValueError
        profile_text = json.dumps(config, ensure_ascii=True, allow_nan=False,
                                  separators=(",", ":")) + "\n"
    except (KeyError, IndexError, TypeError, ValueError):
        raise ValueError("Invalid local VLESS + Reality configuration.") from None
    if len(profile_text.encode("utf-8")) > 2_000_000:
        raise ValueError("Client configuration is too large.")
    kit_version = metadata.get("kit_version", "development")
    routing_mode = metadata.get("routing_mode", "ru-direct")
    if not isinstance(kit_version, str) or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,40}", kit_version):
        raise ValueError("Invalid build metadata.")
    if routing_mode not in {"ru-direct", "all-vpn"}:
        raise ValueError("Invalid routing mode.")
    build_info = {
        "device": "Keenetic Speedster KN-3013 EAEU",
        "base_keeneticos": "5.1.8",
        "sdk_commit": SDK_COMMIT,
        "xray_version": "26.11.9",
        "xray_architecture": "linux/mipsle softfloat",
        "kit_version": kit_version,
        "routing_mode": routing_mode,
        "client_configuration": "personal profile embedded; do not redistribute image",
        "physical_router_validation": "not performed for this generated image",
    }
    scripts = {}
    for relative in SCRIPTS:
        text = _read(OVERLAY / relative)
        if not text.startswith("#!/bin/ash\n"):
            raise ValueError("Unexpected service script.")
        scripts[relative] = text

    # All inputs have been checked. mkdir(exist_ok=False) also rejects a race
    # that could otherwise silently merge a different user's credentials.
    files.mkdir(mode=0o700)
    for relative, text in scripts.items():
        _write(files / relative, text, 0o755)
    _write(files / "etc/xray/config.json", profile_text, 0o600)
    _write(files / "etc/xray/build-info.json", json.dumps(build_info, indent=2) + "\n", 0o644)
    (files / "opt/bin").symlink_to("/bin")
    destination = files / "usr/bin/xray"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(xray, destination)
    destination.chmod(0o755)
    _write(files / "usr/share/licenses/xray/LICENSE", license_text, 0o644)
    for path, text in ((sdk / ".config", sdk_config), (busybox_path, busybox), (image_path, image_recipe)):
        path.write_text(text, encoding="utf-8", newline="\n")
    return {
        "sdk_commit": SDK_COMMIT,
        "xray_sha256": XRAY_SHA256,
        "removed_packages": removed,
        "added_package": "busybox",
        "modified_boot_binaries": False,
        "modified_flash_layout": False,
        "client_configuration_included": True,
        "routing_mode": routing_mode,
    }
