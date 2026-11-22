"""Strict, offline VLESS + REALITY configuration for Xray 26.11.9.

The returned config contains credentials: keep it out of logs and repositories.
This module neither downloads routing data nor contacts the VPN server.
"""

from __future__ import annotations

import base64
import copy
import ipaddress
from pathlib import Path
import re
import stat
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit
import uuid


ROUTING_FILES = (
    "russia-inside.txt",
    "telegram-domains.txt",
    "telegram-ipv4.txt",
    "russia-ip.txt",
)
MAX_LINK_LENGTH = 8192
MAX_SOURCE_BYTES = 4_000_000
MAX_DOMAINS = 10_000
MAX_RUSSIA_NETWORKS = 100_000
MAX_TELEGRAM_NETWORKS = 500

_PARAMETERS = frozenset({
    "security", "type", "encryption", "flow", "sni", "fp", "pbk",
    "sid", "spx", "headerType",
})
# Deliberately support the documented portable names, not every uTLS version alias.
# https://xtls.github.io/en/config/transports/tls.html#tlsobject
_FINGERPRINTS = frozenset({
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "randomized",
})
_FLOWS = frozenset({"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"})
_PRIVATE_IPS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
    "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)
_EXTRA_VPN_DOMAINS = frozenset({
    "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
    "ipwho.is", "ipapi.co",
})
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_LINK_ERROR = "Invalid or unsupported VLESS + REALITY link."
_ROUTING_ERROR = "Invalid, missing, or oversized local routing data."
_CONFIG_ERROR = "Expected an unrouted loopback SOCKS client configuration."


def _has_controls(value: str) -> bool:
    return any(unicodedata.category(char).startswith("C") for char in value)


def _domain(value: str) -> str:
    if not value or _has_controls(value) or any(char.isspace() for char in value):
        raise ValueError
    value = value.removesuffix(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(_LABEL.fullmatch(label) for label in value.split(".")):
        raise ValueError
    # Avoid interpreting malformed IPv4 literals as DNS names.
    if all(char in "0123456789." for char in value):
        raise ValueError
    return value


def _host(value: str) -> str:
    if not value or "%" in value or "\\" in value or _has_controls(value):
        raise ValueError
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return _domain(value)


def parse_vless(link: str) -> dict:
    """Parse one RAW/TCP + REALITY URI, raising a redacted ValueError on failure.

    Only the documented parameters in this module are supported. A UTF-8 label
    after ``#`` is decoded and discarded. The caller may strip a file's final
    newline before calling; whitespace/control characters in the URI are rejected.
    ``sid`` may be empty and is normalized to lowercase; ``pbk`` must be canonical
    unpadded base64url encoding of 32 bytes. SNI may also be an IP, as Xray allows.
    """
    try:
        return _parse_vless(link)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        # Do not expose urlsplit/ipaddress/UUID exception strings or their causes.
        raise ValueError(_LINK_ERROR) from None


def _parse_vless(link: str) -> dict:
    if (not isinstance(link, str) or not 1 <= len(link) <= MAX_LINK_LENGTH
            or _has_controls(link) or any(char.isspace() for char in link)
            or "\\" in link or _BAD_PERCENT.search(link)):
        raise ValueError
    url = urlsplit(link)
    if (url.scheme.lower() != "vless" or url.netloc.count("@") != 1
            or url.password is not None or not url.username
            or not _UUID.fullmatch(url.username) or url.path not in {"", "/"}):
        raise ValueError
    client_id = str(uuid.UUID(url.username))
    # Validate the literal authority too: urlsplit tolerates suffixes after ']'.
    authority = url.netloc.rsplit("@", 1)[1]
    if authority.startswith("["):
        match = re.fullmatch(r"\[([^\[\]]+)\]:([0-9]{1,5})", authority)
        if not match or ipaddress.ip_address(match[1]).version != 6:
            raise ValueError
    else:
        match = re.fullmatch(r"([^:\[\]]+):([0-9]{1,5})", authority)
        if not match:
            raise ValueError
    host = _host(match[1])
    port = int(match[2])
    if not 1 <= port <= 65535:
        raise ValueError
    query = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                      encoding="utf-8", errors="strict", max_num_fields=len(_PARAMETERS))
    params = {}
    for name, value in query:
        if (name not in _PARAMETERS or name in params or _has_controls(value)
                or any(char.isspace() for char in value) or "\\" in value):
            raise ValueError
        params[name] = value
    if (params.get("security") != "reality"
            or params.get("type", "tcp") not in {"tcp", "raw"}
            or params.get("encryption", "none") != "none"
            or params.get("headerType", "none") != "none"
            or params.get("flow", "") not in _FLOWS):
        raise ValueError
    public_key = params.get("pbk", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
        raise ValueError
    key_bytes = base64.urlsafe_b64decode(public_key + "=")
    if (len(key_bytes) != 32
            or base64.urlsafe_b64encode(key_bytes).decode("ascii").rstrip("=") != public_key):
        raise ValueError
    short_id = params.get("sid", "")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
        raise ValueError
    server_name = _host(params.get("sni", ""))
    fingerprint = params.get("fp", "chrome")
    if fingerprint not in _FINGERPRINTS:
        raise ValueError
    spider = params.get("spx", "/")
    if (not spider.startswith("/") or spider.startswith("//") or "#" in spider
            or not spider.isascii() or len(spider) > 2048 or _BAD_PERCENT.search(spider)):
        raise ValueError
    # Reject nested encodings of controls as well as directly encoded ones.
    decoded_spider = unquote(spider, encoding="utf-8", errors="strict")
    if (_has_controls(decoded_spider) or "\\" in decoded_spider
            or decoded_spider.startswith("//")
            or any(char.isspace() for char in decoded_spider)):
        raise ValueError
    label = unquote(url.fragment, encoding="utf-8", errors="strict")
    if _has_controls(label):
        raise ValueError
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [{
            "tag": "local-socks", "listen": "127.0.0.1", "port": 1080,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
        }],
        "outbounds": [{
            "tag": "vpn", "protocol": "vless",
            "settings": {"address": host, "port": port, "id": client_id,
                         "encryption": "none", "flow": params.get("flow", "")},
            "streamSettings": {
                "method": "raw", "security": "reality",
                "realitySettings": {
                    "serverName": server_name, "fingerprint": fingerprint,
                    "password": public_key, "shortId": short_id.lower(), "spiderX": spider,
                },
            },
        }],
    }


def _read_lines(path: Path, max_lines: int) -> list[str]:
    # Regular local files only; bounded read also covers a file growing after stat.
    if path.is_symlink():
        raise ValueError
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_SOURCE_BYTES:
        raise ValueError
    with path.open("rb") as stream:
        data = stream.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError
    text = data.decode("utf-8-sig")
    if any(unicodedata.category(char).startswith("C") and char not in "\r\n\t" for char in text):
        raise ValueError
    result = []
    for line in text.split("\n"):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if _has_controls(value) or any(char.isspace() for char in value):
            raise ValueError
        result.append(value)
        if len(result) > max_lines:
            raise ValueError
    if not result:
        raise ValueError
    return result


def _domains(path: Path) -> set[str]:
    domains = set()
    for line in _read_lines(path, MAX_DOMAINS):
        value = _domain(line.removeprefix("."))
        # Public allow-domains explicitly writes TLD suffixes as '.ua'. Accept
        # that notation, but keep rejecting accidental bare entries such as 'com'.
        if "." not in value and not (
            line.startswith(".")
            and re.fullmatch(r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})", value)
        ):
            raise ValueError
        domains.add(value)
    return domains


def _networks(path: Path, max_lines: int, only_ipv4: bool = False) -> list[str]:
    result = []
    values = []
    for line in _read_lines(path, max_lines):
        if len(line) > 49 or "%" in line:
            raise ValueError
        value = ipaddress.ip_network(line, strict=True)
        if value.prefixlen == 0 or (only_ipv4 and value.version != 4):
            raise ValueError
        values.append(value)
    for version in (4, 6):
        collapsed = ipaddress.collapse_addresses(n for n in values if n.version == version)
        for network in collapsed:
            if network.prefixlen == 0:
                raise ValueError
            result.append(str(network))
    return result


def _base_copy(config: dict) -> dict:
    try:
        inbound, = config["inbounds"]
        outbound, = config["outbounds"]
        if (inbound["listen"] != "127.0.0.1" or inbound["port"] != 1080
                or inbound["protocol"] != "socks" or inbound["settings"]["udp"] is not True
                or outbound["tag"] != "vpn" or outbound["protocol"] != "vless"
                or "routing" in config or "dns" in config):
            raise ValueError
        return copy.deepcopy(config)
    except (ValueError, KeyError, TypeError):
        raise ValueError(_CONFIG_ERROR) from None


def add_routing(config: dict, routing_dir: Path, mode: str = "ru-direct") -> dict:
    """Return a separate config with cached RU bypass rules, or all traffic via VPN.

    ``config`` must be the unrouted result of :func:`parse_vless`. ``all-vpn``
    ignores ``routing_dir``. ``ru-direct`` requires all four ``ROUTING_FILES``;
    source authenticity/freshness must be checked by the caller. Geographic IP
    lists and sniffing are approximate and cannot identify every Russian service.
    """
    if mode not in ("ru-direct", "all-vpn"):
        raise ValueError("Unsupported routing mode; choose ru-direct or all-vpn.")
    result = _base_copy(config)
    if mode == "all-vpn":
        return result
    try:
        root = Path(routing_dir)
        vpn_domains = (_domains(root / ROUTING_FILES[0])
                       | _domains(root / ROUTING_FILES[1]) | _EXTRA_VPN_DOMAINS)
        vpn_domains = sorted(domain for domain in vpn_domains if not any(
            domain == suffix or domain.endswith("." + suffix)
            for suffix in ("ru", "xn--p1ai")
        ))
        if len(vpn_domains) > MAX_DOMAINS:
            raise ValueError
        telegram_ips = _networks(root / ROUTING_FILES[2], MAX_TELEGRAM_NETWORKS, only_ipv4=True)
        russia_ips = _networks(root / ROUTING_FILES[3], MAX_RUSSIA_NETWORKS)
    except (ValueError, TypeError, OSError, UnicodeError):
        raise ValueError(_ROUTING_ERROR) from None
    result["inbounds"][0]["sniffing"] = {
        "enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True,
    }
    result["outbounds"].append({"tag": "direct", "protocol": "freedom", "settings": {}})
    result["dns"] = {"servers": ["localhost"]}
    result["routing"] = {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {"type": "field", "ip": list(_PRIVATE_IPS), "outboundTag": "direct"},
            {"type": "field", "domain": ["domain:ru", "domain:xn--p1ai"], "outboundTag": "direct"},
            {"type": "field", "domain": ["domain:" + domain for domain in vpn_domains], "outboundTag": "vpn"},
            {"type": "field", "ip": telegram_ips, "outboundTag": "vpn"},
            {"type": "field", "ip": russia_ips, "outboundTag": "direct"},
        ],
    }
    # No final catch-all: it would suppress IPIfNonMatch's DNS/IP second pass.
    # Xray's default when no rule matches is the FIRST outbound, which stays VPN.
    return result
