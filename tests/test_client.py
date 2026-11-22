"""Offline tests; identifiers are fake and addresses use documentation ranges."""

import base64
import copy
import ipaddress
from pathlib import Path
import tempfile
import traceback
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from lib.client import ROUTING_FILES, add_routing, parse_vless


FAKE_ID = "00000000-0000-4000-8000-000000000001"
FAKE_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")


def link(host="192.0.2.1", port="443", client_id=FAKE_ID, label="", **overrides):
    params = {"security": "reality", "type": "tcp", "encryption": "none",
              "sni": "example.com", "fp": "chrome", "pbk": FAKE_KEY, "sid": "0123ab"}
    for name, value in overrides.items():
        if value is None:
            params.pop(name, None)
        else:
            params[name] = value
    return f"vless://{client_id}@{host}:{port}?{urlencode(params)}{label}"


class ClientTests(unittest.TestCase):
    def test_base_config_has_loopback_udp_and_short_xray_fields(self):
        config = parse_vless(link(flow="xtls-rprx-vision", spx="/"))
        self.assertEqual(config["inbounds"][0], {
            "tag": "local-socks", "listen": "127.0.0.1", "port": 1080,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
        })
        self.assertEqual(len(config["outbounds"]), 1)
        outbound = config["outbounds"][0]
        self.assertEqual((outbound["tag"], outbound["protocol"]), ("vpn", "vless"))
        self.assertEqual(outbound["settings"], {
            "address": "192.0.2.1", "port": 443, "id": FAKE_ID,
            "encryption": "none", "flow": "xtls-rprx-vision",
        })
        self.assertEqual(outbound["streamSettings"]["method"], "raw")
        reality = outbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["password"], FAKE_KEY)
        self.assertNotIn("publicKey", reality)
        self.assertNotIn("routing", config)

    def test_ipv6_and_hostname_authorities(self):
        for host, expected in (("[2001:db8::1]", "2001:db8::1"),
                               ("VPN.Example.COM.", "vpn.example.com")):
            with self.subTest(host=host):
                result = parse_vless(link(host=host, port="65535"))
                self.assertEqual(result["outbounds"][0]["settings"]["address"], expected)

    def test_idna_sni_ip_sni_labels_and_short_id_normalization(self):
        result = parse_vless(link(sni="пример.рф", sid="AA0123", label="#Keenetic%20test"))
        reality = result["outbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["serverName"], "xn--e1afmkfd.xn--p1ai")
        self.assertEqual(reality["shortId"], "aa0123")
        self.assertNotIn("Keenetic", str(result))
        for sni in ("198.51.100.1", "2001:db8::2"):
            self.assertEqual(parse_vless(link(sni=sni))["outbounds"][0]["streamSettings"]
                             ["realitySettings"]["serverName"], sni)

    def test_defaults_and_supported_flows(self):
        for flow in (None, "", "xtls-rprx-vision", "xtls-rprx-vision-udp443"):
            with self.subTest(flow=flow):
                result = parse_vless(link(flow=flow, type=None, encryption=None, fp=None, sid=None))
                outbound = result["outbounds"][0]
                self.assertEqual(outbound["settings"]["flow"], flow or "")
                self.assertEqual(outbound["streamSettings"]["realitySettings"]["shortId"], "")
                self.assertEqual(outbound["streamSettings"]["realitySettings"]["fingerprint"], "chrome")

    def test_supported_fingerprints_and_raw_alias(self):
        for fingerprint in ("chrome", "firefox", "safari", "ios", "android", "edge",
                            "360", "qq", "random", "randomized"):
            with self.subTest(fingerprint=fingerprint):
                parse_vless(link(type="raw", fp=fingerprint))

    def test_rejects_bad_authorities_and_uuid(self):
        examples = [
            link(port="0"), link(port="65536"), link(port="-1"), link(port=""),
            link(port="443junk"), link(port="+443"), link(port="000443"),
            link(host="2001:db8::1"), link(host="[2001:db8::1]evil"),
            link(host="[192.0.2.1]"), link(host="[2001:db8::1%25eth0]"),
            link(host="[2001:db8::1"), link(host="192.0.2.999"),
            link(host="0127.0.0.1"), link(host="-bad.example"), link(host="bad..example"),
            link(host="a" * 64 + ".example"), link(host="example.com@192.0.2.2"),
            link(client_id="not-a-uuid"), link(client_id="{" + FAKE_ID + "}"),
            link(client_id=FAKE_ID.replace("-", "")), link(client_id=FAKE_ID + ":password"),
            link(client_id=FAKE_ID + ":"), link(client_id=""),
        ]
        for value in examples:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_vless(value)

    def test_rejects_unsupported_or_duplicate_parameters(self):
        examples = [
            link(security=None), link(security="tls"), link(type="ws"),
            link(encryption="aes-128-gcm"), link(flow="vision"),
            link(headerType="http"), link(allowInsecure="1"), link(fp="unsafe"),
            link(fp="not-a-browser"), link(fp=""), link() + "&type=raw",
            link() + "&%74ype=tcp", link() + "&unknown", link() + "&",
            link() + "&sni=other.example", link() + "&sni[]=other.example",
            link().replace("vless://", "https://"), link().replace("?", "/ws?", 1),
        ]
        for value in examples:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_vless(value)

    def test_key_short_id_and_domain_bounds(self):
        # Last base64 character's low two bits must be zero for a 32-byte key.
        noncanonical = FAKE_KEY[:-1] + chr(ord(FAKE_KEY[-1]) + 1)
        self.assertEqual(base64.urlsafe_b64decode(noncanonical + "="), bytes(range(32)))
        examples = [
            link(pbk=""), link(pbk=FAKE_KEY + "="), link(pbk=FAKE_KEY[:-1]),
            link(pbk="+" + FAKE_KEY[1:]), link(pbk=noncanonical),
            link(sid="a"), link(sid="abc"), link(sid="a" * 18), link(sid="xz"),
            link(sni=""), link(sni="*.example.com"), link(sni="example.com:443"),
            link(sni="https://example.com"), link(sni="bad_name.example"),
            link(sni="a" * 64 + ".example"), link(sni=("a" * 63 + ".") * 4 + "com"),
            link(sni="example..com"), link(sni="example.com/path"),
        ]
        for value in examples:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_vless(value)

    def test_rejects_controls_and_uri_injection(self):
        examples = [
            None, b"vless://", "", " " + link(), link() + "\n", link() + "\t",
            link(sni="example.com\r\nInjected:yes"), link(sni="example.com\\evil"),
            link(spx="//other.example/path"), link(spx="https://example.com/"),
            link(spx="/\r\nInjected:yes"), link(spx="/%0d%0aInjected"),
            link(spx="/%2fother.example"), link(spx="/%20space"),
            link(spx="/\\evil"), link(spx="/bad%escape"), link(spx="/x#fragment"),
            link(label="#label%00"), link(label="#label%0d%0a"),
            link(label="#%E2%80%AEhidden"), link(label="#%FF"), link(label="#bad%escape"),
            link().replace("sni=example.com", "sni=%FF"),
            link().replace("sni=example.com", "sni=example.com%00"),
            link() + "#" + "x" * 8192,
        ]
        for value in examples:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_vless(value)

    def test_error_does_not_disclose_secrets_in_message_or_traceback(self):
        marker = "PRIVATE_LINK_SENTINEL"
        for value in (link(**{marker: marker}), link(client_id=marker),
                      link(host="[" + marker), link(pbk=marker), link(sni=marker + "/")):
            try:
                parse_vless(value)
            except ValueError as error:
                output = "".join(traceback.format_exception(type(error), error, error.__traceback__))
                for secret in (value, marker, FAKE_ID, FAKE_KEY):
                    self.assertNotIn(secret, output)
                self.assertTrue(error.__suppress_context__)
            else:
                self.fail("Invalid input accepted")


def routed_destination(config, domain=None, address=None, resolved=()):
    """Small independent model of Xray's documented first-match/two-pass semantics.

    It tests rule precedence, not DNS/sniffing implementation or network reachability.
    ``address`` represents the original SOCKS IP when routeOnly sniffing finds a name.
    """
    def match(ips):
        for rule in config["routing"]["rules"]:
            domains = rule.get("domain")
            networks = rule.get("ip")
            if domains is not None:
                if not domain or not any(domain == item[7:] or domain.endswith("." + item[7:])
                                         for item in domains if item.startswith("domain:")):
                    continue
            if networks is not None:
                if not any(ipaddress.ip_address(ip) in ipaddress.ip_network(network)
                           for ip in ips for network in networks):
                    continue
            return rule["outboundTag"]
        return None
    first = match([address] if address else [])
    if first is not None:
        return first
    if domain and config["routing"]["domainStrategy"] == "IPIfNonMatch":
        second = match(resolved)
        if second is not None:
            return second
    return config["outbounds"][0]["tag"]


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        data = {
            "russia-inside.txt": "# public source fixture\nblocked.example\nportal.ru\nпример.рф\n",
            "telegram-domains.txt": "messenger.example\n.Sub.Messenger.Example.\n",
            "telegram-ipv4.txt": "203.0.113.64/26\n",
            "russia-ip.txt": "198.51.100.0/24\n203.0.113.0/24\n2001:db8:1::/48\n",
        }
        self.assertEqual(set(data), set(ROUTING_FILES))
        for name, text in data.items():
            (self.root / name).write_text(text, encoding="utf-8")
        self.base = parse_vless(link())

    def test_config_copy_and_sniffing_preserve_original_destination(self):
        before = copy.deepcopy(self.base)
        result = add_routing(self.base, self.root)
        self.assertEqual(self.base, before)
        self.assertIsNot(result, self.base)
        self.assertEqual(result["outbounds"][0], before["outbounds"][0])
        self.assertEqual(result["inbounds"][0]["sniffing"], {
            "enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True,
        })
        self.assertEqual(result["dns"], {"servers": ["localhost"]})
        result["outbounds"][0]["settings"]["id"] = "changed"
        self.assertEqual(self.base, before)

    def test_domain_and_ip_precedence_and_no_catchall(self):
        result = add_routing(self.base, self.root)
        cases = (
            ("portal.ru", "203.0.113.70", (), "direct"),
            ("www.portal.ru", "192.0.2.30", (), "direct"),
            ("example.xn--p1ai", "192.0.2.30", (), "direct"),
            ("blocked.example", "198.51.100.10", (), "vpn"),
            ("messenger.example", "198.51.100.10", (), "vpn"),
            ("sub.messenger.example", "203.0.113.20", (), "vpn"),
            (None, "203.0.113.70", (), "vpn"),  # Telegram beats overlapping RU range.
            (None, "203.0.113.20", (), "direct"),
            (None, "2001:db8:1::10", (), "direct"),
            (None, "192.0.2.30", (), "vpn"),
            ("ordinary.example", None, ("198.51.100.10",), "direct"),
            ("ordinary.example", None, ("192.0.2.30",), "vpn"),
            ("portal.ru.foreign.example", "192.0.2.30", (), "vpn"),
            ("portal.notru", "192.0.2.30", (), "vpn"),
        )
        for domain, address, resolved, expected in cases:
            with self.subTest(domain=domain, address=address):
                self.assertEqual(routed_destination(result, domain, address, resolved), expected)
        for rule in result["routing"]["rules"]:
            self.assertTrue(rule.get("domain") or rule.get("ip"), "A catch-all breaks DNS second pass")
            self.assertNotIn("network", rule)
        vpn_domains = {entry for rule in result["routing"]["rules"] if rule["outboundTag"] == "vpn"
                       for entry in rule.get("domain", [])}
        self.assertNotIn("domain:portal.ru", vpn_domains)
        self.assertNotIn("domain:xn--e1afmkfd.xn--p1ai", vpn_domains)
        self.assertIn("domain:sub.messenger.example", vpn_domains)

    def test_private_ips_have_priority_without_using_live_test_addresses(self):
        result = add_routing(self.base, self.root)
        first = result["routing"]["rules"][0]
        self.assertEqual(first["outboundTag"], "direct")
        self.assertIn("192.168.0.0/16", first["ip"])
        self.assertIn("fc00::/7", first["ip"])

    def test_all_vpn_never_reads_cached_files(self):
        with patch.object(Path, "stat", side_effect=AssertionError("Must not read cache")), \
                patch.object(Path, "open", side_effect=AssertionError("Must not read cache")):
            result = add_routing(self.base, self.root / "absent", mode="all-vpn")
        self.assertEqual(result, self.base)
        self.assertIsNot(result, self.base)

    def test_rejects_missing_empty_bad_encoding_and_default_routes(self):
        bad_files = (
            ("russia-inside.txt", b"# only comments\n"),
            ("russia-inside.txt", b"*.example.com\n"),
            ("russia-inside.txt", b"https://example.com\n"),
            ("russia-inside.txt", b"a..example\n"),
            ("russia-inside.txt", b"-bad.example\n"),
            ("russia-inside.txt", b"a" * 64 + b".example\n"),
            ("russia-inside.txt", b"example.\x00com\n"),
            ("russia-inside.txt", b"first.example\x0bsecond.example\n"),
            ("russia-inside.txt", b"com\n"),
            ("russia-inside.txt", b".a\n"),
            ("russia-inside.txt", b".123\n"),
            ("russia-inside.txt", b"..ua\n"),
            ("russia-inside.txt", b"\xff\n"),
            ("russia-ip.txt", b"198.51.100.1/24\n"),
            ("russia-ip.txt", b"198.51.100.0/33\n"),
            ("russia-ip.txt", b"0.0.0.0/0\n"),
            ("russia-ip.txt", b"::/0\n"),
            ("telegram-ipv4.txt", b"2001:db8::/32\n"),
        )
        for name, data in bad_files:
            path = self.root / name
            old = path.read_bytes()
            try:
                path.write_bytes(data)
                with self.subTest(name=name, data=data):
                    with self.assertRaises(ValueError):
                        add_routing(self.base, self.root)
            finally:
                path.write_bytes(old)
        (self.root / "russia-ip.txt").unlink()
        with self.assertRaises(ValueError):
            add_routing(self.base, self.root)

    def test_file_and_item_bounds(self):
        for constant, limit in (("MAX_SOURCE_BYTES", 10), ("MAX_DOMAINS", 1),
                                ("MAX_RUSSIA_NETWORKS", 2), ("MAX_TELEGRAM_NETWORKS", 0)):
            with self.subTest(constant=constant), patch("lib.client." + constant, limit):
                with self.assertRaises(ValueError):
                    add_routing(self.base, self.root)

    def test_bom_comments_deduplication_and_cidr_collapse(self):
        (self.root / "russia-inside.txt").write_bytes(b"\xef\xbb\xbf# comment\nBlocked.Example\nblocked.example\n")
        (self.root / "russia-ip.txt").write_text("198.51.100.0/25\n198.51.100.128/25\n", encoding="utf-8")
        result = add_routing(self.base, self.root)
        self.assertEqual(result["routing"]["rules"][-1]["ip"], ["198.51.100.0/24"])
        domains = result["routing"]["rules"][2]["domain"]
        self.assertEqual(domains.count("domain:blocked.example"), 1)

    def test_explicit_tld_suffix_in_public_source(self):
        # The pinned allow-domains Russia/inside-raw.lst includes exactly '.ua'.
        (self.root / "russia-inside.txt").write_text(
            ".ua\n.UA\n.ru\n.\u0440\u0444\nblocked.example\n", encoding="utf-8")
        result = add_routing(self.base, self.root)
        domains = result["routing"]["rules"][2]["domain"]
        self.assertEqual(domains.count("domain:ua"), 1)
        self.assertNotIn("domain:ru", domains)
        self.assertNotIn("domain:xn--p1ai", domains)
        self.assertEqual(routed_destination(result, "portal.ua", "198.51.100.10"), "vpn")
        self.assertEqual(routed_destination(result, "portal.notua", "198.51.100.10"), "direct")

    def test_configuration_and_routing_errors_are_redacted(self):
        marker = "PRIVATE_DATA_SENTINEL"
        bad_base = copy.deepcopy(self.base)
        bad_base["outbounds"][0]["tag"] = marker
        bad_file = self.root / "russia-inside.txt"
        bad_file.write_text(marker + "/invalid", encoding="utf-8")
        for base, mode in ((bad_base, "ru-direct"), (self.base, marker), (self.base, "ru-direct")):
            with self.subTest(mode=mode):
                try:
                    add_routing(base, self.root, mode)
                except ValueError as error:
                    self.assertNotIn(marker, str(error))
                    self.assertNotIn(FAKE_ID, str(error))
                    self.assertNotIn(FAKE_KEY, str(error))
                    self.assertNotIn(str(self.root), str(error))
                else:
                    self.fail("Invalid routing accepted")

    def test_rejects_reapplying_rules_and_non_loopback_inbound(self):
        routed = add_routing(self.base, self.root)
        with self.assertRaises(ValueError):
            add_routing(routed, self.root)
        self.base["inbounds"][0]["listen"] = "192.0.2.1"
        with self.assertRaises(ValueError):
            add_routing(self.base, self.root)


if __name__ == "__main__":
    unittest.main()
