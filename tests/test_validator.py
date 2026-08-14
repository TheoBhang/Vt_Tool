import unittest
from unittest import mock

import tldextract

import app.DataHandler.validator as validator_mod
from app.DataHandler.validator import (
    DataValidator,
    get_url_details,
    get_service_name,
    get_port_from_service_name,
    extract_ip_address,
)


def setUpModule():
    # get_url_details() calls the module-level tldextract.extract(), which
    # uses tldextract's global default instance and can hit the network on
    # a cold cache. Patch just the `extract` attribute (not the whole
    # module, which would also shadow tldextract.TLDExtract used by
    # DataValidator.__init__) to a local, network-free instance so tests
    # never perform real I/O regardless of cache state.
    global _tldextract_patcher
    offline_extract = tldextract.TLDExtract(
        cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True
    )
    _tldextract_patcher = mock.patch.object(
        validator_mod.tldextract, "extract", offline_extract
    )
    _tldextract_patcher.start()


def tearDownModule():
    _tldextract_patcher.stop()


class ValidateIpTests(unittest.TestCase):
    def setUp(self):
        self.validator = DataValidator()

    def test_public_ipv4(self):
        self.assertEqual(self.validator.validate_ip(("8.8.8.8",)), "Public IPv4")

    def test_private_ipv4(self):
        self.assertEqual(self.validator.validate_ip(("192.168.1.1",)), "Private IPv4")

    def test_loopback_ipv4_is_classified_as_private(self):
        # ipaddress.IPv4Address("127.0.0.1").is_private is True, and validate_ip
        # checks is_private before is_loopback, so the "Private" branch wins.
        # The "Loopback IPv4" branch is effectively unreachable for IPv4.
        # Documents current behavior; not a claim that it's correct.
        self.assertEqual(self.validator.validate_ip(("127.0.0.1",)), "Private IPv4")

    def test_public_ipv6(self):
        self.assertEqual(
            self.validator.validate_ip(("2606:4700:4700::1111",)), "Public IPv6"
        )

    def test_invalid_ip_returns_none(self):
        self.assertIsNone(self.validator.validate_ip(("999.999.999.999",)))

    def test_valid_public_ipv4_as_plain_string(self):
        self.assertEqual(self.validator.validate_ip("8.8.8.8"), "Public IPv4")


class ValidateDomainTests(unittest.TestCase):
    def setUp(self):
        self.validator = DataValidator()

    def test_valid_domain(self):
        self.assertEqual(self.validator.validate_domain("example.com"), "DOMAIN")

    def test_localhost_is_not_a_domain(self):
        self.assertIsNone(self.validator.validate_domain("localhost"))

    def test_plain_text_is_not_a_domain(self):
        self.assertIsNone(self.validator.validate_domain("just some text"))


class ValidateHashTests(unittest.TestCase):
    def setUp(self):
        self.validator = DataValidator()

    def test_md5_by_length(self):
        self.assertEqual(self.validator.validate_hash("a" * 32), "MD5")

    def test_sha1_by_length(self):
        self.assertEqual(self.validator.validate_hash("a" * 40), "SHA-1")

    def test_sha256_by_length(self):
        self.assertEqual(self.validator.validate_hash("a" * 64), "SHA-256")

    def test_ssdeep_by_pattern(self):
        self.assertEqual(
            self.validator.validate_hash("3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr"),
            "SSDEEP",
        )

    def test_invalid_hash_returns_none(self):
        self.assertIsNone(self.validator.validate_hash("abc123"))


class ValidateUrlTests(unittest.TestCase):
    def setUp(self):
        self.validator = DataValidator()

    def test_valid_url(self):
        self.assertEqual(self.validator.validate_url("https://example.com"), "URL")

    def test_invalid_url_returns_none(self):
        self.assertIsNone(self.validator.validate_url("not a url"))


class GetUrlDetailsTests(unittest.TestCase):
    def test_parses_all_components(self):
        details = get_url_details(
            "https://sub.example.com:8443/path/to/res?a=1&b=2#frag"
        )
        self.assertEqual(details["scheme"], "https")
        self.assertEqual(details["subdomain"], "sub")
        self.assertEqual(details["domain"], "example.com")
        self.assertEqual(details["tld"], "com")
        self.assertEqual(details["port"], 8443)
        self.assertEqual(details["resource_path"], "/path/to/res")
        self.assertEqual(details["query_strings"], "a=1&b=2")
        self.assertEqual(details["query_params"], {"a": ["1"], "b": ["2"]})
        self.assertEqual(details["fragment"], "frag")


class ServiceNameLookupTests(unittest.TestCase):
    def test_get_service_name_known_port(self):
        self.assertEqual(get_service_name(80), "http")

    def test_get_service_name_invalid_port(self):
        self.assertIsNone(get_service_name("not-a-port"))

    def test_get_port_from_service_name_known_service(self):
        self.assertEqual(get_port_from_service_name("http"), 80)

    def test_get_port_from_service_name_unknown_service(self):
        self.assertIsNone(get_port_from_service_name("not-a-real-service"))


class ExtractIpAddressTests(unittest.TestCase):
    def test_extracts_ip_from_whois_style_text(self):
        text = "Name: foo\nIP Address: 10.20.30.40\nOther: x"
        self.assertEqual(extract_ip_address(text), "10.20.30.40")

    def test_returns_none_when_no_match(self):
        self.assertIsNone(extract_ip_address("no ip here"))


if __name__ == "__main__":
    unittest.main()
