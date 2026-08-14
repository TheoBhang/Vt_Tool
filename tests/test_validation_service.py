import unittest
from unittest import mock

from app.services.validation_service import ValidationService


class ValidationServiceTests(unittest.TestCase):
    def test_classify_real_public_ip(self):
        service = ValidationService()
        self.assertEqual(service.classify(("8.8.8.8",), "ips"), "Public IPv4")

    def test_classify_real_domain(self):
        service = ValidationService()
        self.assertEqual(service.classify("example.com", "domains"), "DOMAIN")

    def test_classify_real_url(self):
        service = ValidationService()
        self.assertEqual(service.classify("https://example.com", "urls"), "URL")

    def test_classify_hashes_uses_validate_hash_not_validate_hashe(self):
        # "hashes"[:-1] would be "hashe" (no such validator method) - hashes is
        # special-cased, matching today's validate_value() dispatch exactly.
        service = ValidationService()
        self.assertEqual(service.classify("a" * 32, "hashes"), "MD5")

    def test_classify_returns_none_for_unknown_value_type(self):
        service = ValidationService()
        self.assertIsNone(service.classify("example.com", "bogus"))

    def test_classify_delegates_to_injected_validator(self):
        fake_validator = mock.Mock()
        fake_validator.validate_domain.return_value = "DOMAIN"
        service = ValidationService(validator=fake_validator)
        result = service.classify("example.com", "domains")
        fake_validator.validate_domain.assert_called_once_with("example.com")
        self.assertEqual(result, "DOMAIN")


if __name__ == "__main__":
    unittest.main()
