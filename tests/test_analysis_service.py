import unittest
from unittest import mock

from app.errors import ValidationError
from app.services.analysis_service import AnalysisService, UNSUPPORTED_VALUE_TYPES


class UnsupportedValueTypesTests(unittest.TestCase):
    def test_contains_exact_expected_set(self):
        self.assertEqual(
            UNSUPPORTED_VALUE_TYPES,
            {
                "Private IPv4", "Loopback IPv4", "Unspecified IPv4", "Link-local IPv4",
                "Reserved IPv4", "SHA-224", "SHA-384", "SHA-512", "SSDEEP",
            },
        )


class AnalysisServiceTests(unittest.TestCase):
    def setUp(self):
        self.validation = mock.Mock()
        self.virustotal = mock.Mock()
        self.cache = mock.Mock()
        self.service = AnalysisService(self.validation, self.virustotal, self.cache)

    def test_cache_hit_returns_cached_report_without_calling_virustotal_or_classifying(self):
        self.cache.get.return_value = {"malicious_score": 5}

        report, from_cache = self.service.analyze("example.com", "domains")

        self.assertEqual(report, {"malicious_score": 5})
        self.assertTrue(from_cache)
        self.cache.get.assert_called_once_with("domains", "example.com")
        self.virustotal.get_report.assert_not_called()
        self.validation.classify.assert_not_called()

    def test_cache_miss_validates_fetches_and_caches(self):
        self.cache.get.return_value = None
        self.validation.classify.return_value = "DOMAIN"
        self.virustotal.get_report.return_value = {"malicious_score": 9}

        report, from_cache = self.service.analyze("example.com", "domains")

        self.assertEqual(report, {"malicious_score": 9})
        self.assertFalse(from_cache)
        self.cache.get.assert_called_once_with("domains", "example.com")
        self.validation.classify.assert_called_once_with("example.com", "domains")
        self.virustotal.get_report.assert_called_once_with("DOMAIN", "example.com")
        self.cache.set.assert_called_once_with("domains", "example.com", {"malicious_score": 9})

    def test_unsupported_classification_raises_validation_error_without_querying_vt(self):
        self.cache.get.return_value = None
        self.validation.classify.return_value = "Private IPv4"

        with self.assertRaises(ValidationError):
            self.service.analyze(("192.168.1.1",), "ips")
        self.virustotal.get_report.assert_not_called()
        self.cache.set.assert_not_called()

    def test_unclassifiable_value_raises_validation_error(self):
        self.cache.get.return_value = None
        self.validation.classify.return_value = None

        with self.assertRaises(ValidationError):
            self.service.analyze("not a real domain", "domains")
        self.virustotal.get_report.assert_not_called()
        self.cache.set.assert_not_called()

    def test_ip_tuple_uses_plain_ip_string_as_cache_key_but_full_tuple_for_virustotal(self):
        self.cache.get.return_value = None
        self.validation.classify.return_value = "Public IPv4"
        self.virustotal.get_report.return_value = {"malicious_score": 0}

        self.service.analyze(("8.8.8.8", "443"), "ips")

        self.cache.get.assert_called_once_with("ips", "8.8.8.8")
        self.virustotal.get_report.assert_called_once_with("PUBLIC IPV4", ("8.8.8.8", "443"))
        self.cache.set.assert_called_once_with("ips", "8.8.8.8", {"malicious_score": 0})

    def test_hashes_value_type_canonical_form_is_uppercased_for_virustotal_only(self):
        self.cache.get.return_value = None
        self.validation.classify.return_value = "MD5"
        self.virustotal.get_report.return_value = {"malicious_score": 0}

        self.service.analyze("a" * 32, "hashes")

        self.cache.get.assert_called_once_with("hashes", "a" * 32)
        self.virustotal.get_report.assert_called_once_with("MD5", "a" * 32)


if __name__ == "__main__":
    unittest.main()
