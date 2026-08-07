import unittest
from unittest import mock

from app.services.cache_service import ReportCacheService

NOT_FOUND_ERROR = "Not found"


class ReportCacheServiceTests(unittest.TestCase):
    def test_get_returns_none_when_backend_has_nothing(self):
        backend = mock.Mock()
        backend.get.return_value = None
        service = ReportCacheService(backend)
        self.assertIsNone(service.get("DOMAIN", "example.com"))
        backend.get.assert_called_once_with("DOMAIN", "example.com")

    def test_get_returns_the_report_on_a_real_hit(self):
        backend = mock.Mock()
        backend.get.return_value = {
            "malicious_score": 5, "total_scans": 70, "tags": "phishing",
            "link": "l", "domain": "example.com",
        }
        service = ReportCacheService(backend)
        self.assertEqual(service.get("DOMAIN", "example.com")["malicious_score"], 5)

    def test_get_treats_mostly_empty_report_as_a_miss(self):
        # Same ratio-based heuristic as the old DBHandler.exists(), now correctly
        # comparing against NOT_FOUND_ERROR (the case-sensitivity bug fixed
        # earlier this session stays fixed here).
        backend = mock.Mock()
        mostly_empty = {k: NOT_FOUND_ERROR for k in range(10)}
        mostly_empty[0] = "example.com"  # 1 real field out of 10 -> 90% empty
        backend.get.return_value = mostly_empty
        service = ReportCacheService(backend)
        self.assertIsNone(service.get("DOMAIN", "example.com"))

    def test_get_keeps_a_mostly_populated_report(self):
        backend = mock.Mock()
        mostly_full = {k: "real value" for k in range(10)}
        mostly_full[0] = NOT_FOUND_ERROR  # 1 empty field out of 10 -> 10% empty
        backend.get.return_value = mostly_full
        service = ReportCacheService(backend)
        self.assertIsNotNone(service.get("DOMAIN", "example.com"))

    def test_set_delegates_to_backend(self):
        backend = mock.Mock()
        service = ReportCacheService(backend)
        report = {"malicious_score": 1}
        service.set("URL", "http://example.com", report)
        backend.set.assert_called_once_with("URL", "http://example.com", report)


if __name__ == "__main__":
    unittest.main()
