import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from app.services.cache_service import ReportCacheService


def iso_at(delta: timedelta) -> str:
    """An ISO timestamp `delta` away from now - negative delta = in the past."""
    return (datetime.now(timezone.utc) + delta).isoformat()


class ReportCacheServiceTests(unittest.TestCase):
    def test_get_returns_none_when_backend_has_nothing(self):
        backend = mock.Mock()
        backend.get.return_value = None
        service = ReportCacheService(backend)
        self.assertIsNone(service.get("DOMAIN", "example.com"))
        backend.get.assert_called_once_with("DOMAIN", "example.com")

    def test_get_returns_the_report_when_within_ttl(self):
        backend = mock.Mock()
        report = {"malicious_score": 5, "domain": "example.com"}
        backend.get.return_value = (report, iso_at(timedelta(hours=-1)))
        service = ReportCacheService(backend, ttl=timedelta(hours=24))
        self.assertEqual(service.get("DOMAIN", "example.com"), report)

    def test_get_returns_none_when_past_ttl(self):
        backend = mock.Mock()
        report = {"malicious_score": 5, "domain": "example.com"}
        backend.get.return_value = (report, iso_at(timedelta(hours=-25)))
        service = ReportCacheService(backend, ttl=timedelta(hours=24))
        self.assertIsNone(service.get("DOMAIN", "example.com"))

    def test_a_cached_not_found_report_is_a_real_hit_within_ttl(self):
        # Deliberate behavior change from the old ratio heuristic: a mostly
        # "Not found"-valued report is now honored like any other report,
        # as long as it's within TTL - no special-casing.
        backend = mock.Mock()
        not_found_report = {k: "Not found" for k in range(5)}
        backend.get.return_value = (not_found_report, iso_at(timedelta(hours=-1)))
        service = ReportCacheService(backend, ttl=timedelta(hours=24))
        self.assertEqual(service.get("DOMAIN", "example.com"), not_found_report)

    def test_default_ttl_is_zero_hours(self):
        service = ReportCacheService(mock.Mock())
        self.assertEqual(service.ttl, timedelta(hours=0))

    def test_set_delegates_to_backend(self):
        backend = mock.Mock()
        service = ReportCacheService(backend)
        report = {"malicious_score": 1}
        service.set("URL", "http://example.com", report)
        backend.set.assert_called_once_with("URL", "http://example.com", report)


if __name__ == "__main__":
    unittest.main()
