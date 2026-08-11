import os
import tempfile
import unittest
from unittest import mock

from app.DataHandler.validator import DataValidator
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.cache_service import ReportCacheService
from app.services.validation_service import ValidationService
from app.worker.settings import WorkerSettings, startup
from app.worker.tasks import analyze_value


class AnalyzeValueJobTests(unittest.IsolatedAsyncioTestCase):
    """Tests the arq job function as a plain async function - no real Redis
    or arq worker process needed. Mocks vt.Client.get_object_async (the
    underlying coroutine get_object()/close() wrap via make_sync()), not the
    sync get_object() wrapper itself - mocking get_object() directly would
    bypass vt-py's real sync/async bridging code entirely and hide the exact
    bug this design works around (calling vt.Client's sync methods directly
    from this coroutine raises "RuntimeError: This event loop is already
    running", verified during planning)."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)
        self.cache = ReportCacheService(SQLiteCacheBackend(self.db_path))
        self.ctx = {
            "validation": ValidationService(DataValidator()),
            "cache": self.cache,
        }

    def tearDown(self):
        self.cache.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    async def test_analyze_value_populates_cache_and_returns_report(self):
        found_report = mock.Mock()
        found_report.last_analysis_stats = {"malicious": 1, "harmless": 50}
        found_report.tags = []
        found_report.whois = ""
        found_report.port = None
        found_report.creation_date = "2020-01-01"
        found_report.reputation = 0
        found_report.last_analysis_results = {}
        found_report.last_dns_records = []
        found_report.last_https_certificate = ""
        found_report.registrar = ""

        with mock.patch("vt.Client.get_object_async", new=mock.AsyncMock(return_value=found_report)):
            report = await analyze_value(self.ctx, "example.com", "domains", "fake-api-key", None)

        self.assertEqual(report["domain"], "example.com")
        cached = self.cache.get("domains", "example.com")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["domain"], "example.com")

    async def test_analyze_value_does_not_raise_from_the_event_loop_collision(self):
        # Regression test for the executor-thread fix: calling vt.Client's
        # real sync get_object()/close() directly from this coroutine
        # (instead of inside a thread pool executor) raises RuntimeError.
        # Mocking get_object_async means the real make_sync()/event-loop
        # bridging code in vt-py actually runs during this test.
        with mock.patch(
            "vt.Client.get_object_async",
            new=mock.AsyncMock(side_effect=Exception("NotFoundError raised by vt-py")),
        ):
            report = await analyze_value(self.ctx, "doesnotexist12345.org", "domains", "fake-api-key", None)

        self.assertEqual(report["domain"], "doesnotexist12345.org")

    async def test_analyze_value_handles_a_plain_string_ip(self):
        # Regression test for the Critical bug found in final review: validate_ip()
        # assumed a tuple, so every plain-string IP (what the API sends) was
        # rejected as invalid before this fix.
        found_report = mock.Mock()
        found_report.last_analysis_stats = {"malicious": 0, "harmless": 60}
        found_report.tags = []
        found_report.as_owner = "Google LLC"
        found_report.continent = "NA"
        found_report.country = "US"
        found_report.network = "8.8.8.0/24"
        found_report.last_https_certificate = ""
        found_report.regional_internet_registry = "ARIN"
        found_report.asn = 15169

        with mock.patch("vt.Client.get_object_async", new=mock.AsyncMock(return_value=found_report)):
            report = await analyze_value(self.ctx, "8.8.8.8", "ips", "fake-api-key", None)

        self.assertEqual(report["ip"], "8.8.8.8")
        cached = self.cache.get("ips", "8.8.8.8")
        self.assertIsNotNone(cached)


class WorkerSettingsTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_populates_ctx_with_validation_and_cache(self):
        ctx = {}
        await startup(ctx)
        try:
            self.assertIsInstance(ctx["validation"], ValidationService)
            self.assertIsInstance(ctx["cache"], ReportCacheService)
        finally:
            ctx["cache"].backend.close()

    def test_worker_settings_registers_analyze_value(self):
        self.assertIn(analyze_value, WorkerSettings.functions)


if __name__ == "__main__":
    unittest.main()
