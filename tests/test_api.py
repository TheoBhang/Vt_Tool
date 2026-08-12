import os
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

from fastapi.testclient import TestClient

from app.DataHandler.validator import DataValidator
from app.api.main import app
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.analysis_service import AnalysisService
from app.services.cache_service import ReportCacheService
from app.services.validation_service import ValidationService


class AnalyzeEndpointTests(unittest.TestCase):
    """TestClient(app) is used WITHOUT the 'with client:' context manager, so
    FastAPI's lifespan (which calls arq.create_pool() against a real Redis)
    never runs - app.state is populated by hand instead, with a mocked redis
    pool. This is deliberate: no test in this suite needs a real Redis."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)
        app.state.analysis = AnalysisService(
            validation=ValidationService(DataValidator()),
            virustotal=None,
            # explicit TTL: these tests seed the cache then expect a hit,
            # which the DEFAULT_TTL_HOURS=0 default would never give them.
            cache=ReportCacheService(SQLiteCacheBackend(self.db_path), ttl=timedelta(hours=24)),
        )
        app.state.redis = mock.Mock()
        app.state.redis.enqueue_job = mock.AsyncMock(
            return_value=mock.Mock(job_id="test-job-id-123")
        )
        self.client = TestClient(app)

    def tearDown(self):
        app.state.analysis.cache.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_cache_hit_returns_report_synchronously_without_enqueueing(self):
        app.state.analysis.cache.set("domains", "example.com", {"domain": "example.com", "malicious_score": 0})

        response = self.client.post("/analyze", json={
            "values": [{"value": "example.com", "value_type": "domains"}],
            "api_key": "fake-api-key",
        })

        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "hit")
        self.assertEqual(results[0]["report"]["domain"], "example.com")
        app.state.redis.enqueue_job.assert_not_called()

    def test_cache_miss_enqueues_a_job_and_returns_its_id(self):
        response = self.client.post("/analyze", json={
            "values": [{"value": "notcached.example.org", "value_type": "domains"}],
            "api_key": "fake-api-key",
        })

        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(results[0]["status"], "queued")
        self.assertEqual(results[0]["job_id"], "test-job-id-123")
        app.state.redis.enqueue_job.assert_called_once_with(
            "analyze_value", "notcached.example.org", "domains", "fake-api-key", None
        )

    def test_invalid_value_is_rejected_without_enqueueing(self):
        response = self.client.post("/analyze", json={
            "values": [{"value": "not a domain!!", "value_type": "domains"}],
            "api_key": "fake-api-key",
        })

        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(results[0]["status"], "invalid")
        app.state.redis.enqueue_job.assert_not_called()

    def test_ip_value_is_valid_and_gets_queued_on_a_cache_miss(self):
        response = self.client.post("/analyze", json={
            "values": [{"value": "8.8.8.8", "value_type": "ips"}],
            "api_key": "fake-api-key",
        })

        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertEqual(results[0]["status"], "queued")
        app.state.redis.enqueue_job.assert_called_once_with(
            "analyze_value", "8.8.8.8", "ips", "fake-api-key", None
        )

    def test_batch_of_mixed_hit_miss_and_invalid_values(self):
        app.state.analysis.cache.set("domains", "cached.example.com", {"domain": "cached.example.com"})

        response = self.client.post("/analyze", json={
            "values": [
                {"value": "cached.example.com", "value_type": "domains"},
                {"value": "notcached.example.org", "value_type": "domains"},
                {"value": "not a domain!!", "value_type": "domains"},
            ],
            "api_key": "fake-api-key",
        })

        results = response.json()
        self.assertEqual([r["status"] for r in results], ["hit", "queued", "invalid"])


class HealthEndpointTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)
        app.state.analysis = AnalysisService(
            validation=ValidationService(DataValidator()),
            virustotal=None,
            cache=ReportCacheService(SQLiteCacheBackend(self.db_path)),
        )
        app.state.redis = mock.Mock()
        app.state.redis.ping = mock.AsyncMock(return_value=True)
        self.client = TestClient(app)

    def tearDown(self):
        app.state.analysis.cache.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_returns_ok_when_cache_and_redis_are_reachable(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_returns_503_when_redis_ping_fails(self):
        app.state.redis.ping = mock.AsyncMock(side_effect=Exception("connection refused"))
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)

    def test_returns_503_when_cache_backend_is_unreachable(self):
        # A closed sqlite3 connection raises ProgrammingError on any further
        # call - a real, verifiable "backend unreachable" condition, not a
        # mocked stand-in for one.
        app.state.analysis.cache.backend.close()
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)


class JobStatusEndpointTests(unittest.TestCase):
    def setUp(self):
        app.state.redis = mock.Mock()
        self.client = TestClient(app)

    def test_complete_successful_job_returns_the_report(self):
        mock_job = mock.Mock()
        mock_job.status = mock.AsyncMock(return_value=__import__("arq").jobs.JobStatus.complete)
        mock_job.result_info = mock.AsyncMock(
            return_value=mock.Mock(success=True, result={"domain": "example.com"})
        )
        with mock.patch("app.api.main.Job", return_value=mock_job):
            response = self.client.get("/jobs/some-job-id")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "complete")
        self.assertEqual(body["report"]["domain"], "example.com")
        self.assertIsNone(body["error"])

    def test_failed_job_returns_the_error_message(self):
        mock_job = mock.Mock()
        mock_job.status = mock.AsyncMock(return_value=__import__("arq").jobs.JobStatus.complete)
        mock_job.result_info = mock.AsyncMock(
            return_value=mock.Mock(success=False, result=Exception("network down"))
        )
        with mock.patch("app.api.main.Job", return_value=mock_job):
            response = self.client.get("/jobs/some-job-id")

        body = response.json()
        self.assertEqual(body["status"], "failed")
        self.assertIsNone(body["report"])
        self.assertEqual(body["error"], "network down")

    def test_queued_job_returns_queued_status(self):
        mock_job = mock.Mock()
        mock_job.status = mock.AsyncMock(return_value=__import__("arq").jobs.JobStatus.queued)
        with mock.patch("app.api.main.Job", return_value=mock_job):
            response = self.client.get("/jobs/some-job-id")

        self.assertEqual(response.json()["status"], "queued")

    def test_unknown_job_returns_404(self):
        mock_job = mock.Mock()
        mock_job.status = mock.AsyncMock(return_value=__import__("arq").jobs.JobStatus.not_found)
        with mock.patch("app.api.main.Job", return_value=mock_job):
            response = self.client.get("/jobs/some-job-id")

        self.assertEqual(response.status_code, 404)


class CorsTests(unittest.TestCase):
    def test_allows_configured_origin(self):
        with mock.patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://localhost:5173"}):
            import importlib
            import app.api.main as main_module
            importlib.reload(main_module)
            client = TestClient(main_module.app)
            response = client.options(
                "/analyze",
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "POST",
                },
            )
            self.assertEqual(
                response.headers.get("access-control-allow-origin"), "http://localhost:5173"
            )
            importlib.reload(main_module)


if __name__ == "__main__":
    unittest.main()
