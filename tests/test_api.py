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
from app.services.history_service import HistoryService
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
        import importlib
        import app.api.main as main_module

        with mock.patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://localhost:5173"}):
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
        # Reload AFTER the env var patch is reverted, so app.api.main is left
        # in its default state (CORS_ALLOWED_ORIGINS unset -> "*") for any
        # later code that accesses app.api.main.app directly rather than via
        # a frozen `from app.api.main import app` reference taken at this
        # file's own import time (which the other test classes already use,
        # and which this reload doesn't affect either way).
        importlib.reload(main_module)


class HistoryEndpointTests(unittest.TestCase):
    def setUp(self):
        fd, self.history_db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.history_db_path)
        app.state.history = HistoryService(self.history_db_path)
        self.client = TestClient(app)

    def tearDown(self):
        app.state.history.close()
        if os.path.exists(self.history_db_path):
            os.remove(self.history_db_path)

    def test_save_analysis_returns_id_and_created_at(self):
        response = self.client.post("/analyses", json={
            "items": [{"value": "8.8.8.8", "value_type": "ips", "report": {"malicious_score": 0}, "error": None}],
        })
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("id", body)
        self.assertIn("created_at", body)

    def test_save_analysis_with_case_label(self):
        response = self.client.post("/analyses", json={
            "case_label": "incident-1",
            "items": [],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["case_label"], "incident-1")

    def test_list_analyses_returns_saved_summaries(self):
        self.client.post("/analyses", json={"items": [
            {"value": "a", "value_type": "domains", "report": None, "error": "x"},
        ]})
        response = self.client.get("/analyses")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["item_count"], 1)

    def test_get_analysis_returns_full_detail(self):
        items = [{"value": "example.com", "value_type": "domains", "report": {"domain": "example.com"}, "error": None}]
        saved = self.client.post("/analyses", json={"items": items}).json()

        response = self.client.get(f"/analyses/{saved['id']}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"], items)

    def test_get_analysis_returns_404_when_missing(self):
        response = self.client.get("/analyses/does-not-exist")
        self.assertEqual(response.status_code, 404)

    def test_list_analyses_caps_limit_at_100(self):
        response = self.client.get("/analyses?limit=500")
        self.assertEqual(response.status_code, 422)


class MispPushEndpointTests(unittest.TestCase):
    def setUp(self):
        fd, self.history_db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.history_db_path)
        app.state.history = HistoryService(self.history_db_path)
        self.client = TestClient(app)
        self.saved = self.client.post("/analyses", json={"items": [
            {"value": "8.8.8.8", "value_type": "ips", "report": {"ip": "8.8.8.8", "malicious_score": 0}, "error": None},
            {"value": "example.com", "value_type": "domains", "report": None, "error": "Wrong API key"},
        ]}).json()

    def tearDown(self):
        app.state.history.close()
        if os.path.exists(self.history_db_path):
            os.remove(self.history_db_path)

    def test_returns_503_when_misp_is_not_configured(self):
        with mock.patch.dict(os.environ, {"MISPURL": "", "MISPKEY": ""}, clear=False):
            response = self.client.post(f"/analyses/{self.saved['id']}/misp-push", json={})
        self.assertEqual(response.status_code, 503)

    def test_returns_404_when_analysis_does_not_exist(self):
        with mock.patch.dict(os.environ, {"MISPURL": "https://misp.example", "MISPKEY": "key"}):
            response = self.client.post("/analyses/does-not-exist/misp-push", json={})
        self.assertEqual(response.status_code, 404)

    def test_pushes_the_valid_item_and_skips_the_one_with_no_report(self):
        fake_event = mock.Mock(id="42")
        with mock.patch.dict(os.environ, {"MISPURL": "https://misp.example", "MISPKEY": "key"}), \
             mock.patch("app.api.main.ExpandedPyMISP") as mock_misp_cls, \
             mock.patch("app.api.main.get_misp_event", return_value=fake_event) as mock_get_event, \
             mock.patch("app.api.main.submit_misp_objects") as mock_submit:
            response = self.client.post(f"/analyses/{self.saved['id']}/misp-push", json={"case_id": "incident-1"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["event_id"], "42")
        self.assertEqual(body["pushed_count"], 1)
        self.assertEqual(body["skipped_count"], 1)
        mock_misp_cls.assert_called_once_with("https://misp.example", "key", False)
        mock_get_event.assert_called_once()
        mock_submit.assert_called_once()
        # submit_misp_objects's 3rd positional arg is the list of built MISPObjects - exactly 1 (the skipped item never got one built).
        self.assertEqual(len(mock_submit.call_args.args[2]), 1)

    def test_a_successful_push_records_the_event_id_and_case_label_in_history(self):
        fake_event = mock.Mock(id="42")
        with mock.patch.dict(os.environ, {"MISPURL": "https://misp.example", "MISPKEY": "key"}), \
             mock.patch("app.api.main.ExpandedPyMISP"), \
             mock.patch("app.api.main.get_misp_event", return_value=fake_event), \
             mock.patch("app.api.main.submit_misp_objects"):
            self.client.post(f"/analyses/{self.saved['id']}/misp-push", json={"case_id": "incident-1"})

        detail = self.client.get(f"/analyses/{self.saved['id']}").json()
        self.assertEqual(detail["misp_event_id"], "42")
        self.assertEqual(detail["case_label"], "incident-1")

    def test_returns_502_when_misp_connection_fails(self):
        with mock.patch.dict(os.environ, {"MISPURL": "https://misp.example", "MISPKEY": "key"}), \
             mock.patch("app.api.main.ExpandedPyMISP", side_effect=Exception("connection refused")):
            response = self.client.post(f"/analyses/{self.saved['id']}/misp-push", json={})
        self.assertEqual(response.status_code, 502)


if __name__ == "__main__":
    unittest.main()
