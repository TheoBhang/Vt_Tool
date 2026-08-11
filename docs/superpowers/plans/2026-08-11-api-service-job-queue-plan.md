# API Service + Job Queue (Sub-project B4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a FastAPI app (`app/api/`) + arq/Redis job queue (`app/worker/`) for vt_tool, built entirely on the existing `AnalysisService`/`ValidationService`/`ReportCacheService` core — cache hits return synchronously, cache misses are queued and fetched by a worker.

**Architecture:** The API and worker are new, additive callers of the unchanged B1/B2/B3 service layer. `ReportCacheService.get()` (already cache-only) powers the sync-hit path directly in the API handler; `AnalysisService.analyze()` (already check-cache-then-fetch-then-cache) powers the worker's job function, unchanged in its own logic but invoked through a thread-pool executor to avoid a real event-loop conflict discovered during planning (see Global Constraints and Task 2).

**Tech Stack:** FastAPI + `uvicorn` (API), `arq` + Redis (job queue). stdlib `unittest`/`unittest.mock`/`unittest.IsolatedAsyncioTestCase` for tests — no pytest, no real Redis needed anywhere in CI.

## Global Constraints

- stdlib `unittest` + `unittest.mock` only — no pytest.
- `ruff check .` must stay clean (rule set: E4, E7, E9, F).
- No MISP submission, no CSV/TXT export via the API — core value analysis only.
- Per-request VirusTotal API key (in the `POST /analyze` body), not a shared server-side key.
- No new service classes — `AnalysisService`/`ValidationService`/`ReportCacheService` are used exactly as they exist today, with one exception documented below (a genuine bug fix to `SQLiteCacheBackend`, not a new class or a change to its public interface).
- No Docker/Compose wiring, no authentication/authorization on the API itself, no per-API-key `vt.Client` pooling, no rate limiting — all explicitly out of scope per the design spec (`docs/superpowers/specs/2026-08-11-api-service-job-queue-design.md`).
- **A real architectural issue was found and must be fixed, not worked around ad hoc**: `vt.Client`'s methods (`get_object`, `close`) are synchronous wrappers that internally drive their own event loop via `asyncio.get_event_loop().run_until_complete(...)` (vt-py's `make_sync()` helper). Calling them directly from an arq job function — which arq already runs inside a live event loop — raises `RuntimeError: This event loop is already running`. This was reproduced directly against the installed `vt-py`/`arq` versions during planning (not assumed). The fix: the worker's job function runs the entire synchronous `AnalysisService.analyze()` call chain inside `asyncio.get_event_loop().run_in_executor(None, ...)` — a fresh executor thread has no event loop of its own running, so vt-py's `make_sync()` can safely create one there. See Task 2.
- **A second, connected issue was found and must be fixed**: running `AnalysisService.analyze()` inside a thread-pool executor means multiple concurrent arq jobs can call `ReportCacheService`/`SQLiteCacheBackend` from different threads simultaneously (arq runs several jobs concurrently within one worker process by default). `SQLiteCacheBackend` held a single `sqlite3.Connection` with no thread-safety — reproduced directly: concurrent `set()`/`get()` calls from a `ThreadPoolExecutor` raised `sqlite3.ProgrammingError` (wrong-thread) and, even after adding `check_same_thread=False`, `sqlite3.InterfaceError: bad parameter or other API misuse` under genuine concurrent access. The fix, also verified directly: `check_same_thread=False` on the connection *and* a `threading.Lock` serializing every `get()`/`set()` call. This is Task 1, and it must land before Task 2, since Task 2's worker code depends on a thread-safe cache. `SQLAlchemyCacheBackend` (from B3) does not have this problem — verified directly that its connection-per-call pattern via SQLAlchemy's engine pool is safe under the same concurrent-executor-thread test, no changes needed there.

---

### Task 1: Thread-safety fix for `SQLiteCacheBackend`

**Files:**
- Modify: `app/cache_backends/sqlite_backend.py`
- Test: `tests/test_sqlite_backend.py`

**Interfaces:**
- Produces: `SQLiteCacheBackend`'s public interface (`get`/`set`/`close`, `db_path` attribute) is completely unchanged — this task only makes the existing connection safe to call from multiple threads. Nothing downstream needs to know this task happened; it's invisible to every caller except that it no longer breaks under concurrent access.
- Consumes: nothing new.

This task stands alone: nothing in the existing codebase calls `SQLiteCacheBackend` from multiple threads today (the CLI is single-threaded, and B1/B2/B3's tests never exercised concurrent access), so this fix cannot change any existing behavior — only add safety for a usage pattern Task 2 is about to introduce.

- [ ] **Step 1: Write the failing test**

Add this test class to `tests/test_sqlite_backend.py` (add `from concurrent.futures import ThreadPoolExecutor` to its imports):

```python
class ThreadSafetyTests(unittest.TestCase):
    """SQLiteCacheBackend.get()/set() must be safe to call concurrently from
    multiple threads - the worker (Task 2) runs each job's cache access inside
    a thread pool executor, and arq runs multiple jobs concurrently within one
    worker process by default."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)
        self.backend = SQLiteCacheBackend(self.db_path)

    def tearDown(self):
        self.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_concurrent_set_and_get_from_multiple_threads_does_not_raise(self):
        errors = []

        def write_and_read(i):
            try:
                self.backend.set("domains", f"value{i % 5}.com", {"malicious_score": i})
                self.backend.get("domains", f"value{i % 5}.com")
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(write_and_read, range(50)))

        self.assertEqual(errors, [])
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_sqlite_backend.ThreadSafetyTests -v`
Expected: FAIL — `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same thread` (or, depending on timing, `sqlite3.InterfaceError: bad parameter or other API misuse`). Either failure confirms the gap is real, not hypothetical — both were reproduced directly against the current code during planning.

- [ ] **Step 3: Fix `SQLiteCacheBackend`**

Replace the entire contents of `app/cache_backends/sqlite_backend.py`:

```python
import json
import sqlite3
import threading
from collections.abc import Mapping
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS cached_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value_type TEXT NOT NULL,
    value TEXT NOT NULL,
    report_json TEXT NOT NULL,
    cached_at TEXT NOT NULL,
    UNIQUE(value_type, value)
);
"""


class SQLiteCacheBackend:
    """SQLite implementation of the report-cache backend: stores an already-shaped
    report dict as a JSON blob, keyed by (value_type, value). No report-shaping
    logic lives here - that is VirusTotalService's job alone.

    check_same_thread=False plus an internal lock make this safe to call from
    multiple threads - needed because the API/worker (sub-project B4) call this
    from a thread-pool executor, potentially concurrently across several jobs."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def get(self, value_type: str, value: str) -> tuple[dict, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT report_json, cached_at FROM cached_reports WHERE value_type = ? AND value = ?",
                (value_type, value),
            ).fetchone()
        if row is None:
            return None
        report_json, cached_at = row
        return json.loads(report_json), cached_at

    def set(self, value_type: str, value: str, report: dict) -> None:
        cached_at = datetime.now(timezone.utc).isoformat()
        report_json = json.dumps(
            report,
            default=lambda o: dict(o) if isinstance(o, Mapping) else str(o),
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO cached_reports (value_type, value, report_json, cached_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(value_type, value) DO UPDATE SET
                    report_json = excluded.report_json,
                    cached_at = excluded.cached_at
                """,
                (value_type, value, report_json, cached_at),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
```

(Only changes from the current file: `import threading` added; `check_same_thread=False` added to `sqlite3.connect(...)`; `self._lock = threading.Lock()` added in `__init__`; `get()`'s query wrapped in `with self._lock:`; `set()`'s `json.dumps(...)` computed before acquiring the lock — pure CPU work, no need to hold it — with only the `execute`/`commit` calls inside `with self._lock:`. `close()` and `SCHEMA` are byte-for-byte unchanged.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `source .venv/bin/activate && python -m unittest tests.test_sqlite_backend -v`
Expected: PASS, all tests including the new `ThreadSafetyTests` (7 total: the pre-existing 6 plus this one new test).

- [ ] **Step 5: Run the full suite and ruff**

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
ruff check .
```

Expected: full suite passes (this fix changes no observable behavior for any existing single-threaded caller), ruff clean.

- [ ] **Step 6: Commit**

```bash
git add app/cache_backends/sqlite_backend.py tests/test_sqlite_backend.py
git commit -m "fix: make SQLiteCacheBackend safe for concurrent multi-threaded access"
```

---

### Task 2: arq worker job function

**Files:**
- Modify: `requirements.txt` (add `arq`)
- Create: `app/worker/__init__.py` (empty)
- Create: `app/worker/tasks.py`
- Create: `app/worker/settings.py`
- Test: `tests/test_worker.py`

**Interfaces:**
- Consumes: `SQLiteCacheBackend`/`SQLAlchemyCacheBackend` (thread-safe as of Task 1), `ReportCacheService(backend, ttl)`, `ValidationService(DataValidator())`, `AnalysisService(validation, virustotal, cache).analyze(value, value_type) -> tuple[dict, bool]`, `VirusTotalService(vt_client)`, `VirusTotalClient(api_key, proxy).init_client()` — all unchanged from B1/B2/B3.
- Produces: `analyze_value(ctx, value, value_type, api_key, proxy) -> dict` (the arq job function, registered as `"analyze_value"` when enqueued by name — Task 3's API handler enqueues it as `redis.enqueue_job("analyze_value", ...)`). `WorkerSettings` class (arq's entrypoint, `functions = [analyze_value]`) for running the worker process (`arq app.worker.settings.WorkerSettings`).

This task is standalone: nothing in the existing codebase or Task 1 calls `analyze_value` yet (that's Task 3's job, via the queue), so this task cannot break anything else.

- [ ] **Step 1: Add the new dependency**

Add `arq` to `requirements.txt` (append as a new line):

```
prettytable
vt-py
python-dotenv
pymisp
rich
validators
tldextract
sqlalchemy
arq
```

Install it:

```bash
source .venv/bin/activate
pip install arq
```

- [ ] **Step 2: Create `app/worker/__init__.py`**

Empty file (matches `app/services/__init__.py`/`app/cache_backends/__init__.py`'s pattern before B2's `CacheBackend` Protocol was added — this one stays empty, the Protocol precedent doesn't apply here).

- [ ] **Step 3: Write the failing tests**

Create `tests/test_worker.py`:

```python
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
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `source .venv/bin/activate && python -m unittest tests.test_worker -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.worker.tasks'` (and `app.worker.settings`), since neither file exists yet.

- [ ] **Step 5: Implement `app/worker/tasks.py`**

```python
import asyncio

from app.VirusTotal.vt_client import VirusTotalClient
from app.services.analysis_service import AnalysisService
from app.services.virustotal_service import VirusTotalService


async def analyze_value(ctx, value, value_type: str, api_key: str, proxy: str | None) -> dict:
    """arq job: analyze one value using the calling request's own VT API key.

    vt-py's Client methods (get_object, close) are synchronous wrappers that
    internally drive their own event loop via asyncio.get_event_loop()
    .run_until_complete() (vt-py's make_sync() helper). Calling them directly
    from this coroutine - which arq already runs inside a live event loop -
    raises "RuntimeError: This event loop is already running" (verified
    directly during planning). Running the whole synchronous
    AnalysisService.analyze() call chain inside a thread pool executor
    sidesteps this: a fresh executor thread has no event loop of its own
    running, so make_sync() can safely create one there.

    ctx["validation"]/ctx["cache"] are shared across every job in this worker
    process (populated once at worker startup, see settings.py) - only the
    VirusTotalService/vt.Client differ per job, scoped to this job's api_key.
    """

    def _run_analysis() -> dict:
        client = VirusTotalClient(api_key, proxy).init_client()
        try:
            analysis = AnalysisService(
                validation=ctx["validation"],
                virustotal=VirusTotalService(client),
                cache=ctx["cache"],
            )
            report, _ = analysis.analyze(value, value_type)
            return report
        finally:
            client.close()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_analysis)
```

- [ ] **Step 6: Implement `app/worker/settings.py`**

```python
import os
from datetime import timedelta

from arq.connections import RedisSettings

from app.DataHandler.validator import DataValidator
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.cache_service import DEFAULT_TTL_HOURS, ReportCacheService
from app.services.validation_service import ValidationService
from app.worker.tasks import analyze_value

DATABASE_FILE = "vttools.sqlite"


async def startup(ctx: dict) -> None:
    """Builds the shared ValidationService/ReportCacheService once per worker
    process - reads VT_CACHE_DB_URL/VT_CACHE_TTL_HOURS the same way init.py
    does for the CLI, so the worker's cache configuration always matches."""
    db_url = os.getenv("VT_CACHE_DB_URL")
    cache_backend = SQLAlchemyCacheBackend(db_url) if db_url else SQLiteCacheBackend(DATABASE_FILE)
    cache_ttl = timedelta(hours=float(os.getenv("VT_CACHE_TTL_HOURS", str(DEFAULT_TTL_HOURS))))
    ctx["validation"] = ValidationService(DataValidator())
    ctx["cache"] = ReportCacheService(cache_backend, ttl=cache_ttl)


async def shutdown(ctx: dict) -> None:
    ctx["cache"].backend.close()


class WorkerSettings:
    functions = [analyze_value]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379"))
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_worker -v`
Expected: PASS, 4/4 (2 in `AnalyzeValueJobTests`, 2 in `WorkerSettingsTests`).

- [ ] **Step 8: Run the full suite and ruff**

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
ruff check .
```

Expected: full suite passes, ruff clean.

- [ ] **Step 9: Commit**

```bash
git add requirements.txt app/worker/__init__.py app/worker/tasks.py app/worker/settings.py tests/test_worker.py
git commit -m "feat: add arq worker job function for async value analysis"
```

---

### Task 3: FastAPI app

**Files:**
- Modify: `requirements.txt` (add `fastapi`, `uvicorn`)
- Create: `app/api/__init__.py` (empty)
- Create: `app/api/main.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `ValidationService.classify(value, value_type) -> str | None`, `ReportCacheService.get(value_type, value) -> dict | None`, `UNSUPPORTED_VALUE_TYPES` (from `app.services.analysis_service`), `DEFAULT_TTL_HOURS` (from `app.services.cache_service`) — all unchanged. `arq.create_pool`, `arq.connections.RedisSettings`, `arq.jobs.Job`, `arq.jobs.JobStatus` (Task 2's `analyze_value` job is enqueued by its registered name `"analyze_value"`, not imported directly — the API and worker only share the job *name* as their contract, exactly as arq is designed to be used, since they may run as separate processes/deployments).
- Produces: `app` (the FastAPI instance), `POST /analyze`, `GET /jobs/{job_id}`.

Scope note not explicitly in the design doc, decided here: the API's request body only accepts plain string `value`s, not the CLI's `(ip, port)` tuple form (which comes from `ValueReader` parsing specially-formatted file lines) — a JSON API has no equivalent ambiguity to resolve, and nothing in the design asked for port-tuple support. `ReportCacheService`/`ValidationService`'s calls in this task only ever receive plain strings.

- [ ] **Step 1: Add the new dependencies**

Add `fastapi` and `uvicorn` to `requirements.txt` (append as new lines):

```
prettytable
vt-py
python-dotenv
pymisp
rich
validators
tldextract
sqlalchemy
arq
fastapi
uvicorn
```

Install them:

```bash
source .venv/bin/activate
pip install fastapi uvicorn httpx
```

(`httpx` is required by FastAPI's `TestClient`, used only in tests — not added to `requirements.txt` since it's not a runtime dependency of the app itself, only installed locally for this task's test run. If your test environment needs it declared somewhere, note it as a dev-only install; this plan doesn't create a separate dev-requirements file since none exists in this repo today.)

- [ ] **Step 2: Create `app/api/__init__.py`**

Empty file.

- [ ] **Step 3: Write the failing tests**

Create `tests/test_api.py`:

```python
import os
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from app.DataHandler.validator import DataValidator
from app.api.main import app
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
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
        app.state.validation = ValidationService(DataValidator())
        app.state.cache = ReportCacheService(SQLiteCacheBackend(self.db_path))
        app.state.redis = mock.Mock()
        app.state.redis.enqueue_job = mock.AsyncMock(
            return_value=mock.Mock(job_id="test-job-id-123")
        )
        self.client = TestClient(app)

    def tearDown(self):
        app.state.cache.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_cache_hit_returns_report_synchronously_without_enqueueing(self):
        app.state.cache.set("domains", "example.com", {"domain": "example.com", "malicious_score": 0})

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

    def test_batch_of_mixed_hit_miss_and_invalid_values(self):
        app.state.cache.set("domains", "cached.example.com", {"domain": "cached.example.com"})

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


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `source .venv/bin/activate && python -m unittest tests.test_api -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.api.main'`, since the file doesn't exist yet.

- [ ] **Step 5: Implement `app/api/main.py`**

```python
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Literal

from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.DataHandler.validator import DataValidator
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.analysis_service import UNSUPPORTED_VALUE_TYPES
from app.services.cache_service import DEFAULT_TTL_HOURS, ReportCacheService
from app.services.validation_service import ValidationService

DATABASE_FILE = "vttools.sqlite"


def _build_cache() -> ReportCacheService:
    db_url = os.getenv("VT_CACHE_DB_URL")
    cache_backend = SQLAlchemyCacheBackend(db_url) if db_url else SQLiteCacheBackend(DATABASE_FILE)
    cache_ttl = timedelta(hours=float(os.getenv("VT_CACHE_TTL_HOURS", str(DEFAULT_TTL_HOURS))))
    return ReportCacheService(cache_backend, ttl=cache_ttl)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.validation = ValidationService(DataValidator())
    app.state.cache = _build_cache()
    app.state.redis = await create_pool(
        RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379"))
    )
    yield
    app.state.cache.backend.close()
    await app.state.redis.aclose()


app = FastAPI(lifespan=lifespan)


class AnalyzeItem(BaseModel):
    value: str
    value_type: Literal["ips", "domains", "urls", "hashes"]


class AnalyzeRequest(BaseModel):
    values: list[AnalyzeItem]
    api_key: str
    proxy: str | None = None


@app.post("/analyze")
async def analyze(payload: AnalyzeRequest, request: Request):
    validation: ValidationService = request.app.state.validation
    cache: ReportCacheService = request.app.state.cache
    redis = request.app.state.redis

    results = []
    for item in payload.values:
        cached = cache.get(item.value_type, item.value)
        if cached is not None:
            results.append({"status": "hit", "report": cached})
            continue

        classification = validation.classify(item.value, item.value_type)
        if not classification or classification in UNSUPPORTED_VALUE_TYPES:
            results.append({
                "status": "invalid",
                "error": f"Unsupported or invalid {item.value_type[:-1]}: {item.value}",
            })
            continue

        job = await redis.enqueue_job(
            "analyze_value", item.value, item.value_type, payload.api_key, payload.proxy
        )
        results.append({"status": "queued", "job_id": job.job_id})

    return results


@app.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request):
    redis = request.app.state.redis
    job = Job(job_id, redis=redis)
    status = await job.status()

    if status == JobStatus.not_found:
        raise HTTPException(status_code=404, detail="Job not found")
    if status in (JobStatus.deferred, JobStatus.queued):
        return {"status": "queued", "report": None, "error": None}
    if status == JobStatus.in_progress:
        return {"status": "in_progress", "report": None, "error": None}

    info = await job.result_info()
    if info.success:
        return {"status": "complete", "report": info.result, "error": None}
    return {"status": "failed", "report": None, "error": str(info.result)}
```

Note on the cache-check-before-validate ordering: this deliberately mirrors `AnalysisService.analyze()`'s own order (cache check first, `classify()` only reached on a miss) rather than validating first — matching B1's documented reasoning that a cache hit should never pay for a classification call. An invalid value still never reaches the queue either way; only the order relative to the cache check changes, and matching `analyze()`'s real behavior is more consistent than inventing a different order for the API.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_api -v`
Expected: PASS, 8/8 (4 in `AnalyzeEndpointTests`, 4 in `JobStatusEndpointTests`).

- [ ] **Step 7: Run the full suite and ruff**

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
ruff check .
```

Expected: full suite passes, ruff clean.

- [ ] **Step 8: Commit**

```bash
git add requirements.txt app/api/__init__.py app/api/main.py tests/test_api.py
git commit -m "feat: add FastAPI app with sync-hit/async-miss analyze endpoint"
```

---

### Task 4: Full verification pass

**Files:** none (verification only)

- [ ] **Step 1: Full lint + test run from a clean shell**

```bash
cd <worktree>
source .venv/bin/activate
ruff check .
python -m unittest discover -s tests -t . -v
```

Expected: ruff clean, full suite green. Record the final test count (expect the pre-B4 count of 157 plus 1 from Task 1, plus 4 from Task 2, plus 8 from Task 3 — 170 total).

- [ ] **Step 2: CLI behavior spot-check — confirm `--help` is unchanged**

No task in this plan touches `vt_tools.py`. Confirm that's actually true:

```bash
git log --oneline -- vt_tools.py | head -5
```

Expected: the most recent commit touching `vt_tools.py` predates this plan's first commit. Then run `python vt_tools.py --help` once and visually confirm the full argument list is intact.

- [ ] **Step 3: Manual sanity check — confirm the FastAPI app actually starts and serves requests**

```bash
source .venv/bin/activate
python3 -c "
from fastapi.testclient import TestClient
from unittest import mock
from app.DataHandler.validator import DataValidator
from app.api.main import app
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.cache_service import ReportCacheService
from app.services.validation_service import ValidationService

app.state.validation = ValidationService(DataValidator())
app.state.cache = ReportCacheService(SQLiteCacheBackend(':memory:'))
app.state.redis = mock.Mock()
app.state.redis.enqueue_job = mock.AsyncMock(return_value=mock.Mock(job_id='smoke-test-job'))

client = TestClient(app)
r = client.post('/analyze', json={'values': [{'value': 'example.com', 'value_type': 'domains'}], 'api_key': 'fake-key'})
assert r.status_code == 200, r.text
assert r.json()[0]['status'] == 'queued', r.json()
print('POST /analyze: OK, got', r.json())

r2 = client.get('/jobs/smoke-test-job')
print('GET /jobs/{id}: status code', r2.status_code, '(mocked Job class not patched here, this just confirms the route exists and doesn' + chr(39) + 't 500 on a basic call path if redis were real - not a full assertion)')
"
```

Expected: the `POST /analyze` assertions pass and print the queued-job response. (The `GET /jobs/{id}` call in this smoke test isn't asserted strictly, since it would need `Job` mocked or a real Redis to behave meaningfully — Task 3's own test suite already covers that endpoint's logic thoroughly; this step is about confirming the app object imports and serves a real request end-to-end, which the fully-mocked `Job` unit tests don't by themselves prove.)

- [ ] **Step 4: Manual sanity check — confirm the worker job function still works standalone (no arq process needed)**

```bash
source .venv/bin/activate
python3 -c "
import asyncio
from unittest import mock
from app.DataHandler.validator import DataValidator
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.cache_service import ReportCacheService
from app.services.validation_service import ValidationService
from app.worker.tasks import analyze_value

cache = ReportCacheService(SQLiteCacheBackend(':memory:'))
ctx = {'validation': ValidationService(DataValidator()), 'cache': cache}

async def main():
    found_report = mock.Mock()
    found_report.last_analysis_stats = {'malicious': 0, 'harmless': 60}
    found_report.tags = []
    found_report.whois = ''
    found_report.port = None
    found_report.creation_date = '2020-01-01'
    found_report.reputation = 0
    found_report.last_analysis_results = {}
    found_report.last_dns_records = []
    found_report.last_https_certificate = ''
    found_report.registrar = ''

    with mock.patch('vt.Client.get_object_async', new=mock.AsyncMock(return_value=found_report)):
        report = await analyze_value(ctx, 'example.com', 'domains', 'fake-api-key', None)
    print('worker job result:', report['domain'], report['malicious_score'])
    assert cache.get('domains', 'example.com') is not None
    print('cache populated: OK')

asyncio.run(main())
cache.backend.close()
"
```

Expected: both print statements execute with no exception — proves the worker's job function works end-to-end (including the real executor/event-loop bridging) without needing a real arq process or Redis.

- [ ] **Step 5: Confirm no stray files, clean working tree**

```bash
git status --short
```

Expected: empty (the manual smoke tests above use `:memory:` SQLite URLs, no files written to disk).

- [ ] **Step 6: Report to the user**

No commit for this step. Summarize: final test count, confirmation `vt_tools.py --help` is unchanged, confirmation both manual end-to-end smoke tests passed (API request handling, worker job execution including the real event-loop/executor interaction), and that this closes out sub-project B4. Note explicitly that Docker Compose wiring for the API and worker as deployable services remains its own future sub-project, and that running this for real requires a live Redis instance (`REDIS_URL` env var, defaulting to `redis://localhost:6379`) and starting two processes: `uvicorn app.api.main:app` and `arq app.worker.settings.WorkerSettings`.

---

## Self-Review

**Spec coverage:** Sync-on-hit/async-on-miss (`POST /analyze`'s cache-check-then-enqueue logic, Task 3) ✅. arq + Redis job queue (Task 2) ✅. Core analysis only, no MISP/CSV (no task touches `MispService` or file export) ✅. Per-request API key (`AnalyzeRequest.api_key`, threaded through to the job, Task 3) ✅. No new service classes (Tasks 2/3 only call existing `AnalysisService`/`ValidationService`/`ReportCacheService`; the one change to existing code, `SQLiteCacheBackend`'s thread-safety fix, changes no public interface) ✅. No real Redis needed in CI (every test mocks the arq pool or the `Job` class; Task 4's manual smoke tests use `:memory:` SQLite and mocked Redis too) ✅.

**Placeholder scan:** no TBD/TODO; every step shows complete, directly-verified code.

**Two real architectural bugs caught and fixed during planning, not left for an implementer or reviewer to discover:**

1. Calling `vt.Client`'s synchronous `get_object()`/`close()` directly from the arq job coroutine raises `RuntimeError: This event loop is already running` — reproduced directly against the installed `arq`==0.28.0/`vt-py` versions with a minimal repro script before writing any task code, then verified the `run_in_executor` fix resolves it (also directly, including a successful mocked API-error round-trip through the real `make_sync()` bridging code). Task 2's `analyze_value` ships the fixed version; `tests/test_worker.py`'s `test_analyze_value_does_not_raise_from_the_event_loop_collision` is a genuine regression test for this, verified by literally reproducing the bug's failure mode against an unfixed version of the same call pattern before writing the test, and confirming the mock boundary (`get_object_async`, not `get_object`) is the one that actually exercises the vulnerable code path — mocking `get_object` itself would have hidden the bug entirely.
2. The `run_in_executor` fix for (1) introduces concurrent multi-threaded access to `SQLiteCacheBackend` (arq runs several jobs concurrently per worker process by default), which the existing B1-era implementation was never built to survive — reproduced directly (`sqlite3.ProgrammingError`, then `sqlite3.InterfaceError` even after a partial fix) before writing Task 1, confirmed the full fix (`check_same_thread=False` + `threading.Lock`) resolves it under real concurrent `ThreadPoolExecutor` load, and separately confirmed `SQLAlchemyCacheBackend` (B3) does NOT have this problem (its connection-per-call pattern via SQLAlchemy's engine pool is safe under the identical concurrent test) — so only Task 1's fix was needed, not a matching change to the SQLAlchemy backend.

**Type/signature consistency:** `analyze_value(ctx, value, value_type, api_key, proxy) -> dict` (Task 2) is enqueued by Task 3 as `redis.enqueue_job("analyze_value", item.value, item.value_type, payload.api_key, payload.proxy)` — argument order and count match. `ctx["validation"]`/`ctx["cache"]` (populated by Task 2's `startup()`) are read with the same keys inside `analyze_value`. `ReportCacheService(backend, ttl=...)` and `DEFAULT_TTL_HOURS` (from B2, `app/services/cache_service.py`) are used identically in both `app/worker/settings.py` (Task 2) and `app/api/main.py` (Task 3) — same env-var-reading pattern as `init.py`'s, so all three entrypoints (CLI, API, worker) configure their cache identically from the same environment.

**One thing intentionally left inconsistent with `init.py`, noted here rather than silently diverging:** `init.py`'s cache construction lives inside `Initializator.__init__`, read fresh per CLI invocation. The API's `_build_cache()`/worker's `startup()` each build their own cache instance once per process lifetime (at FastAPI/arq startup), not per-request/per-job — this is correct and deliberate for a long-running server process (rebuilding the cache backend per request would mean constructing a new SQLite connection or SQLAlchemy engine on every single API call, wasteful and unnecessary), but it does mean the API/worker won't pick up a changed `VT_CACHE_DB_URL`/`VT_CACHE_TTL_HOURS` without a process restart, unlike the CLI which re-reads the environment on every invocation. This is the correct tradeoff for a server process, not a bug.
