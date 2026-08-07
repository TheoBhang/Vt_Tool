# TTL-Based Cache Expiry (Sub-project B2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `ReportCacheService`'s empty-field-ratio cache-miss heuristic with real TTL-based expiry, and formalize `CacheBackend` as an actual `typing.Protocol`.

**Architecture:** `CacheBackend.get()` changes to return `(report, cached_at)` instead of just `report`; `ReportCacheService` gains the TTL comparison as its policy (replacing the ratio heuristic it deletes), while `SQLiteCacheBackend` stays a dumb store that only fetches/writes raw data. `AnalysisService` and everything above it is untouched.

**Tech Stack:** Python stdlib only — `datetime`/`timedelta` for TTL math, `typing.Protocol` for the backend contract. No new dependencies.

## Global Constraints

- stdlib `unittest` + `unittest.mock` only — no pytest.
- `ruff check .` must stay clean (rule set: E4, E7, E9, F).
- No Postgres backend, no per-value-type TTL, no active/scheduled cleanup job, no `CacheError` wiring — all explicitly out of scope per the design spec (`docs/superpowers/specs/2026-08-07-cache-ttl-design.md`).
- The empty-field-ratio heuristic and its `threshold` parameter are deleted outright, not deprecated or kept alongside TTL.
- A cached "not found" report is a real cache hit within TTL, same as any other report — no special-casing.
- TTL policy lives in `ReportCacheService`, never in a `CacheBackend` implementation.
- No `vt_tools.py`/CLI-surface changes — `--help` output must be unchanged when this plan is done.
- `cached_at` already exists as a column in `SQLiteCacheBackend`'s schema (added in B1) — no schema migration needed.

---

### Task 1: `CacheBackend` Protocol + TTL-based `ReportCacheService`

**Files:**
- Create: `app/cache_backends/__init__.py` (currently empty)
- Modify: `app/cache_backends/sqlite_backend.py`
- Modify: `app/services/cache_service.py`
- Test: `tests/test_sqlite_backend.py`
- Test: `tests/test_cache_service.py`

**Interfaces:**
- Produces: `CacheBackend` Protocol (`get(value_type: str, value: str) -> tuple[dict, str] | None`, `set(value_type: str, value: str, report: dict) -> None`). `SQLiteCacheBackend.get()` now returns `tuple[dict, str] | None` (report, `cached_at` ISO string) instead of `dict | None`. `ReportCacheService(backend, ttl: timedelta = timedelta(hours=24))` — `ttl` is keyword-friendly with a sensible default so call sites that don't care about a specific TTL don't need to specify one; `init.py` (Task 2) will pass an explicit value from the environment.
- Consumes: nothing new — this task only touches the cache layer.

This task changes the backend and its sole consumer (`ReportCacheService`) together, in one task, specifically so the full test suite stays green at every commit in this plan — splitting them across two tasks would leave `ReportCacheService` broken (calling backend methods that no longer return what it expects) in between.

- [ ] **Step 1: Write the failing backend tests (new tuple return shape)**

Replace the contents of `tests/test_sqlite_backend.py` with:

```python
import os
import sqlite3
import tempfile
import unittest

import vt

from app.cache_backends.sqlite_backend import SQLiteCacheBackend


class SQLiteCacheBackendTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)  # backend creates it fresh
        self.backend = SQLiteCacheBackend(self.db_path)

    def tearDown(self):
        self.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_get_returns_none_when_absent(self):
        self.assertIsNone(self.backend.get("DOMAIN", "example.com"))

    def test_set_then_get_round_trips_the_report_and_cached_at(self):
        report = {"domain": "example.com", "malicious_score": 3, "tags": "phishing"}
        self.backend.set("DOMAIN", "example.com", report)
        result_report, cached_at = self.backend.get("DOMAIN", "example.com")
        self.assertEqual(result_report, report)
        self.assertIsInstance(cached_at, str)
        self.assertNotEqual(cached_at, "")

    def test_set_twice_updates_instead_of_duplicating(self):
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 1})
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 9})
        report, _ = self.backend.get("DOMAIN", "example.com")
        self.assertEqual(report, {"malicious_score": 9})

        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM cached_reports WHERE value_type = ? AND value = ?",
            ("DOMAIN", "example.com"),
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_set_twice_refreshes_cached_at(self):
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 1})
        _, first_cached_at = self.backend.get("DOMAIN", "example.com")
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 9})
        _, second_cached_at = self.backend.get("DOMAIN", "example.com")
        self.assertGreaterEqual(second_cached_at, first_cached_at)

    def test_same_value_different_type_is_a_separate_entry(self):
        self.backend.set("DOMAIN", "8.8.8.8", {"kind": "domain-shaped"})
        self.backend.set("PUBLIC IPV4", "8.8.8.8", {"kind": "ip-shaped"})
        domain_report, _ = self.backend.get("DOMAIN", "8.8.8.8")
        ip_report, _ = self.backend.get("PUBLIC IPV4", "8.8.8.8")
        self.assertEqual(domain_report, {"kind": "domain-shaped"})
        self.assertEqual(ip_report, {"kind": "ip-shaped"})


class SetWithRealVtObjectAttributesTests(unittest.TestCase):
    """A real vt.Object's attributes include datetime (any *_date field) and
    WhistleBlowerDict (any nested-dict field, a collections.UserDict, not a
    dict subclass) - neither is JSON-serializable by default. Regression
    test for the bug this caused: an uncaught TypeError on the first
    cache write for any found domain/IP/URL value."""

    def test_set_does_not_raise_on_datetime_and_whistleblower_dict_fields(self):
        backend = SQLiteCacheBackend(":memory:")
        vt_object = vt.Object.from_dict({
            "type": "domain",
            "id": "example.com",
            "attributes": {
                "creation_date": 1000000000,  # becomes a real datetime on read
                "last_https_certificate": {"thumbprint": "abc123"},  # becomes a WhistleBlowerDict
            },
        })
        report = {
            "domain": "example.com",
            "creation_date": vt_object.creation_date,
            "https_certificate": vt_object.last_https_certificate,
        }

        backend.set("domains", "example.com", report)
        result, cached_at = backend.get("domains", "example.com")

        self.assertEqual(result["domain"], "example.com")
        self.assertIsInstance(result["creation_date"], str)
        self.assertEqual(result["https_certificate"], {"thumbprint": "abc123"})
        self.assertIsInstance(cached_at, str)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the backend tests to verify they fail**

Run: `source .venv/bin/activate && python -m unittest tests.test_sqlite_backend -v`
Expected: FAIL — `TypeError` or assertion errors on tests that unpack `self.backend.get(...)` as a 2-tuple, since the current `get()` still returns a plain dict/`None`.

- [ ] **Step 3: Create the `CacheBackend` Protocol**

Write `app/cache_backends/__init__.py` (currently empty):

```python
from typing import Protocol


class CacheBackend(Protocol):
    """Contract a report-cache storage backend must implement. ReportCacheService
    depends on this, not on any concrete backend - SQLiteCacheBackend is the only
    implementation today, but a future backend just needs to match this shape.
    No report-shaping or freshness-policy logic belongs in an implementation of
    this Protocol; that's ReportCacheService's job."""

    def get(self, value_type: str, value: str) -> tuple[dict, str] | None:
        """Return (report, cached_at_iso_string) for an existing entry, or
        None if nothing has ever been cached for this (value_type, value)."""
        ...

    def set(self, value_type: str, value: str, report: dict) -> None:
        """Store report, stamping/refreshing its cached_at to now."""
        ...
```

- [ ] **Step 4: Update `SQLiteCacheBackend.get()` to return the tuple**

In `app/cache_backends/sqlite_backend.py`, replace the `get` method:

```python
    def get(self, value_type: str, value: str) -> tuple[dict, str] | None:
        row = self._conn.execute(
            "SELECT report_json, cached_at FROM cached_reports WHERE value_type = ? AND value = ?",
            (value_type, value),
        ).fetchone()
        if row is None:
            return None
        report_json, cached_at = row
        return json.loads(report_json), cached_at
```

(`set()`, `SCHEMA`, and `close()` are unchanged — leave them exactly as they are.)

- [ ] **Step 5: Run the backend tests to verify they pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_sqlite_backend -v`
Expected: PASS, 6/6 (5 in `SQLiteCacheBackendTests`, 1 in `SetWithRealVtObjectAttributesTests`).

- [ ] **Step 6: Write the failing service tests (TTL replaces the ratio heuristic)**

Replace the entire contents of `tests/test_cache_service.py` with:

```python
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

    def test_default_ttl_is_24_hours(self):
        backend = mock.Mock()
        report = {"a": 1}
        backend.get.return_value = (report, iso_at(timedelta(hours=-23)))
        service = ReportCacheService(backend)
        self.assertEqual(service.get("DOMAIN", "example.com"), report)

    def test_set_delegates_to_backend(self):
        backend = mock.Mock()
        service = ReportCacheService(backend)
        report = {"malicious_score": 1}
        service.set("URL", "http://example.com", report)
        backend.set.assert_called_once_with("URL", "http://example.com", report)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 7: Run the service tests to verify they fail**

Run: `source .venv/bin/activate && python -m unittest tests.test_cache_service -v`
Expected: FAIL — `ReportCacheService.get()` still expects `backend.get()` to return a plain dict, so unpacking `(report, cached_at) = backend.get(...)`'s mocked tuple return either raises inside the old code (it doesn't unpack at all currently, so the mocked tuple gets treated as the report itself, e.g. `not_found_count / len(report)` runs against a 2-tuple's `len()` returning 2) or produces wrong values — confirm the failures are for this reason (wrong behavior / wrong shape), not a typo, before proceeding.

- [ ] **Step 8: Implement TTL-based `ReportCacheService`**

Replace the entire contents of `app/services/cache_service.py`:

```python
from datetime import datetime, timedelta, timezone


class ReportCacheService:
    """A pure cache in front of a CacheBackend: no report-shaping logic lives
    here, only the policy of when a cached entry counts as a real hit - a TTL
    comparison against the backend's cached_at timestamp."""

    def __init__(self, backend, ttl: timedelta = timedelta(hours=24)):
        self.backend = backend
        self.ttl = ttl

    def get(self, value_type: str, value: str) -> dict | None:
        result = self.backend.get(value_type, value)
        if result is None:
            return None
        report, cached_at = result
        age = datetime.now(timezone.utc) - datetime.fromisoformat(cached_at)
        if age > self.ttl:
            return None
        return report

    def set(self, value_type: str, value: str, report: dict) -> None:
        self.backend.set(value_type, value, report)
```

- [ ] **Step 9: Run the service tests to verify they pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_cache_service -v`
Expected: PASS, 6/6.

- [ ] **Step 10: Run the full suite and ruff**

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
ruff check .
```

Expected: full suite passes (some other test files construct `ReportCacheService`/`SQLiteCacheBackend` directly and may need no changes since they only call `.set()`, or construct via `init.py` which Task 2 hasn't touched yet — if anything else fails, it's most likely `tests/test_init.py`'s `test_analysis_service_cache_uses_the_configured_database_file`, which only reads `.backend.db_path` and should be unaffected; confirm nothing unexpected broke). `ruff check .` clean.

- [ ] **Step 11: Commit**

```bash
git add app/cache_backends/__init__.py app/cache_backends/sqlite_backend.py app/services/cache_service.py tests/test_sqlite_backend.py tests/test_cache_service.py
git commit -m "feat: TTL-based cache expiry replaces the ratio heuristic"
```

---

### Task 2: Wire configurable TTL into `init.py`

**Files:**
- Modify: `init.py`
- Test: `tests/test_init.py`

**Interfaces:**
- Consumes: `ReportCacheService(backend, ttl: timedelta = timedelta(hours=24))` (Task 1).
- Produces: `Initializator` now reads `VT_CACHE_TTL_HOURS` from the environment (default `"24"`) on every construction and passes it as `ttl` to `ReportCacheService`. Read per-instantiation (inside `__init__`), not once at module import time, so it stays testable with `unittest.mock.patch.dict(os.environ, ...)` around a fresh `Initializator(...)` call — a module-level constant computed at import time would not pick up a per-test env var override, since `init.py` is typically already imported by the time a test runs.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_init.py` (add `import os` and `from datetime import timedelta` and `from unittest import mock` to the top of the file, alongside the existing imports):

```python
import os
from datetime import timedelta
from unittest import mock

import unittest

from init import Initializator
from app.services.analysis_service import AnalysisService
from app.services.misp_service import MispService
from app.FileHandler.output_to_file import OutputHandler
```

Add these two test methods to `InitializatorTests`:

```python
    def test_analysis_service_cache_uses_the_default_ttl(self):
        self.assertEqual(self.init.analysis.cache.ttl, timedelta(hours=24))

    def test_analysis_service_cache_ttl_is_configurable_via_env_var(self):
        with mock.patch.dict(os.environ, {"VT_CACHE_TTL_HOURS": "1"}):
            init = Initializator("fake-api-key", proxy=None, case_num="000001")
            try:
                self.assertEqual(init.analysis.cache.ttl, timedelta(hours=1))
            finally:
                init.client.close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `source .venv/bin/activate && python -m unittest tests.test_init -v`
Expected: FAIL — `AttributeError` or `AssertionError` on both new tests, since `ReportCacheService` is currently constructed with no `ttl` argument (defaulting to `timedelta(hours=24)` per Task 1 — so the FIRST new test may actually already pass by coincidence of the default; the SECOND test must fail, since nothing in `init.py` reads `VT_CACHE_TTL_HOURS` yet). Confirm the second test fails for the right reason (the env var override has no effect yet) before proceeding.

- [ ] **Step 3: Wire the env var into `Initializator.__init__`**

In `init.py`, add `import os` and `from datetime import timedelta` to the top imports, and change the `__init__` body:

```python
import os
from datetime import timedelta

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from app.VirusTotal.vt_client import VirusTotalClient
from app.DataHandler.validator import DataValidator
from app.FileHandler.output_to_file import OutputHandler
from app.services.validation_service import ValidationService
from app.services.virustotal_service import VirusTotalService
from app.services.cache_service import ReportCacheService
from app.services.analysis_service import AnalysisService
from app.services.misp_service import MispService
from app.cache_backends.sqlite_backend import SQLiteCacheBackend

console = Console()

DATABASE_FILE = "vttools.sqlite"


class Initializator:
    """
    Wires up the service factory for a single vt_tool run.

    Attributes:
        api_key (str): VirusTotal API key.
        proxy (str, optional): Proxy for API requests.
        case_num (str, optional): Case identifier for logging/output.
        client (vt.Client): VirusTotal API client instance.
        analysis (AnalysisService): The core "analyze one value" orchestrator.
        misp (MispService): MISP object-building service.
        output (OutputHandler): Manages output file handling.
    """

    def __init__(self, api_key: str, proxy: str = None, case_num: str = None):
        self.api_key = api_key
        self.proxy = proxy
        self.case_num = case_num

        self.client = self._init_client()
        cache_backend = SQLiteCacheBackend(DATABASE_FILE)
        cache_ttl = timedelta(hours=float(os.getenv("VT_CACHE_TTL_HOURS", "24")))
        self.analysis = AnalysisService(
            validation=ValidationService(DataValidator()),
            virustotal=VirusTotalService(self.client),
            cache=ReportCacheService(cache_backend, ttl=cache_ttl),
        )
        self.misp = MispService()
        self.output = OutputHandler(self.case_num)

        self._display_info(self.client, self.analysis, self.misp, self.output)
```

(`_init_client` and `_display_info` are unchanged — leave them exactly as they are.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_init -v`
Expected: PASS, 6/6.

- [ ] **Step 5: Run the full suite and ruff**

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
ruff check .
```

Expected: full suite passes, ruff clean.

- [ ] **Step 6: Commit**

```bash
git add init.py tests/test_init.py
git commit -m "feat: make cache TTL configurable via VT_CACHE_TTL_HOURS"
```

---

### Task 3: Full verification pass

**Files:** none (verification only)

- [ ] **Step 1: Full lint + test run from a clean shell**

```bash
cd /home/forensics/vt_tool
source .venv/bin/activate
ruff check .
python -m unittest discover -s tests -t . -v
```

Expected: ruff clean, full suite green. Record the final test count for the report (expect roughly the pre-B2 count, since this plan mostly rewrites existing tests rather than adding many new ones — a handful net new from the TTL-boundary and env-var-override tests).

- [ ] **Step 2: CLI behavior spot-check — confirm `--help` is unchanged**

No task in this plan touches `vt_tools.py`. Confirm that's actually true (catches an accidental unrelated edit, not a re-verification of B1's already-proven `--help` parity):

```bash
git log --oneline -- vt_tools.py | head -5
```

Expected: the most recent commit touching `vt_tools.py` predates this plan's first commit (Task 1's `feat: TTL-based cache expiry replaces the ratio heuristic`) — i.e., nothing in this plan appears in that list. Then run `python vt_tools.py --help` once and visually confirm the full argument list is intact.

- [ ] **Step 3: Manual sanity check — confirm TTL actually expires a cache entry end-to-end**

```bash
rm -f /tmp/b2_smoke.sqlite
python3 -c "
from datetime import timedelta
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.services.cache_service import ReportCacheService

backend = SQLiteCacheBackend('/tmp/b2_smoke.sqlite')
service = ReportCacheService(backend, ttl=timedelta(seconds=1))
service.set('domains', 'example.com', {'domain': 'example.com', 'malicious_score': 0})

# Immediately after set(), within TTL: should be a hit.
assert service.get('domains', 'example.com') is not None, 'expected a hit immediately after set()'
print('immediate get: HIT (expected)')

import time
time.sleep(2)

# After the 1-second TTL has elapsed: should be a miss.
assert service.get('domains', 'example.com') is None, 'expected a miss after TTL elapsed'
print('get after TTL elapsed: MISS (expected)')

backend.close()
"
rm -f /tmp/b2_smoke.sqlite
```

Expected: both print statements execute with no `AssertionError` — proves TTL expiry actually works end-to-end through the real `SQLiteCacheBackend` + `ReportCacheService`, not just against mocks.

- [ ] **Step 4: Confirm no stray files, clean working tree**

```bash
git status --short
```

Expected: empty.

- [ ] **Step 5: Report to the user**

No commit for this step. Summarize: final test count, confirmation `vt_tools.py --help` is unchanged (no commit in this plan touches `vt_tools.py`), confirmation the end-to-end TTL smoke test passed, and that this closes out sub-project B2 — B3 (API service with job queue) and B4 (Docker deployment) remain, each needing its own design/plan cycle. Note explicitly that `PostgresCacheBackend` was deliberately deferred to whenever B3 makes a concrete need for it, per this plan's Global Constraints.

---

## Self-Review

**Spec coverage:** `CacheBackend` Protocol (Task 1, Step 3) ✅. `SQLiteCacheBackend.get()` tuple return shape (Task 1, Step 4) ✅. `ReportCacheService` TTL policy replacing the ratio heuristic (Task 1, Step 8) ✅. Not-found-as-real-hit behavior change (Task 1, Step 6's `test_a_cached_not_found_report_is_a_real_hit_within_ttl`) ✅. Lazy expiry / no cleanup job — implicitly satisfied by never writing one; nothing in any task adds a `purge_expired()` method or scheduled job ✅. `VT_CACHE_TTL_HOURS` env var, default 24h (Task 2) ✅. No Postgres, no per-type TTL, no `CacheError` wiring — none of the three tasks touch those areas, consistent with Global Constraints ✅.

**Placeholder scan:** no TBD/TODO; every step shows complete code, not descriptions of code.

**Type/signature consistency:** `CacheBackend.get() -> tuple[dict, str] | None` (Task 1 Protocol) matches `SQLiteCacheBackend.get()`'s actual new return type (Task 1 Step 4) matches what `ReportCacheService.get()` unpacks (Task 1 Step 8) — all three reference the same `(report: dict, cached_at: str)` shape. `ReportCacheService(backend, ttl: timedelta = timedelta(hours=24))` is the same signature used in Task 1's own tests and Task 2's `init.py` wiring (`ReportCacheService(cache_backend, ttl=cache_ttl)`).

**One design-doc deviation, made deliberately and noted inline:** the design doc's illustrative `init.py` snippet computed `CACHE_TTL` as a module-level constant. Task 2 instead reads `VT_CACHE_TTL_HOURS` inside `Initializator.__init__` itself, per-instantiation. Reason: a module-level constant is computed once at first import and Python caches that import, so a test using `mock.patch.dict(os.environ, ...)` around a later `Initializator(...)` construction would silently see the stale, already-computed value — the env var override would never take effect within a single test run. Reading it inside `__init__` matches how `get_api_key`/`get_proxy` are already read elsewhere in this codebase (per-call, not per-import) and is what Task 2's own tests rely on. This does not change the design's intent (one env var, one default, read at startup) — only where in the file that read happens.
