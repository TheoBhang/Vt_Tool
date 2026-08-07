# Core Library Extraction (Sub-project B1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract vt_tool's analyze-one-value business logic into five service classes with no CLI dependency, per the approved design at `docs/superpowers/specs/2026-08-06-core-library-extraction-design.md`. Fix the structural root cause (duplicated report-shaping between `VTReporter` and `DBHandler`) behind two bugs fixed earlier this session. `vt_tools.py`'s user-facing behavior (arguments, output format, prompts) must be unchanged when this plan is done.

**Architecture:** `AnalysisService` orchestrates `ValidationService`, `VirusTotalService`, and `ReportCacheService` (which wraps a `CacheBackend`, `SQLiteCacheBackend` the only implementation). `MispService` is a separate call path. `init.py` becomes a factory wiring these five classes; `vt_tools.py` shrinks to argparse + service calls + Rich output.

**Tech Stack:** No new dependencies. Cache moves from four SQLite tables (one column per report field) to one table storing the report as a JSON blob (stdlib `json`).

## Global Constraints

- `vt_tools.py --help` and all CLI output formatting must be unchanged when this plan is done — this is an internal restructure, not a behavior change.
- No migration for existing `vttools.sqlite` — new schema, fresh table, per the approved design.
- Services (`app/services/*`, `app/cache_backends/*`) must not import `rich`, `argparse`, or call `input()`/`Prompt.ask()` — no CLI dependency, that's the entire point.
- `VirusTotalService`, `ValidationService` reuse existing, already-correct logic from `VTReporter`/`DataValidator` — this is an extraction, not a rewrite of business logic that already works.
- Testing conventions from earlier this session carry over: stdlib `unittest`, mock only at real boundaries (`vt.Client`, `sqlite3`, filesystem), assert on real behavior.
- Activate the venv for every command: `source .venv/bin/activate`.
- Value-type vocabulary is preserved as-is (CLI-plural `"ips"/"domains"/"urls"/"hashes"` at the `AnalysisService`/`ValidationService` boundary, canonical-uppercase `"PUBLIC IPV4"/"DOMAIN"/"URL"/"SHA-256"/"SHA-1"/"MD5"` at the `VirusTotalService`/cache boundary) — cleaning this up is out of scope for B1.

---

### Task 1: `app/errors.py`

**Files:**
- Create: `app/errors.py`
- Test: `tests/test_errors.py`

**Interfaces:**
- Produces: `AnalysisError`, `ValidationError`, `VirusTotalAPIError`, `CacheError` — imported by every later task's services.

- [ ] **Step 1: Write the failing test**

```python
import unittest

from app.errors import AnalysisError, ValidationError, VirusTotalAPIError, CacheError


class ErrorHierarchyTests(unittest.TestCase):
    def test_validation_error_is_analysis_error(self):
        self.assertTrue(issubclass(ValidationError, AnalysisError))

    def test_virustotal_api_error_is_analysis_error(self):
        self.assertTrue(issubclass(VirusTotalAPIError, AnalysisError))

    def test_cache_error_is_analysis_error(self):
        self.assertTrue(issubclass(CacheError, AnalysisError))

    def test_analysis_error_is_exception(self):
        self.assertTrue(issubclass(AnalysisError, Exception))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_errors -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.errors'`

- [ ] **Step 3: Write the implementation**

```python
class AnalysisError(Exception):
    """Base class for all core-service errors."""


class ValidationError(AnalysisError):
    """Raised when a value cannot be classified as a supported, queryable IOC type."""


class VirusTotalAPIError(AnalysisError):
    """Raised when a VirusTotal API call fails for a reason other than 'not found'."""


class CacheError(AnalysisError):
    """Raised when the report cache fails to read or write."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m unittest tests.test_errors -v`
Expected: PASS, 4/4.

- [ ] **Step 5: Commit**

```bash
git add app/errors.py tests/test_errors.py
git commit -m "feat: add core service error hierarchy"
```

---

### Task 2: `app/cache_backends/sqlite_backend.py`

**Files:**
- Create: `app/cache_backends/__init__.py` (empty)
- Create: `app/cache_backends/sqlite_backend.py`
- Test: `tests/test_sqlite_backend.py`

**Interfaces:**
- Produces: `SQLiteCacheBackend(db_path).get(value_type, value) -> dict | None`, `.set(value_type, value, report: dict) -> None`, `.close() -> None`. Consumed by `ReportCacheService` (Task 3).

- [ ] **Step 1: Write the failing test**

```python
import json
import os
import sqlite3
import tempfile
import unittest

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

    def test_set_then_get_round_trips_the_report(self):
        report = {"domain": "example.com", "malicious_score": 3, "tags": "phishing"}
        self.backend.set("DOMAIN", "example.com", report)
        self.assertEqual(self.backend.get("DOMAIN", "example.com"), report)

    def test_set_twice_updates_instead_of_duplicating(self):
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 1})
        self.backend.set("DOMAIN", "example.com", {"malicious_score": 9})
        self.assertEqual(self.backend.get("DOMAIN", "example.com"), {"malicious_score": 9})

        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM cached_reports WHERE value_type = ? AND value = ?",
            ("DOMAIN", "example.com"),
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_same_value_different_type_is_a_separate_entry(self):
        self.backend.set("DOMAIN", "8.8.8.8", {"kind": "domain-shaped"})
        self.backend.set("PUBLIC IPV4", "8.8.8.8", {"kind": "ip-shaped"})
        self.assertEqual(self.backend.get("DOMAIN", "8.8.8.8"), {"kind": "domain-shaped"})
        self.assertEqual(self.backend.get("PUBLIC IPV4", "8.8.8.8"), {"kind": "ip-shaped"})

    def test_cached_at_column_is_populated(self):
        self.backend.set("DOMAIN", "example.com", {"a": 1})
        conn = sqlite3.connect(self.db_path)
        cached_at = conn.execute(
            "SELECT cached_at FROM cached_reports WHERE value_type = ? AND value = ?",
            ("DOMAIN", "example.com"),
        ).fetchone()[0]
        conn.close()
        self.assertIsNotNone(cached_at)
        self.assertNotEqual(cached_at, "")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_sqlite_backend -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.cache_backends'`

- [ ] **Step 3: Write the implementation**

`app/cache_backends/__init__.py`: empty file.

`app/cache_backends/sqlite_backend.py`:

```python
import json
import sqlite3
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
    logic lives here - that is VirusTotalService's job alone."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def get(self, value_type: str, value: str) -> dict | None:
        row = self._conn.execute(
            "SELECT report_json FROM cached_reports WHERE value_type = ? AND value = ?",
            (value_type, value),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def set(self, value_type: str, value: str, report: dict) -> None:
        cached_at = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            INSERT INTO cached_reports (value_type, value, report_json, cached_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(value_type, value) DO UPDATE SET
                report_json = excluded.report_json,
                cached_at = excluded.cached_at
            """,
            (value_type, value, json.dumps(report), cached_at),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m unittest tests.test_sqlite_backend -v`
Expected: PASS, 5/5.

- [ ] **Step 5: Commit**

```bash
git add app/cache_backends/ tests/test_sqlite_backend.py
git commit -m "feat: add SQLiteCacheBackend with unified JSON-blob schema"
```

---

### Task 3: `app/services/cache_service.py`

**Files:**
- Create: `app/services/__init__.py` (empty)
- Create: `app/services/cache_service.py`
- Test: `tests/test_cache_service.py`

**Interfaces:**
- Consumes: `SQLiteCacheBackend`-shaped object (duck-typed: anything with `.get(value_type, value)` / `.set(value_type, value, report)`) from Task 2.
- Produces: `ReportCacheService(backend).get(value_type, value) -> dict | None`, `.set(value_type, value, report) -> None`. Consumed by `AnalysisService` (Task 7).

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_cache_service -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services'`

- [ ] **Step 3: Write the implementation**

`app/services/__init__.py`: empty file.

`app/services/cache_service.py`:

```python
NOT_FOUND_ERROR = "Not found"


class ReportCacheService:
    """A pure cache in front of a CacheBackend: no report-shaping logic lives
    here, only the policy of when a cached entry counts as a real hit."""

    def __init__(self, backend, threshold: float = 0.8):
        self.backend = backend
        self.threshold = threshold

    def get(self, value_type: str, value: str) -> dict | None:
        report = self.backend.get(value_type, value)
        if report is None:
            return None
        if not report:
            return None
        not_found_count = sum(1 for v in report.values() if v == NOT_FOUND_ERROR)
        if (not_found_count / len(report)) >= self.threshold:
            return None
        return report

    def set(self, value_type: str, value: str, report: dict) -> None:
        self.backend.set(value_type, value, report)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m unittest tests.test_cache_service -v`
Expected: PASS, 5/5.

- [ ] **Step 5: Commit**

```bash
git add app/services/__init__.py app/services/cache_service.py tests/test_cache_service.py
git commit -m "feat: add ReportCacheService"
```

---

### Task 4: `app/services/validation_service.py`

**Files:**
- Create: `app/services/validation_service.py`
- Test: `tests/test_validation_service.py`

**Interfaces:**
- Consumes: `DataValidator` (`app/DataHandler/validator.py`, unchanged).
- Produces: `ValidationService(validator=None).classify(value, value_type: str) -> str | None`. Consumed by `AnalysisService` (Task 7). `value_type` here is the CLI-plural bucket (`"ips"/"domains"/"urls"/"hashes"`); the returned string is `DataValidator`'s classification vocabulary (e.g. `"Public IPv4"`, `"DOMAIN"`, `"URL"`, `"MD5"`).

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_validation_service -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.validation_service'`

- [ ] **Step 3: Write the implementation**

```python
from app.DataHandler.validator import DataValidator


class ValidationService:
    """Classifies a raw value into DataValidator's type-string vocabulary, or None
    if unsupported/invalid. Thin wrapper - the validation logic itself already
    lives correctly in DataValidator, this just gives it a service-class entry
    point AnalysisService can call without knowing DataValidator's method-naming
    convention."""

    def __init__(self, validator: DataValidator | None = None):
        self.validator = validator or DataValidator()

    def classify(self, value, value_type: str) -> str | None:
        try:
            if value_type == "hashes":
                return self.validator.validate_hash(value)
            validator_func = getattr(self.validator, f"validate_{value_type[:-1]}")
            return validator_func(value)
        except AttributeError:
            return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m unittest tests.test_validation_service -v`
Expected: PASS, 6/6.

- [ ] **Step 5: Commit**

```bash
git add app/services/validation_service.py tests/test_validation_service.py
git commit -m "feat: add ValidationService"
```

---

### Task 5: `app/services/virustotal_service.py`

**Files:**
- Create: `app/services/virustotal_service.py`
- Test: `tests/test_virustotal_service.py`

**Interfaces:**
- Consumes: a `vt.Client`-shaped object (duck-typed, has `.get_object(path)`), `app.errors.VirusTotalAPIError`.
- Produces: `VirusTotalService(vt_client).get_report(value_type: str, value) -> dict`. `value_type` here is the canonical uppercase form (`"PUBLIC IPV4"/"DOMAIN"/"URL"/"SHA-256"/"SHA-1"/"MD5"`). Raises `VirusTotalAPIError` on any VT failure other than "not found". Consumed by `AnalysisService` (Task 7).
- This absorbs `VTReporter`'s report-shaping methods (`app/VirusTotal/vt_reporter.py`, read in full during planning) almost verbatim - the shaping logic itself is unchanged and already correct. The one deliberate behavior change: **no longer inserts into the database as a side effect** (`VTReporter.insert_into_db` is dropped entirely) - caching becomes `AnalysisService`'s explicit responsibility via `ReportCacheService`, not something buried inside report-shaping.

- [ ] **Step 1: Write the failing test**

```python
import unittest
from unittest import mock

from app.errors import VirusTotalAPIError
from app.services.virustotal_service import VirusTotalService


class FakeReport:
    """Minimal stand-in for vt.Object: supports getattr() and .get()."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)


class CreateReportTests(unittest.TestCase):
    def test_unknown_value_type_returns_default_object(self):
        service = VirusTotalService(mock.Mock())
        result = service.get_report("BOGUS", "x")
        self.assertEqual(result["malicious_score"], "Not found")

    def test_not_found_returns_default_object_no_exception(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = Exception("NotFoundError raised by vt-py")
        service = VirusTotalService(vt_client)
        result = service.get_report("DOMAIN", "nosuch.example")
        self.assertEqual(result["malicious_score"], "Not found")
        self.assertEqual(result["tags"], "Not found")

    def test_other_errors_raise_virustotal_api_error(self):
        vt_client = mock.Mock()
        vt_client.get_object.side_effect = RuntimeError("network down")
        service = VirusTotalService(vt_client)
        with self.assertRaises(VirusTotalAPIError):
            service.get_report("DOMAIN", "example.com")


class GetReportIpTests(unittest.TestCase):
    def test_populates_ip_fields_from_report(self):
        vt_client = mock.Mock()
        report = FakeReport(
            last_analysis_stats={"malicious": 2, "harmless": 60},
            tags=["t1", "t2"],
            as_owner="Google LLC",
            continent="NA",
            country="US",
            network="8.8.8.0/24",
            last_https_certificate="cert",
            regional_internet_registry="ARIN",
            asn=15169,
        )
        vt_client.get_object.return_value = report
        service = VirusTotalService(vt_client)

        result = service.get_report("PUBLIC IPV4", "8.8.8.8")

        self.assertEqual(result["malicious_score"], 2)
        self.assertEqual(result["total_scans"], 62)
        self.assertEqual(result["tags"], "t1, t2")
        self.assertEqual(result["location"], "NA / US")
        self.assertEqual(result["owner"], "Google LLC")
        self.assertEqual(result["link"], "https://www.virustotal.com/gui/search/8.8.8.8")

    def test_does_not_write_to_a_database(self):
        # The one deliberate behavior change from VTReporter: no DB side effect.
        vt_client = mock.Mock()
        vt_client.get_object.return_value = FakeReport(
            last_analysis_stats={"malicious": 0, "harmless": 1}, tags=[],
            as_owner="x", continent="NA", country="US", network="n",
            last_https_certificate="c", regional_internet_registry="r", asn=1,
        )
        service = VirusTotalService(vt_client)
        self.assertFalse(hasattr(service, "insert_into_db"))
        self.assertFalse(hasattr(service, "db_handler"))


class GetReportHashThreatClassificationTests(unittest.TestCase):
    def test_populates_threat_category_and_labels_when_present(self):
        vt_client = mock.Mock()
        report = FakeReport(
            last_analysis_stats={"malicious": 40, "harmless": 20},
            tags=[],
            type_extension="exe", size=1024, md5="m", sha1="s1", sha256="s2",
            ssdeep="sd", tlsh="t", meaningful_name="n", names=["n1", "n2"],
            trid=[{"file_type": "Win32 EXE", "probability": "80.0%"}],
            popular_threat_classification={
                "suggested_threat_label": "trojan.generic",
                "popular_threat_category": [{"value": "trojan"}],
            },
        )
        vt_client.get_object.return_value = report
        service = VirusTotalService(vt_client)

        result = service.get_report("SHA-256", "a" * 64)

        self.assertEqual(result["threat_category"], "trojan")
        self.assertEqual(result["threat_labels"], "trojan.generic")
        self.assertEqual(result["type"], "Win32 EXE")

    def test_missing_classification_falls_back_to_not_found(self):
        vt_client = mock.Mock()
        report = FakeReport(
            last_analysis_stats={"malicious": 0, "harmless": 20},
            tags=[],
            type_extension="exe", size=1024, md5="m", sha1="s1", sha256="s2",
            ssdeep="sd", tlsh="t", meaningful_name="n", names=["n1"],
        )
        vt_client.get_object.return_value = report
        service = VirusTotalService(vt_client)

        result = service.get_report("SHA-256", "b" * 64)

        self.assertEqual(result["threat_category"], "Not found")
        self.assertEqual(result["threat_labels"], "Not found")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_virustotal_service -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.virustotal_service'`

- [ ] **Step 3: Write the implementation**

```python
import logging

from vt import url_id

from app.DataHandler.utils import utc2local, build_virustotal_link
from app.DataHandler.validator import (
    get_service_name,
    get_url_details,
    extract_ip_address,
    get_port_from_service_name,
)
from app.errors import VirusTotalAPIError

IPV4_PUBLIC_TYPE = "PUBLIC IPV4"
NOT_FOUND_ERROR = "Not found"

logger = logging.getLogger(__name__)


class VirusTotalService:
    """Fetches a VirusTotal report and shapes it into vt_tool's flat report dict.
    This is the only place report-shaping happens - the cache stores whatever
    this returns verbatim and never re-derives it."""

    def __init__(self, vt_client):
        self.vt = vt_client

    def get_report(self, value_type: str, value) -> dict:
        report = self._fetch(value_type, value)
        value_object = self._initialize(value_type)
        if report is not None:
            self._populate(value_object, value_type, value, report)
        return value_object

    def _fetch(self, value_type, value):
        if isinstance(value, tuple):
            value = value[0]
        api_endpoints = {
            IPV4_PUBLIC_TYPE: f"/ip_addresses/{value}",
            "DOMAIN": f"/domains/{value}",
            "URL": f"/urls/{url_id(value)}",
            "SHA-256": f"/files/{value}",
            "SHA-1": f"/files/{value}",
            "MD5": f"/files/{value}",
        }
        if value_type not in api_endpoints:
            return None
        try:
            return self.vt.get_object(api_endpoints[value_type])
        except Exception as e:
            if "NotFoundError" in str(e):
                logger.warning(f"{NOT_FOUND_ERROR} on VirusTotal Database: {value}")
                return None
            logger.error(f"Error fetching report for {value_type}: {value} - {e}")
            raise VirusTotalAPIError(str(e)) from e

    def _initialize(self, value_type):
        value_object = {
            "malicious_score": NOT_FOUND_ERROR,
            "total_scans": NOT_FOUND_ERROR,
            "tags": NOT_FOUND_ERROR,
            "link": NOT_FOUND_ERROR,
        }
        if value_type in ["SHA-256", "SHA-1", "MD5"]:
            value_object["threat_category"] = NOT_FOUND_ERROR
            value_object["threat_labels"] = NOT_FOUND_ERROR
        return value_object

    def _populate(self, value_object, value_type, value, report):
        total_scans = sum(report.last_analysis_stats.values())
        malicious = report.last_analysis_stats.get("malicious", 0)
        value_object["malicious_score"] = malicious
        value_object["total_scans"] = total_scans
        value_object["link"] = build_virustotal_link(value, value_type)
        tags = getattr(report, "tags", [])
        value_object["tags"] = ", ".join(tags) if tags else NOT_FOUND_ERROR

        if value_type == IPV4_PUBLIC_TYPE:
            self._populate_ip(value_object, value, report)
        elif value_type == "DOMAIN":
            self._populate_domain(value_object, value, report)
        elif value_type == "URL":
            self._populate_url(value_object, value, report)
        elif value_type in ["SHA-256", "SHA-1", "MD5"]:
            self._populate_hash(value_object, value, report)
            self._populate_threat_classification(value_object, report)

    def _populate_ip(self, value_object, value, report):
        if isinstance(value, tuple):
            ip, port = value
        else:
            ip, port = value, None
        value_object.update({
            "ip": ip,
            "port": port if port else NOT_FOUND_ERROR,
            "protocol": get_service_name(port) if port else NOT_FOUND_ERROR,
            "owner": getattr(report, "as_owner", NOT_FOUND_ERROR),
            "location": f"{report.continent} / {report.country}"
                if hasattr(report, "continent") and hasattr(report, "country")
                else NOT_FOUND_ERROR,
            "network": getattr(report, "network", NOT_FOUND_ERROR),
            "https_certificate": getattr(report, "last_https_certificate", NOT_FOUND_ERROR),
            "info-ip": {
                "regional_internet_registry": getattr(report, "regional_internet_registry", NOT_FOUND_ERROR),
                "asn": getattr(report, "asn", NOT_FOUND_ERROR),
            },
        })

    def _populate_domain(self, value_object, value, report):
        ip = getattr(report, "whois", {})
        if isinstance(ip, str):
            ip = extract_ip_address(ip)
        value_object.update({
            "domain": value,
            "ip": ip if ip else NOT_FOUND_ERROR,
            "port": getattr(report, "port", NOT_FOUND_ERROR),
            "protocol": get_service_name(getattr(report, "port", None))
                if getattr(report, "port", None) else NOT_FOUND_ERROR,
            "creation_date": getattr(report, "creation_date", NOT_FOUND_ERROR),
            "reputation": getattr(report, "reputation", NOT_FOUND_ERROR),
            "whois": getattr(report, "whois", NOT_FOUND_ERROR),
            "info": {
                "last_analysis_results": getattr(report, "last_analysis_results", NOT_FOUND_ERROR),
                "last_analysis_stats": getattr(report, "last_analysis_stats", NOT_FOUND_ERROR),
                "last_dns_records": getattr(report, "last_dns_records", NOT_FOUND_ERROR),
                "last_https_certificate": getattr(report, "last_https_certificate", NOT_FOUND_ERROR),
                "registrar": getattr(report, "registrar", NOT_FOUND_ERROR),
            },
        })

    def _populate_url(self, value_object, value, report):
        details = get_url_details(value)
        first_submission_date = getattr(report, "first_submission_date", None)
        if first_submission_date:
            try:
                first_scan = str(utc2local(first_submission_date))
            except Exception as e:
                logger.error(f"Date was not found: {e}")
                first_scan = NOT_FOUND_ERROR
        else:
            first_scan = NOT_FOUND_ERROR

        port = details["port"] if details["port"] else get_port_from_service_name(details["scheme"])

        value_object.update({
            "url": value,
            "domain": details["domain"] if details["domain"] != '' else NOT_FOUND_ERROR,
            "ip": getattr(report, "ip_address", NOT_FOUND_ERROR),
            "port": port,
            "protocol": get_service_name(details["port"]) if details["port"] != '' else NOT_FOUND_ERROR,
            "fragment": details["fragment"] if details["fragment"] != '' else NOT_FOUND_ERROR,
            "resource_path": details["resource_path"] if details["resource_path"] != '' else NOT_FOUND_ERROR,
            "query_params": details["query_params"] if details["query_params"] != '' else NOT_FOUND_ERROR,
            "query_strings": details["query_strings"] if details["query_strings"] != '' else NOT_FOUND_ERROR,
            "tld": details["tld"] if details["tld"] != '' else NOT_FOUND_ERROR,
            "subdomain": details["subdomain"] if details["subdomain"] != '' else NOT_FOUND_ERROR,
            "scheme": details["scheme"] if details["scheme"] != '' else NOT_FOUND_ERROR,
            "title": getattr(report, "title", NOT_FOUND_ERROR),
            "final_url": getattr(report, "last_final_url", NOT_FOUND_ERROR),
            "first_scan": first_scan,
            "info": {
                "metadatas": getattr(report, "html_meta", NOT_FOUND_ERROR),
                "targeted": getattr(report, "targeted_brand", NOT_FOUND_ERROR),
                "links": getattr(report, "outgoing_links", NOT_FOUND_ERROR),
                "redirection_chain": getattr(report, "redirection_chain", NOT_FOUND_ERROR),
                "trackers": getattr(report, "trackers", NOT_FOUND_ERROR),
            },
        })

    def _populate_hash(self, value_object, value, report):
        value_object.update({
            "hash": value,
            "extension": getattr(report, "type_extension", NOT_FOUND_ERROR),
            "size": getattr(report, "size", NOT_FOUND_ERROR),
            "md5": getattr(report, "md5", NOT_FOUND_ERROR),
            "sha1": getattr(report, "sha1", NOT_FOUND_ERROR),
            "sha256": getattr(report, "sha256", NOT_FOUND_ERROR),
            "ssdeep": getattr(report, "ssdeep", NOT_FOUND_ERROR),
            "tlsh": getattr(report, "tlsh", NOT_FOUND_ERROR),
            "meaningful_name": getattr(report, "meaningful_name", NOT_FOUND_ERROR),
            "names": ", ".join(getattr(report, "names", [NOT_FOUND_ERROR])),
            "type": report.trid[0]["file_type"] if hasattr(report, "trid") else NOT_FOUND_ERROR,
            "type_probability": report.trid[0]["probability"] if hasattr(report, "trid") else NOT_FOUND_ERROR,
        })

    def _populate_threat_classification(self, value_object, report):
        try:
            if report.popular_threat_classification:
                classification = report.get("popular_threat_classification", {})
                categories = classification.get('popular_threat_category', [])
                value_object["threat_category"] = ", ".join(c['value'] for c in categories)
                value_object["threat_labels"] = classification.get("suggested_threat_label", NOT_FOUND_ERROR)
            else:
                value_object["threat_category"] = NOT_FOUND_ERROR
                value_object["threat_labels"] = NOT_FOUND_ERROR
        except Exception:
            value_object["threat_category"] = NOT_FOUND_ERROR
            value_object["threat_labels"] = NOT_FOUND_ERROR
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m unittest tests.test_virustotal_service -v`
Expected: PASS, 7/7.

- [ ] **Step 5: Commit**

```bash
git add app/services/virustotal_service.py tests/test_virustotal_service.py
git commit -m "feat: add VirusTotalService, absorbing VTReporter's shaping logic"
```

---

### Task 6: `app/services/misp_service.py`

**Files:**
- Create: `app/services/misp_service.py`
- Test: `tests/test_misp_service.py`
- Modify: `app/MISP/vt_tools2misp.py`
- Modify: `tests/test_misp.py`

**Interfaces:**
- Produces: `MispService.create_object(row, object_name, attribute_mapping) -> MISPObject | None`, `MispService.identify_object_type(csv_file: str) -> str`, `MispService.build_attribute_mapping(headers, attribute_type_mapping) -> dict`, `MispService.objects_from_csv(data, object_name, attribute_mapping, template_object=None, template_key=None) -> list[MISPObject]`. These are `create_misp_object`/`identify_object_type`/`get_attribute_mapping`/`create_misp_objects_from_csv` from `app/MISP/vt_tools2misp.py`, moved verbatim (function bodies unchanged) into class methods.
- `app/MISP/vt_tools2misp.py` keeps `process_csv_file`, `load_template`, `apply_template_data` (file-reading, not MISP-object-building — arguably core too, but small and tightly coupled to the CSV/template file format the CLI reads, left in place to keep this task's diff focused), `get_misp_event`, `submit_misp_objects`, `misp_event`, `misp_choice` (all either interactive or need a live `ExpandedPyMISP` connection), and `process_and_submit_to_misp` (now calls `MispService` methods instead of the free functions it used to call directly).

- [ ] **Step 1: Write the failing test**

```python
import unittest

from app.services.misp_service import MispService


class MispServiceTests(unittest.TestCase):
    def test_identify_object_type_matches_known_patterns(self):
        service = MispService()
        self.assertEqual(service.identify_object_type("000001_Hashes_Analysis_x.csv"), "file")
        self.assertEqual(service.identify_object_type("000001_URL_Analysis_x.csv"), "url")
        self.assertEqual(service.identify_object_type("000001_IP_Analysis_x.csv"), "ip-port")
        self.assertEqual(service.identify_object_type("000001_Domains_Analysis_x.csv"), "domain-ip")
        self.assertEqual(service.identify_object_type("000001_hashes_analysis_x.csv"), "file")

    def test_identify_object_type_unknown_filename_raises(self):
        service = MispService()
        with self.assertRaises(ValueError):
            service.identify_object_type("unrelated_file.csv")

    def test_build_attribute_mapping_maps_known_headers(self):
        service = MispService()
        mapping = {"ip": ("ip", "ip-dst", "Network activity", False)}
        result = service.build_attribute_mapping(["ip", "malicious_score"], mapping)
        self.assertEqual(result, {"ip": ("ip", "ip-dst", "Network activity", False)})

    def test_build_attribute_mapping_raises_when_nothing_matches(self):
        service = MispService()
        with self.assertRaises(ValueError):
            service.build_attribute_mapping(["nope"], {"ip": ("ip", "ip-dst", "Network activity", False)})

    def test_create_object_builds_misp_object_with_mapped_attributes(self):
        service = MispService()
        row = {"ip": "8.8.8.8", "malicious_score": "Not found", "comment": "hi"}
        attribute_mapping = {
            "ip": ("ip", "ip-dst", "Network activity", False),
            "malicious_score": ("malicious_score", "text", "Antivirus detection", False),
        }
        obj = service.create_object(row, "ip-port", attribute_mapping)
        self.assertEqual(obj.name, "ip-port")
        self.assertEqual(obj.comment, "hi")
        self.assertEqual(len(obj.attributes), 1)
        self.assertEqual(obj.attributes[0].type, "ip-dst")
        self.assertEqual(obj.attributes[0].value, "8.8.8.8")

    def test_create_object_incomplete_mapping_returns_none(self):
        service = MispService()
        row = {"ip": "8.8.8.8"}
        attribute_mapping = {"ip": ("ip", "ip-dst", "Network activity")}  # missing 4th element
        self.assertIsNone(service.create_object(row, "ip-port", attribute_mapping))

    def test_objects_from_csv_applies_template_and_builds_objects(self):
        service = MispService()
        data = [{"ip": "8.8.8.8", "malicious_score": "0"}]
        template_object = {"8.8.8.8": {"comment": ["from template"]}}
        attribute_mapping = {"ip": ("ip", "ip-dst", "Network activity", False)}
        objects = service.objects_from_csv(
            data, "ip-port", attribute_mapping, template_object=template_object, template_key="ip"
        )
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0].comment, "from template")

    def test_objects_from_csv_unsupported_object_name_returns_empty(self):
        service = MispService()
        objects = service.objects_from_csv([{"a": "b"}], "bogus-type", {})
        self.assertEqual(objects, [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_misp_service -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.misp_service'`

- [ ] **Step 3: Write the implementation**

`app/services/misp_service.py`:

```python
import datetime
import logging
import re
from typing import Dict, List, Optional

from pymisp import MISPObject

logger = logging.getLogger(__name__)

# object_name -> the CSV column that keys template lookups for that object type.
TEMPLATE_KEY_BY_OBJECT_NAME = {
    "file": "hash",
    "url": "url",
    "ip-port": "ip",
    "domain-ip": "domain",
}

# csv filename pattern -> MISP object name, checked in order.
FILENAME_PATTERNS = [
    (r"Hash", "file"),
    (r"URL", "url"),
    (r"IP", "ip-port"),
    (r"Domain", "domain-ip"),
]


class MispService:
    """Builds MISPObjects from already-analyzed CSV rows. No network calls, no
    interactive prompts - just data shaping, the MISP analog of
    VirusTotalService. The actual submission (needs a live ExpandedPyMISP
    connection) stays in app/MISP/vt_tools2misp.py."""

    def identify_object_type(self, csv_file: str) -> str:
        for pattern, misp_object_name in FILENAME_PATTERNS:
            if re.search(pattern, csv_file, re.IGNORECASE):
                return misp_object_name
        raise ValueError(f"Unknown CSV file format: '{csv_file}'. Could not determine MISP object name.")

    def build_attribute_mapping(self, headers: List[str], attribute_type_mapping: Dict[str, tuple]) -> Dict[str, tuple]:
        attribute_mapping = {}
        for header in headers:
            if header in attribute_type_mapping:
                attribute_mapping[header] = attribute_type_mapping[header]
            else:
                logger.warning(f"Header '{header}' not found in attribute_type_mapping.")
        if not attribute_mapping:
            raise ValueError("No valid attribute mappings were found based on the provided headers.")
        logger.info(f"Successfully mapped {len(attribute_mapping)} attributes.")
        return attribute_mapping

    def create_object(self, row: Dict[str, str], object_name: str, attribute_mapping: Dict[str, tuple]) -> Optional[MISPObject]:
        try:
            misp_object = MISPObject(name=object_name)
            misp_object.comment = row.get("comment", "")

            for key, value in row.items():
                if key not in attribute_mapping:
                    continue
                attr_details = attribute_mapping[key]
                if len(attr_details) != 4:
                    raise ValueError(f"Attribute mapping for '{key}' is incomplete (should contain 4 details).")
                attribute_type, attr_type, category, to_ids = attr_details

                if value in ["Not found", "Not Found", "", None, "null"]:
                    continue
                if attr_type == "datetime" and value == "0":
                    value = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                correlatable = attribute_type in ["ip", "url", "sha256", "md5", "sha1", "ssdeep", "tlsh"]
                misp_object.add_attribute(
                    attribute_type,
                    value=value,
                    type=attr_type,
                    category=category,
                    to_ids=correlatable,
                    disable_correlation=not correlatable,
                )
            return misp_object
        except Exception as e:
            logger.error(f"Failed to create MISP object from row: {row}. Error: {e}")
            return None

    def objects_from_csv(
        self,
        data: List[Dict[str, str]],
        object_name: str,
        attribute_mapping: Dict[str, tuple],
        template_object: Optional[Dict[str, Dict[str, List[str]]]] = None,
        template_key: Optional[str] = None,
    ) -> List[MISPObject]:
        if object_name not in TEMPLATE_KEY_BY_OBJECT_NAME:
            logger.error(f"Unsupported object name '{object_name}'.")
            return []

        if template_object and template_key:
            for row in data:
                key_value = row.get(template_key)
                if key_value and key_value in template_object:
                    for key, values in template_object[key_value].items():
                        row[key] = values[0] if len(values) == 1 else values

        misp_objects = []
        for row in data:
            misp_object = self.create_object(row, object_name, attribute_mapping)
            if misp_object:
                misp_objects.append(misp_object)

        if not misp_objects:
            logger.warning("No valid MISP objects were created.")
        return misp_objects
```

Now trim `app/MISP/vt_tools2misp.py`. Remove `create_misp_object`, `create_misp_objects_from_csv`, `identify_object_type`, `get_attribute_mapping` (moved to `MispService`). Keep `process_csv_file`, `load_template`, `apply_template_data`, `get_misp_event`, `submit_misp_objects`, `misp_event`, `misp_choice`. Update `process_and_submit_to_misp` to use `MispService`:

```python
def process_and_submit_to_misp(misp, case_str, csv_files_created, template_file, template) -> None:
    """
    Process CSV files and submit data to MISP.

    Parameters:
        misp: An instance of the MISP object.
        case_str (str): The case identifier string.
        csv_files_created (List[str]): List of CSV files that were created for submission.
    """
    misp_service = MispService()
    misp_event_obj = get_misp_event(misp, case_str)
    console.print(f"[bold]Using MISP event {misp_event_obj.id} for submission[/bold]")

    if not csv_files_created:
        console.print("[bold red]No CSV files found for processing![/bold red]")
        return

    console.print("[bold]Processing CSV files and submitting data to MISP...[/bold]")

    attribute_type_mapping = {
        "file": {
            "sha256": ("sha256", "sha256", "Payload delivery", False),
            "sha1": ("sha1", "sha1", "Payload delivery", False),
            "md5": ("md5", "md5", "Payload delivery", False),
            "ssdeep": ("ssdeep", "ssdeep", "Payload delivery", False),
            "tlsh": ("tlsh", "tlsh", "Payload delivery", False),
            "size": ("size", "size-in-bytes", "Payload delivery", False),
            "meaningful_name": ("filename", "text", "Payload delivery", False),
        },
        "domain-ip": {
            "domain": ("domain", "domain", "Network activity", False),
            "ip": ("ip", "ip-dst", "Network activity", False),
            "port": ("port", "port", "Network activity", False),
            "protocol": ("protocol", "text", "Network activity", False),
            "creation_date": ("creation_date", "datetime", "Network activity", False),
            "reputation": ("reputation", "text", "External analysis", False),
            "whois": ("whois", "text", "External analysis", False),
            "info": ("info", "text", "Other", False),
        },
        "url": {
            "url": ("url", "url", "Network activity", False),
            "domain": ("domain", "domain", "Network activity", False),
            "ip": ("ip", "ip-dst", "Network activity", False),
            "port": ("port", "port", "Network activity", False),
            "protocol": ("protocol", "text", "Network activity", False),
            "fragment": ("fragment", "text", "Other", False),
            "resource_path": ("resource_path", "text", "Network activity", False),
            "query_params": ("query_params", "text", "Other", False),
            "query_strings": ("query_strings", "text", "Other", False),
            "tld": ("tld", "text", "Other", False),
            "subdomain": ("subdomain", "text", "Other", False),
            "scheme": ("scheme", "text", "Other", False),
            "title": ("title", "text", "Other", False),
            "final_url": ("final_url", "url", "Network activity", False),
            "first_scan": ("first_scan", "datetime", "Other", False),
            "info": ("info", "text", "Other", False),
        },
        "ip-port": {
            "ip": ("ip", "ip-dst", "Network activity", False),
            "port": ("port", "port", "Network activity", False),
            "protocol": ("protocol", "text", "Network activity", False),
            "owner": ("owner", "text", "Other", False),
            "location": ("country-code", "text", "Network activity", False),
            "network": ("network", "text", "Other", False),
            "https_certificate": ("https_certificate", "text", "External analysis", False),
            "regional_internet_registry": ("regional_internet_registry", "text", "External analysis", False),
            "asn": ("AS", "AS", "Network activity", False),
        },
        "general": {
            "malicious_score": ("malicious_score", "text", "Antivirus detection", False),
            "link": ("link", "link", "External analysis", False),
        }
    }

    for csv_file in csv_files_created:
        console.print(f"[bold]Processing CSV file: {csv_file}[/bold]")
        try:
            data = process_csv_file(csv_file)
            if not data:
                console.print(f"[bold yellow]No data found in {csv_file}[/bold yellow]")
                continue

            object_type = misp_service.identify_object_type(csv_file)
            console.print(f"[bold green]Detected format: {object_type}[/bold green]")

            attribute_mapping = attribute_type_mapping[object_type].copy()
            attribute_mapping.update(attribute_type_mapping["general"])

            template_object = load_template(template_file) if template_file else {}
            template_key = {"file": "hash", "url": "url", "ip-port": "ip", "domain-ip": "domain"}.get(object_type)

            misp_objects = misp_service.objects_from_csv(
                data, object_type, attribute_mapping,
                template_object=template_object, template_key=template_key,
            )
            submit_misp_objects(misp, misp_event_obj, misp_objects)
        except ValueError as e:
            console.print(f"[bold red]{e}, skipping...[/bold red]")
            continue
        except Exception as e:
            console.print(f"[bold red]Failed to process CSV file '{csv_file}': {e}[/bold red]")
            continue

    console.print("[bold green]All CSV files processed and submitted successfully![/bold green]")
```

Add `from app.services.misp_service import MispService` to the top of `app/MISP/vt_tools2misp.py`; remove the now-unused `re`, `datetime`, `MISPObject` imports if nothing else in the file uses them (check with `grep` before removing each).

Update `tests/test_misp.py`: remove `IdentifyObjectTypeTests`, `CreateMispObjectTests`, and the `get_attribute_mapping`/`create_misp_object`/`identify_object_type` imports and their standalone test classes (`GetAttributeMappingTests`'s coverage moves to `test_misp_service.py` too) — those behaviors are now covered by `tests/test_misp_service.py`. Keep `ProcessCsvFileTests`, `LoadTemplateTests`, `ApplyTemplateDataTests`, `MispChoiceTests` as-is (unchanged functions).

- [ ] **Step 4: Run tests to verify they pass**

```bash
source .venv/bin/activate
python -m unittest tests.test_misp_service -v
python -m unittest tests.test_misp -v
```

Expected: `test_misp_service` 8/8 passing; `test_misp` passing with the trimmed set of tests (no `IdentifyObjectTypeTests`/`CreateMispObjectTests`/`GetAttributeMappingTests`).

- [ ] **Step 5: Commit**

```bash
git add app/services/misp_service.py app/MISP/vt_tools2misp.py tests/test_misp_service.py tests/test_misp.py
git commit -m "feat: add MispService, extracted from vt_tools2misp.py's non-interactive core"
```

---

### Task 7: `app/services/analysis_service.py`

**Files:**
- Create: `app/services/analysis_service.py`
- Test: `tests/test_analysis_service.py`

**Interfaces:**
- Consumes: `ValidationService` (Task 4), `VirusTotalService` (Task 5), `ReportCacheService` (Task 3), `app.errors.ValidationError`/`VirusTotalAPIError`.
- Produces: `AnalysisService(validation, virustotal, cache).analyze(value, value_type: str) -> tuple[dict, bool]` — returns `(report, from_cache)`. `value_type` is the CLI-plural bucket (`"ips"/"domains"/"urls"/"hashes"`). Raises `ValidationError` if the value classifies as unsupported (private/reserved IP, SHA-224/384/512, SSDEEP) or doesn't validate at all. This is the single method both `vt_tools.py` and a future API job worker call. Also exposes `UNSUPPORTED_VALUE_TYPES` as a module-level constant (moved from `vt_tools.py`).
- **Cache key design (settled during planning, verified with a standalone trace before writing this into the plan — see below):** the cache is keyed by `(value_type, cache_key)` using the CLI-plural `value_type` — NOT the canonical uppercase type `VirusTotalService` uses. This is deliberate: computing the canonical type requires calling `ValidationService.classify()`, and `value_type` (plural) is already known at call time without classifying anything. Keying the cache by the plural bucket means a cache hit never calls `classify()` at all — cheaper, and it's what a reasonable reader would expect ("don't validate something you already have a cached answer for"). `VirusTotalService.get_report()` still receives the canonical uppercase type (computed only on a cache miss) — that boundary is unaffected.

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_analysis_service -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.services.analysis_service'`

- [ ] **Step 3: Write the implementation**

```python
from app.errors import ValidationError

UNSUPPORTED_VALUE_TYPES = {
    "Private IPv4",
    "Loopback IPv4",
    "Unspecified IPv4",
    "Link-local IPv4",
    "Reserved IPv4",
    "SHA-224",
    "SHA-384",
    "SHA-512",
    "SSDEEP",
}


class AnalysisService:
    """The orchestrator: check cache, on miss validate + fetch from VirusTotal +
    cache the result. This is the single 'analyze one value' entry point both
    the CLI and (later) an API job worker call.

    The cache is namespaced by the CLI-plural value_type ("domains", "ips", ...)
    rather than VirusTotalService's canonical uppercase type, specifically so a
    cache hit never has to call ValidationService.classify() at all - that type
    conversion is only needed on the miss path, right before the VT API call."""

    def __init__(self, validation, virustotal, cache):
        self.validation = validation
        self.virustotal = virustotal
        self.cache = cache

    def analyze(self, value, value_type: str) -> tuple[dict, bool]:
        cache_key = self._cache_key(value)

        cached = self.cache.get(value_type, cache_key)
        if cached is not None:
            return cached, True

        classification = self.validation.classify(value, value_type)
        if not classification or classification in UNSUPPORTED_VALUE_TYPES:
            raise ValidationError(f"Unsupported or invalid {value_type[:-1]}: {value}")

        canonical_type = classification.upper()
        report = self.virustotal.get_report(canonical_type, value)
        self.cache.set(value_type, cache_key, report)
        return report, False

    def _cache_key(self, value) -> str:
        return value[0] if isinstance(value, tuple) else value
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m unittest tests.test_analysis_service -v`
Expected: PASS, 7/7.

- [ ] **Step 5: Commit**

```bash
git add app/services/analysis_service.py tests/test_analysis_service.py
git commit -m "feat: add AnalysisService orchestrator"
```

---

### Task 8: Rewrite `init.py` as a service factory

**Files:**
- Modify: `init.py`
- Modify: `tests/test_init.py`

**Interfaces:**
- Produces: `Initializator(api_key, proxy, case_num).analysis -> AnalysisService`, `.misp -> MispService`, `.output -> OutputHandler` (unchanged), `.client -> vt.Client` (unchanged, still exposed for `close()` in `vt_tools.py`'s cleanup). Drops `.reporter`, `.validator`, `.db_handler` as public attributes (their functionality now lives inside `.analysis`).

- [ ] **Step 1: Write the failing test**

```python
import unittest

from init import Initializator
from app.services.analysis_service import AnalysisService
from app.services.misp_service import MispService
from app.FileHandler.output_to_file import OutputHandler


class InitializatorTests(unittest.TestCase):
    def setUp(self):
        self.init = Initializator("fake-api-key", proxy=None, case_num="000001")

    def tearDown(self):
        self.init.client.close()

    def test_wires_up_all_components(self):
        self.assertTrue(self.init.client)
        self.assertIsInstance(self.init.analysis, AnalysisService)
        self.assertIsInstance(self.init.misp, MispService)
        self.assertIsInstance(self.init.output, OutputHandler)

    def test_stores_constructor_args(self):
        self.assertEqual(self.init.api_key, "fake-api-key")
        self.assertIsNone(self.init.proxy)
        self.assertEqual(self.init.case_num, "000001")
        self.assertEqual(self.init.output.case_num, "000001")

    def test_analysis_service_is_wired_to_the_same_client(self):
        self.assertIs(self.init.analysis.virustotal.vt, self.init.client)

    def test_analysis_service_cache_uses_the_configured_database_file(self):
        self.assertEqual(self.init.analysis.cache.backend.db_path, "vttools.sqlite")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python -m unittest tests.test_init -v`
Expected: FAIL — `AttributeError: 'Initializator' object has no attribute 'analysis'`.

- [ ] **Step 3: Write the implementation**

```python
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
        self.analysis = AnalysisService(
            validation=ValidationService(DataValidator()),
            virustotal=VirusTotalService(self.client),
            cache=ReportCacheService(cache_backend),
        )
        self.misp = MispService()
        self.output = OutputHandler(self.case_num)

        self._display_info(self.client, self.analysis, self.misp, self.output)

    def _init_client(self):
        """Initializes the VirusTotal client."""
        return VirusTotalClient(self.api_key, self.proxy).init_client()

    def _display_info(self, client, analysis, misp, output):
        """Displays information about the initialized components with a clear UI."""

        console.print(Panel(Text("Initialized Components", style="bold magenta"), expand=False))

        components = {
            "VirusTotal Client": client,
            "Analysis Service": analysis,
            "MISP Service": misp,
            "Output Handler": output,
        }

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Component", style="bold white")
        table.add_column("Status", justify="center", style="bold")

        for name, status in components.items():
            status_text = "[green]✅ Initialized[/green]" if status else "[red]❌ Not initialized[/red]"
            table.add_row(name, status_text)

        console.print(table)

        console.print(Panel(Text("Initialization Complete ✅", style="bold green"), expand=False))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python -m unittest tests.test_init -v`
Expected: PASS, 4/4.

- [ ] **Step 5: Commit**

```bash
git add init.py tests/test_init.py
git commit -m "refactor: rewire Initializator to wire the new services"
```

---

### Task 9: Rewrite `vt_tools.py`'s analysis flow to use `AnalysisService`

**Files:**
- Modify: `vt_tools.py`
- Modify: `tests/test_vt_tools.py`

**Interfaces:**
- Consumes: `init.analysis.analyze(value, value_type) -> tuple[dict, bool]` (Task 7/8), `app.errors.ValidationError`/`VirusTotalAPIError`.
- `vt_tools.py`'s CLI surface (arguments, `--help` text, output format, prompts) is unchanged — only the internal implementation of the analyze/cache/report-shaping plumbing changes.
- **A second, real fix bundled into this task, found by tracing the actual data flow during planning (not assumed):** `extract_table_data()` and `output_csv()` currently expect each result to be the *old* triple shape `{"report": ..., "csv_report": [value_object], "rows": [...]}` (they read `result["csv_report"][0]`/`result["csv_report"]`). `VirusTotalService.get_report()` (Task 5) and `AnalysisService.analyze()` (Task 7) return the flat `value_object` dict directly — there is no `"csv_report"` key anymore. Traced where `"rows"` was actually consumed: nowhere in `vt_tools.py` — `process_results()` builds its own rows via `extract_table_data()`, it never reads `result["rows"]`. So dropping the `"rows"` key (already done, implicitly, back in Task 5) loses nothing; `extract_table_data`/`output_csv` just need to stop assuming the `"csv_report"` wrapper exists.

- [ ] **Step 1: Identify exactly what's being replaced**

Deleted from `vt_tools.py`: `get_existing_report`, `value_exists`, `analyze_value`, `validate_value`, the module-level `UNSUPPORTED_VALUE_TYPES` constant. Rewritten: `analyze_values` (drops its `conn`/`DBHandler` setup), `analyze_value_type` (drops the `conn` parameter), `analyze_single_value` (calls `init.analysis.analyze(...)` directly), `extract_table_data` and `output_csv` (read the flat report dict directly instead of a `"csv_report"` wrapper).

- [ ] **Step 2: Write the failing/changed tests first**

In `tests/test_vt_tools.py`: remove `UnsupportedValueTypesTests`, `ValueExistsTests`, `ValidateValueTests` (moved to `test_analysis_service.py`/`test_validation_service.py` in Tasks 4/7) and their now-unused imports. Replace `ExtractTableDataTests`' fixtures (flat dicts, not `{"csv_report": [...]}`-wrapped) and add `AnalyzeSingleValueTests`:

```python
class ExtractTableDataTests(unittest.TestCase):
    def test_headers_are_the_union_of_all_results(self):
        results = [
            {"ip": "8.8.8.8", "malicious_score": 0},
            {"ip": "1.1.1.1", "malicious_score": 5, "extra": "x"},
        ]
        headers, rows = vt_tools.extract_table_data(results)
        self.assertEqual(set(headers), {"ip", "malicious_score", "extra"})

    def test_rows_are_fully_populated_with_final_headers(self):
        results = [
            {"ip": "8.8.8.8", "malicious_score": 0},
            {"ip": "1.1.1.1", "malicious_score": 5, "extra": "x"},
        ]
        headers, rows = vt_tools.extract_table_data(results)
        self.assertEqual(len(rows[0]), len(headers))
        self.assertEqual(len(rows[1]), len(headers))
        row0 = dict(zip(headers, rows[0]))
        row1 = dict(zip(headers, rows[1]))
        self.assertEqual(row0["ip"], "8.8.8.8")
        self.assertEqual(row0["extra"], "")
        self.assertEqual(row1["extra"], "x")


class AnalyzeSingleValueTests(unittest.TestCase):
    def test_cache_hit_reports_one_skipped_value(self):
        init = mock.Mock()
        init.analysis.analyze.return_value = ({"malicious_score": 1}, True)
        results, skipped, errors = vt_tools.analyze_single_value(init, "domains", "example.com")
        self.assertEqual(results, [{"malicious_score": 1}])
        self.assertEqual(skipped, 1)
        self.assertEqual(errors, 0)

    def test_cache_miss_reports_zero_skipped(self):
        init = mock.Mock()
        init.analysis.analyze.return_value = ({"malicious_score": 9}, False)
        results, skipped, errors = vt_tools.analyze_single_value(init, "domains", "example.com")
        self.assertEqual(results, [{"malicious_score": 9}])
        self.assertEqual(skipped, 0)
        self.assertEqual(errors, 0)

    def test_validation_error_counts_as_one_error_no_results(self):
        init = mock.Mock()
        init.analysis.analyze.side_effect = errors_module.ValidationError("invalid")
        results, skipped, errs = vt_tools.analyze_single_value(init, "domains", "not-a-domain")
        self.assertEqual(results, [])
        self.assertEqual(skipped, 0)
        self.assertEqual(errs, 1)

    def test_virustotal_api_error_counts_as_one_error_no_results(self):
        init = mock.Mock()
        init.analysis.analyze.side_effect = errors_module.VirusTotalAPIError("network down")
        results, skipped, errs = vt_tools.analyze_single_value(init, "domains", "example.com")
        self.assertEqual(results, [])
        self.assertEqual(skipped, 0)
        self.assertEqual(errs, 1)
```

Add `from app import errors as errors_module` to `tests/test_vt_tools.py`'s imports.

- [ ] **Step 3: Run tests to verify the new/changed ones fail**

Run: `source .venv/bin/activate && python -m unittest tests.test_vt_tools.AnalyzeSingleValueTests tests.test_vt_tools.ExtractTableDataTests -v`
Expected: `AnalyzeSingleValueTests` FAILs (`analyze_single_value` doesn't accept this call shape yet). `ExtractTableDataTests` currently PASSes against the *old* implementation with the *old* fixture shape — since the fixtures just changed to flat dicts in Step 2, re-running now should FAIL with a `KeyError: 'csv_report'` (proving the old `extract_table_data` really does assume the wrapper, confirming the gap found during planning is real, not hypothetical).

- [ ] **Step 4: Rewrite `vt_tools.py`**

Remove entirely: `get_existing_report`, `value_exists`, `analyze_value`, `validate_value`, the module-level `UNSUPPORTED_VALUE_TYPES` constant.

Replace `analyze_values` with (the only changes from today's version: the `with init.db_handler.create_connection(database) as conn:` wrapper and its `conn is None`/`create_schema` setup are gone — `Initializator.__init__` already opens the cache's connection now — the body is de-indented one level, and the `analyze_value_type(...)` call drops its trailing `conn` argument):

```python
def analyze_values(args: argparse.Namespace, value_types: List[str]) -> None:
    """
    Analyze the values provided by the user through the command-line arguments.

    Parameters:
    args (argparse.Namespace): Command-line arguments.
    value_types (list): List of value types (e.g., "ips", "domains", "urls", "hashes").

    Returns:
    None
    """
    # Load environment variables
    load_dotenv()

    # Initialize necessary parameters
    api_key = get_api_key(args.api_key, args.api_key_file)
    proxy = get_proxy(args.proxy)
    case_id = str(args.case_id or 0).zfill(6)

    init = Initializator(api_key, proxy, case_id)
    quota_saved = 0
    error_values = 0

    # Start the analysis
    start_time = datetime.now()
    if not args.non_interactive:
        console.print("\n[bold blue]Checking for remaining queries...[/bold blue]")
    else:
        logging.info("Checking for remaining queries...")

    remaining_queries = get_remaining_quota(init.api_key, init.proxy, args)
    if remaining_queries == 0:
        if not args.non_interactive:
            console.print(
                "[bold yellow]No queries remaining for this hour.[/bold yellow]"
            )
            console.print("[bold blue]Check your API key before analysis.[/bold blue]")
            return
        else:
            logging.error("No queries remaining for this hour.")
            logging.warning("Check your API key before analysis.")
            return
    if not args.non_interactive:
        console.print(f"Remaining queries for this hour: {remaining_queries}")
    else:
        logging.info(f"Remaining queries for this hour: {remaining_queries}")

    # Retrieve values to analyze
    if args.template_file:
        table = Table(title="Template Types", title_style="bold yellow")
        table.add_column("Key", justify="center", style="cyan", no_wrap=True)
        table.add_column("Type", justify="center", style="magenta")

        for key, value in TEMPLATE_OPTIONS.items():
            table.add_row(key, value)

        console.print(table)

        choice = Prompt.ask(
            "[bold green]Select an option[/bold green]",
            choices=TEMPLATE_OPTIONS.keys(),
            default="1",
        )
        values = ValueReader(args.template_file, args.values).read_template_values(
            TEMPLATE_OPTIONS[choice]
        )
    else:
        values = ValueReader(args.input_file, args.values).read_values()
    if not values:
        if not args.non_interactive:
            console.print("[bold yellow]No values to analyze.[/bold yellow]")
        else:
            logging.warning("No values to analyze.")
        return
    if not args.non_interactive:
        console.print(
            f"[bold blue]This analysis will use {count_iocs(values)} out of your {remaining_queries} hourly quota.[/bold blue]\n"
        )
    else:
        logging.info(
            f"This analysis will use {count_iocs(values)} out of your {remaining_queries} hourly quota."
        )

    if remaining_queries < count_iocs(values):
        if not args.non_interactive:
            console.print(
                f"[bold yellow]Warning:[/bold yellow] You have {remaining_queries} queries left for this hour, but you are trying to analyze {len(values)} values."
            )
            console.print(
                "[bold yellow]Some values may be skipped to avoid exceeding the quota.[/bold yellow]\n"
            )
        else:
            logging.warning(
                f"Warning: You have {remaining_queries} queries left for this hour, but you are trying to analyze {len(values)} values."
            )
            logging.warning("Some values may be skipped to avoid exceeding the quota.")

    # Start the analysis process for each value type
    for value_type in value_types:
        if not values.get(value_type):
            if not args.non_interactive:
                console.print(
                    f"[bold yellow]No {value_type[:-1].upper()} values to analyze.[/bold yellow]"
                )
            else:
                logging.info(f"No {value_type[:-1].upper()} values to analyze.")
            continue
        if not args.non_interactive:
            console.print(
                Panel(
                    Markdown("## Analysis Started"),
                    title=f"[bold green]{value_type[:-1].upper()} Analysis[/bold green]",
                    border_style="green",
                )
            )
        else:
            logging.info(f"Starting {value_type[:-1].upper()} analysis...")

        results, skipped_values, error_values = analyze_value_type(
            init, value_type, values[value_type], remaining_queries
        )
        quota_saved += skipped_values

        if results:
            process_results(init, results, value_type)

    # Post-analysis report
    csv_files_created = list(set(init.output.csvfilescreated))
    quota_final = get_remaining_quota(init.api_key, init.proxy, args)
    if not args.non_interactive:
        if quota_saved == 0:
            console.print(
                "[bold green]Analysis completed. No values were skipped.[/bold green]"
            )
        else:
            console.print(
                f"[bold green]Analysis completed. {quota_saved} values were skipped as they already exist in the database.[/bold green]"
            )

        console.print(
            f"[bold blue]Errors occurred for {error_values} values.[/bold blue]"
        )
        console.print(
            f"[bold yellow]Remaining queries for this hour: {quota_final}[/bold yellow]"
        )
    else:
        if quota_saved == 0:
            logging.info("Analysis completed. No values were skipped.")
        else:
            logging.info(
                f"Analysis completed. {quota_saved} values were skipped as they already exist in the database."
            )

        logging.info(f"Errors occurred for {error_values} values.")
        logging.info(f"Remaining queries for this hour: {quota_final}")

    total_time = datetime.now() - start_time
    if not args.non_interactive:
        console.print(f"[bold blue]Total time taken: {total_time}[/bold blue]")
    else:
        logging.info(f"Total time taken: {total_time}")

    # MISP-related action
    if args.template_file:
        misp_choice(
            case_str=case_id,
            csvfilescreated=csv_files_created,
            template_file=args.template_file,
            template=TEMPLATE_OPTIONS[choice],
        )
    else:
        if args.non_interactive:
            console.print(
                "[bold blue]Non-interactive mode: Skipping MISP integration step.[/bold blue]"
            )
        else:
            misp_choice(case_str=case_id, csvfilescreated=csv_files_created)

    console.print("[bold green]Thank you for using VT Tools! 👍[/bold green]")

    # Close resources
    close_resources(init)


def analyze_value_type(
    init: Initializator, value_type: str, values: List[str], remaining_queries
) -> tuple:
    """Analyze values of a specific type (e.g., hashes, URLs, domains)."""
    results = []
    skipped_values = 0
    error_values = 0

    for value in values:
        if remaining_queries == 0:
            console.print("[bold yellow]No queries remaining for this hour.[/bold yellow]")
            break
        result, skipped, errors = analyze_single_value(init, value_type, value)
        results.extend(result)
        skipped_values += skipped
        error_values += errors

    return results, skipped_values, error_values


def analyze_single_value(init: Initializator, value_type: str, value: str) -> tuple:
    """Analyze a single value via AnalysisService (cache-check + VT fetch + cache-store)."""
    try:
        report, from_cache = init.analysis.analyze(value, value_type)
        if from_cache:
            console.print(f"[bold yellow]Value already exists in LOCAL database: {value}[/bold yellow]")
            return [report], 1, 0
        return [report], 0, 0
    except ValidationError as e:
        console.print(f"[bold red]{e}[/bold red]")
        return [], 0, 1
    except VirusTotalAPIError as e:
        console.print(f"[bold red]Error analyzing {value_type[:-1]}: {value}[/bold red] - {e}")
        return [], 0, 1
```

Replace `extract_table_data` and `output_csv` (both currently assume the old `{"csv_report": [value_object]}` wrapper — `process_results`, which calls both, is unchanged, since it only passes `results`/`value_type` through without touching their shape itself):

```python
def extract_table_data(results: List[Dict]) -> Tuple[List[str], List[List[str]]]:
    """Extract headers and row values directly from the flat report dicts."""

    headers = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        headers.update(result.keys())

    rows = []
    for result in results:
        if not isinstance(result, dict):
            continue
        rows.append(
            [str(result.get(header, "")) for header in headers]
        )

    return list(headers), rows


def output_csv(init: Initializator, results: List[Dict], value_type: str) -> None:
    """Generate and save the CSV report based on the analysis results."""
    try:
        # OutputHandler.output_to_csv expects List[List[Dict]] (each element a
        # 1-item list wrapping one row's dict) - wrap each flat report to match
        # its existing, unchanged interface.
        total_csv_report = [[result] for result in results]

        init.output.output_to_csv(
            total_csv_report,
            f"{value_type[:-1].upper()}" if value_type != "hashes" else "HASH",
        )
    except Exception as e:
        logging.error(f"Error saving CSV report: {e}")
        console.print(f"[bold red]Error saving CSV report: {e}[/bold red]")
```

Add the import: `from app.errors import ValidationError, VirusTotalAPIError` near the top of `vt_tools.py`.

- [ ] **Step 5: Run tests to verify they pass**

```bash
source .venv/bin/activate
python -m unittest tests.test_vt_tools -v
```

Expected: PASS, all of `test_vt_tools.py`'s remaining/new tests green — including `ExtractTableDataTests` against its new flat-dict fixtures.

- [ ] **Step 6: Manual smoke test — confirm CLI behavior is actually unchanged**

```bash
python vt_tools.py --help
```

Expected: identical output to before this task (arguments, descriptions, defaults unchanged — this task touched no `argparse` code).

- [ ] **Step 7: Commit**

```bash
git add vt_tools.py tests/test_vt_tools.py
git commit -m "refactor: vt_tools.py delegates analyze-one-value to AnalysisService"
```

---

### Task 10: Remove the now-dead old implementation and its tests

**Files:**
- Delete: `app/DBHandler/db_handler.py`
- Delete: `app/DBHandler/__init__.py` (if present) and the now-empty `app/DBHandler/` directory
- Delete: `app/VirusTotal/vt_reporter.py`
- Delete: `tests/test_db_handler.py`
- Delete: `tests/test_vt_reporter.py`

**Interfaces:**
- Nothing should import these after Task 9 — this task's job is to confirm that and remove them.

- [ ] **Step 1: Confirm nothing still imports the old modules**

```bash
grep -rn "from app.DBHandler\|import app.DBHandler\|from app.VirusTotal.vt_reporter\|VTReporter\|DBHandler(" --include="*.py" . | grep -v "/.venv/\|__pycache__\|/docs/"
```

Expected: no output. If anything shows up, STOP — a caller was missed in an earlier task and needs fixing before deleting these files, not after.

- [ ] **Step 2: Delete the files**

```bash
git rm app/DBHandler/db_handler.py
git rm tests/test_db_handler.py
git rm tests/test_vt_reporter.py
git rm app/VirusTotal/vt_reporter.py
rmdir app/DBHandler 2>/dev/null || true
```

- [ ] **Step 3: Run the full suite**

```bash
source .venv/bin/activate
ruff check .
python -m unittest discover -s tests -t . -v
```

Expected: `ruff check .` clean; full suite passes with no import errors (confirms Step 1's grep was accurate — nothing was still depending on the deleted files).

- [ ] **Step 4: Commit**

```bash
git commit -m "chore: remove DBHandler and VTReporter, superseded by the new services"
```

---

### Task 11: Full verification pass

**Files:** none (verification only)

- [ ] **Step 1: Full lint + test run from a clean shell**

```bash
cd <worktree>
source .venv/bin/activate
ruff check .
python -m unittest discover -s tests -t . -v
```

Expected: ruff clean, full suite green. Record the final test count for the report (expected to be higher than the 122-test baseline — new service test files added more coverage than the two deleted old test files removed).

- [ ] **Step 2: CLI behavior spot-check**

```bash
python vt_tools.py --help
python vt_tools.py -n -t domains example.com --api_key fake-key-for-this-smoke-test 2>&1 | head -30
```

Expected: `--help` output unchanged from before this plan. The second command will fail at the VT API call (fake key) but should fail the same way it did before this refactor (a clean, formatted error — not a Python traceback from a missing attribute or broken import), confirming the CLI's error-handling path through the new `AnalysisService`/`ValidationError`/`VirusTotalAPIError` plumbing works end-to-end.

- [ ] **Step 3: Confirm the cache actually uses the new schema**

```bash
rm -f vttools.sqlite
python vt_tools.py -n -t domains example.com --api_key fake-key-for-this-smoke-test 2>&1 | tail -5
sqlite3 vttools.sqlite ".schema" 2>/dev/null || python -c "
import sqlite3
conn = sqlite3.connect('vttools.sqlite')
print(conn.execute(\"SELECT sql FROM sqlite_master WHERE type='table'\").fetchall())
"
rm -f vttools.sqlite
```

Expected: schema shows the single `cached_reports` table (with `value_type`, `value`, `report_json`, `cached_at` columns), not the old four-table schema. Clean up the smoke-test database file afterward — it must not be committed.

- [ ] **Step 4: Confirm no stray files, clean working tree**

```bash
git status --short
```

Expected: empty.

- [ ] **Step 5: Report to the user**

No commit for this step. Summarize: final test count, confirmation `vt_tools.py --help` output is byte-identical to before, confirmation the two structural bugs' root cause (duplicated report-shaping) no longer exists in the codebase (only `VirusTotalService` shapes reports; the cache is a pure JSON-blob store), and that this closes out sub-project B1 — B2 (pluggable cache backend + TTL), B3 (API service), B4 (Docker deployment) remain, each needing its own design pass.

---

## Self-Review

**Spec coverage:** all five services from the design doc are covered (Tasks 3-7), the cache-storage redesign (Task 2), the `init.py`/`vt_tools.py` integration (Tasks 8-9), and cleanup (Task 10). The "no migration for existing caches" and "no CLI behavior change" constraints are both explicitly checked in Task 11.

**Placeholder scan:** no TBD/TODO.

**Two real bugs caught and fixed during planning, not left in:**

1. The first draft of `AnalysisService.analyze()` called `ValidationService.classify()` unconditionally before checking the cache, to compute the canonical type needed for the cache key — which meant every cache hit still paid for a classification call, and contradicted the test I'd drafted alongside it (`classify.assert_not_called()` on a cache hit). Traced with a standalone script (outside the plan) before writing the fix in: confirmed the bug reproduces with the first draft, then confirmed the fix (namespace the cache by the CLI-plural `value_type` instead of the canonical type, so cache lookups never need classification) resolves it for both the hit and miss paths. The version in Task 7 is the corrected one; Tasks 8 and 9 were checked against this final signature, not the buggy draft.
2. While writing Task 9, re-read the *actual current* `extract_table_data`/`output_csv` source (not from memory) and found they read `result["csv_report"][0]`/`result["csv_report"]` — the old triple-wrapper `VTReporter.get_report()` used to return. `VirusTotalService.get_report()` (Task 5) and `AnalysisService.analyze()` (Task 7) return the flat report dict directly, with no `"csv_report"` key — so as originally planned, Task 9 would have shipped a `KeyError: 'csv_report'` the first time `process_results()` ran on real data, never caught by any test in the plan as first drafted (no task exercised `extract_table_data` against a flat-dict input). Also traced whether the old `"rows"` key (dropped when `VTReporter.get_rows()` wasn't carried into `VirusTotalService`) was consumed anywhere in `vt_tools.py` — it wasn't (`process_results` builds its own rows via `extract_table_data`) — so dropping it in Task 5 was already correct, only `extract_table_data`/`output_csv` needed updating to match. Task 9's `ExtractTableDataTests` fixtures and `output_csv` implementation are the corrected versions; verified the new `output_csv` wrapping (`[[result] for result in results]`) still satisfies `OutputHandler.output_to_csv`'s existing, unchanged `data[0][0]` access pattern by tracing that function's source too, not just assuming it.

**Type/signature consistency:** `AnalysisService.analyze(value, value_type) -> tuple[dict, bool]` is used identically in Task 7's tests, Task 8's `init.py` wiring, and Task 9's `vt_tools.py` call site. `ValidationService.classify(value, value_type) -> str | None` and `VirusTotalService.get_report(value_type, value) -> dict` signatures match between their defining tasks (4, 5) and their only caller (`AnalysisService` in Task 7). `ReportCacheService.get/set(value_type, value, ...)` matches between Task 3 and its caller in Task 7 — note `value_type` here is the CLI-plural bucket end-to-end (`ReportCacheService`/`SQLiteCacheBackend` are agnostic to what string is used as the namespace key; Task 2/3's own unit tests use canonical-looking example strings like `"DOMAIN"` for their own isolated testing purposes, which doesn't constrain what `AnalysisService` actually passes at runtime).

**Known risk flagged for the executor:** Task 9 is the largest, least mechanically-verifiable task (removing four functions and restructuring `analyze_values`' connection handling in a 700-line file) — its Step 6 manual CLI smoke test exists specifically to catch anything the unit tests wouldn't (argparse wiring, output formatting drift). Task reviewers should weight this task's review more heavily than the others.
