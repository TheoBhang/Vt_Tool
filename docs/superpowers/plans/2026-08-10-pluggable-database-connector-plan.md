# Pluggable Database Connector (Sub-project B3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users point vt_tool's report cache at any SQL database via a `VT_CACHE_DB_URL` connection string, through one new SQLAlchemy-backed `CacheBackend` implementation, without touching the existing SQLite path.

**Architecture:** A new `SQLAlchemyCacheBackend` implements the same `CacheBackend` Protocol `SQLiteCacheBackend` already satisfies, using SQLAlchemy Core (not the ORM) against the same 4-column `cached_reports` schema. `init.py` picks between the two backends based on whether `VT_CACHE_DB_URL` is set; `ReportCacheService` and everything above it is untouched.

**Tech Stack:** SQLAlchemy Core (new dependency) for dialect-agnostic SQL. stdlib `unittest`/`unittest.mock` for tests, `sqlite:///`-style URLs through the real SQLAlchemy engine for CI (no external DB server needed).

## Global Constraints

- stdlib `unittest` + `unittest.mock` only — no pytest.
- `ruff check .` must stay clean (rule set: E4, E7, E9, F).
- SQL databases only — no MongoDB, Redis, or other non-SQL stores.
- `SQLiteCacheBackend` is not modified in this plan — it stays the zero-config default, exactly as it is today.
- One new dependency: `sqlalchemy`. No specific DB driver (`psycopg2`, `PyMySQL`, etc.) is bundled — users install their own for whichever database they choose.
- Upserts use insert-then-update-on-conflict, not dialect-specific `ON CONFLICT`/`ON DUPLICATE KEY` SQL.
- No CI infrastructure for real Postgres/MySQL servers — tests run `SQLAlchemyCacheBackend` against `sqlite:///`-style URLs through the real SQLAlchemy engine.
- `VT_CACHE_DB_URL` is read per-`Initializator`-instantiation (inside `__init__`), not as a module-level constant — same rationale as B2's `VT_CACHE_TTL_HOURS`: a module-level constant computed once at import time would not pick up a per-test env var override via `mock.patch.dict(os.environ, ...)`.
- No `vt_tools.py`/CLI-surface changes — `--help` output must be unchanged when this plan is done.
- No migration of existing SQLite cache data into a newly-configured external database, and no `CacheError` wiring — both explicitly out of scope per the design spec (`docs/superpowers/specs/2026-08-10-pluggable-database-connector-design.md`).

---

### Task 1: `SQLAlchemyCacheBackend`

**Files:**
- Modify: `requirements.txt` (add `sqlalchemy`)
- Create: `app/cache_backends/sqlalchemy_backend.py`
- Test: `tests/test_sqlalchemy_backend.py`

**Interfaces:**
- Produces: `SQLAlchemyCacheBackend(db_url: str)` with `get(value_type: str, value: str) -> tuple[dict, str] | None`, `set(value_type: str, value: str, report: dict) -> None`, `close() -> None` — the exact same shape `SQLiteCacheBackend` and the `CacheBackend` Protocol (`app/cache_backends/__init__.py`, already merged from B2) already define.
- Consumes: nothing new. This task is standalone — nothing in the existing codebase constructs `SQLAlchemyCacheBackend` yet, so this task cannot break anything else. `init.py` wiring is Task 2.

- [ ] **Step 1: Add the new dependency**

Add `sqlalchemy` to `requirements.txt` (append as a new line, matching the file's existing one-package-per-line style with no version pin):

```
prettytable
vt-py
python-dotenv
pymisp
rich
validators
tldextract
sqlalchemy
```

Install it into the worktree's venv:

```bash
source .venv/bin/activate
pip install sqlalchemy
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_sqlalchemy_backend.py`:

```python
import os
import tempfile
import unittest

import vt

from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend


class SQLAlchemyCacheBackendTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)  # backend creates it fresh
        self.backend = SQLAlchemyCacheBackend(f"sqlite:///{self.db_path}")

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

    def test_matches_the_cache_backend_tuple_contract(self):
        # ReportCacheService depends on the (dict, str) shape, not on which
        # backend produced it - confirm this backend honors it exactly like
        # SQLiteCacheBackend does.
        self.backend.set("URL", "http://example.com", {"url": "http://example.com"})
        result = self.backend.get("URL", "http://example.com")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], dict)
        self.assertIsInstance(result[1], str)


class SetWithRealVtObjectAttributesTests(unittest.TestCase):
    """Same regression class as tests/test_sqlite_backend.py's - a real
    vt.Object's attributes include datetime (any *_date field) and
    WhistleBlowerDict (any nested-dict field, a collections.UserDict, not a
    dict subclass), neither JSON-serializable by default. This backend uses
    the identical json.dumps(..., default=...) handling; this test exists so
    a copy-paste slip in that handling is caught here too, not just in the
    SQLite backend's own test file."""

    def test_set_does_not_raise_on_datetime_and_whistleblower_dict_fields(self):
        backend = SQLAlchemyCacheBackend("sqlite:///:memory:")
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

- [ ] **Step 3: Run the tests to verify they fail**

Run: `source .venv/bin/activate && python -m unittest tests.test_sqlalchemy_backend -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.cache_backends.sqlalchemy_backend'`, since the file doesn't exist yet.

- [ ] **Step 4: Implement `SQLAlchemyCacheBackend`**

Create `app/cache_backends/sqlalchemy_backend.py`:

```python
import json
from collections.abc import Mapping
from datetime import datetime, timezone

import sqlalchemy
from sqlalchemy.exc import IntegrityError


class SQLAlchemyCacheBackend:
    """SQLAlchemy Core implementation of the report-cache backend: same
    contract as SQLiteCacheBackend, but works against any SQL database
    SQLAlchemy supports via a connection URL. No report-shaping logic here -
    that's VirusTotalService's job alone, same as SQLiteCacheBackend."""

    def __init__(self, db_url: str):
        self.engine = sqlalchemy.create_engine(db_url)
        self.metadata = sqlalchemy.MetaData()
        self.table = sqlalchemy.Table(
            "cached_reports",
            self.metadata,
            sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
            sqlalchemy.Column("value_type", sqlalchemy.String, nullable=False),
            sqlalchemy.Column("value", sqlalchemy.String, nullable=False),
            sqlalchemy.Column("report_json", sqlalchemy.Text, nullable=False),
            sqlalchemy.Column("cached_at", sqlalchemy.String, nullable=False),
            sqlalchemy.UniqueConstraint("value_type", "value", name="uq_value_type_value"),
        )
        self.metadata.create_all(self.engine)

    def get(self, value_type: str, value: str) -> tuple[dict, str] | None:
        stmt = sqlalchemy.select(self.table.c.report_json, self.table.c.cached_at).where(
            self.table.c.value_type == value_type,
            self.table.c.value == value,
        )
        with self.engine.connect() as conn:
            row = conn.execute(stmt).fetchone()
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
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    self.table.insert().values(
                        value_type=value_type,
                        value=value,
                        report_json=report_json,
                        cached_at=cached_at,
                    )
                )
        except IntegrityError:
            # engine.begin()'s context manager already rolled back and closed
            # the failed connection when the exception propagated out of the
            # `with` block above, so this starts a fresh connection/transaction
            # rather than reusing one that may be in an aborted state.
            with self.engine.begin() as conn:
                conn.execute(
                    self.table.update()
                    .where(
                        self.table.c.value_type == value_type,
                        self.table.c.value == value,
                    )
                    .values(report_json=report_json, cached_at=cached_at)
                )

    def close(self) -> None:
        self.engine.dispose()
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_sqlalchemy_backend -v`
Expected: PASS, 7/7 (6 in `SQLAlchemyCacheBackendTests`, 1 in `SetWithRealVtObjectAttributesTests`).

- [ ] **Step 6: Run the full suite and ruff**

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
ruff check .
```

Expected: full suite passes (this new file is additive — nothing existing constructs `SQLAlchemyCacheBackend` yet, so nothing else can have broken), ruff clean.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt app/cache_backends/sqlalchemy_backend.py tests/test_sqlalchemy_backend.py
git commit -m "feat: add SQLAlchemyCacheBackend for any SQL database"
```

---

### Task 2: Wire `VT_CACHE_DB_URL` into `init.py`

**Files:**
- Modify: `init.py`
- Modify: `.env.example`
- Test: `tests/test_init.py`

**Interfaces:**
- Consumes: `SQLAlchemyCacheBackend(db_url: str)` (Task 1).
- Produces: `Initializator` reads `VT_CACHE_DB_URL` from the environment on every construction; if set, uses `SQLAlchemyCacheBackend(db_url)` as the cache backend; if unset, uses `SQLiteCacheBackend(DATABASE_FILE)` exactly as before.

- [ ] **Step 1: Write the failing tests**

Add these imports to `tests/test_init.py` (alongside the existing ones):

```python
from app.cache_backends.sqlite_backend import SQLiteCacheBackend
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
```

Add these two test methods to `InitializatorTests`:

```python
    def test_uses_sqlite_backend_when_db_url_is_unset(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("VT_CACHE_DB_URL", None)
            init = Initializator("fake-api-key", proxy=None, case_num="000001")
            try:
                self.assertIsInstance(init.analysis.cache.backend, SQLiteCacheBackend)
            finally:
                init.client.close()

    def test_uses_sqlalchemy_backend_when_db_url_is_set(self):
        with mock.patch.dict(os.environ, {"VT_CACHE_DB_URL": "sqlite:///:memory:"}):
            init = Initializator("fake-api-key", proxy=None, case_num="000001")
            try:
                self.assertIsInstance(init.analysis.cache.backend, SQLAlchemyCacheBackend)
            finally:
                init.client.close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `source .venv/bin/activate && python -m unittest tests.test_init -v`
Expected: `test_uses_sqlite_backend_when_db_url_is_unset` PASSes already (current behavior is unconditionally `SQLiteCacheBackend`). `test_uses_sqlalchemy_backend_when_db_url_is_set` FAILs — `init.py` doesn't read `VT_CACHE_DB_URL` yet, so the backend is still `SQLiteCacheBackend` regardless of the env var, and the `assertIsInstance` check fails. Confirm this is the actual failure reason before proceeding.

- [ ] **Step 3: Wire the env var into `Initializator.__init__`**

In `init.py`, add the import and change the cache-backend construction line:

```python
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
```

(add alongside the existing `from app.cache_backends.sqlite_backend import SQLiteCacheBackend` import)

Replace this line inside `__init__`:

```python
        cache_backend = SQLiteCacheBackend(DATABASE_FILE)
```

with:

```python
        db_url = os.getenv("VT_CACHE_DB_URL")
        cache_backend = SQLAlchemyCacheBackend(db_url) if db_url else SQLiteCacheBackend(DATABASE_FILE)
```

(everything else in `__init__` — the `cache_ttl` line, the `AnalysisService(...)` construction, `_display_info`, etc. — is unchanged.)

- [ ] **Step 4: Update `.env.example`**

Add a line for the new variable after the existing `VT_CACHE_TTL_HOURS=` entry, matching the file's blank-line-separated style:

```
VTAPIKEY=

MISPURL=

MISPSSLVERIFY= False

MISPKEY=

PROXY=

VT_CACHE_TTL_HOURS=

VT_CACHE_DB_URL=
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `source .venv/bin/activate && python -m unittest tests.test_init -v`
Expected: PASS, 8/8.

- [ ] **Step 6: Run the full suite and ruff**

```bash
source .venv/bin/activate
python -m unittest discover -s tests -t . -v
ruff check .
```

Expected: full suite passes, ruff clean.

- [ ] **Step 7: Commit**

```bash
git add init.py .env.example tests/test_init.py
git commit -m "feat: make cache database pluggable via VT_CACHE_DB_URL"
```

---

### Task 3: Full verification pass

**Files:** none (verification only)

- [ ] **Step 1: Full lint + test run from a clean shell**

```bash
cd <worktree>
source .venv/bin/activate
ruff check .
python -m unittest discover -s tests -t . -v
```

Expected: ruff clean, full suite green. Record the final test count for the report (expect the pre-B3 count plus 7 from Task 1's new test file plus 2 from Task 2's additions).

- [ ] **Step 2: CLI behavior spot-check — confirm `--help` is unchanged**

No task in this plan touches `vt_tools.py`. Confirm that's actually true:

```bash
git log --oneline -- vt_tools.py | head -5
```

Expected: the most recent commit touching `vt_tools.py` predates this plan's first commit. Then run `python vt_tools.py --help` once and visually confirm the full argument list is intact.

- [ ] **Step 3: Manual sanity check — confirm the SQLAlchemy backend works end-to-end through the real cache stack**

```bash
python3 -c "
from datetime import timedelta
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend
from app.services.cache_service import ReportCacheService

backend = SQLAlchemyCacheBackend('sqlite:///:memory:')
service = ReportCacheService(backend, ttl=timedelta(hours=24))

service.set('domains', 'example.com', {'domain': 'example.com', 'malicious_score': 0})
result = service.get('domains', 'example.com')
assert result is not None, 'expected a hit'
assert result['domain'] == 'example.com', 'expected the round-tripped report back'
print('SQLAlchemyCacheBackend through ReportCacheService: HIT with correct data (expected)')

backend.close()
"
```

Expected: the print statement executes with no `AssertionError` — proves the new backend works through the real `ReportCacheService` (TTL policy included), not just in isolation.

- [ ] **Step 4: Confirm `VT_CACHE_DB_URL` actually switches the backend via a real `Initializator`**

```bash
VT_CACHE_DB_URL="sqlite:///:memory:" python3 -c "
from init import Initializator
from app.cache_backends.sqlalchemy_backend import SQLAlchemyCacheBackend

init = Initializator('fake-api-key', proxy=None, case_num='000001')
assert isinstance(init.analysis.cache.backend, SQLAlchemyCacheBackend), 'expected SQLAlchemyCacheBackend'
print('VT_CACHE_DB_URL correctly selects SQLAlchemyCacheBackend (expected)')
init.client.close()
"
```

Expected: prints the confirmation line with no `AssertionError`.

- [ ] **Step 5: Confirm no stray files, clean working tree**

```bash
git status --short
```

Expected: empty (the manual smoke tests above don't write any file to disk — both use `sqlite:///:memory:` URLs).

- [ ] **Step 6: Report to the user**

No commit for this step. Summarize: final test count, confirmation `vt_tools.py --help` is unchanged, confirmation both manual end-to-end checks passed, and that this closes out sub-project B3. Note explicitly that B4 (the API service + job queue, previously bundled into what B1's original decomposition called "B3") remains, needing its own design/plan cycle, and that non-SQL databases and DB-driver bundling were deliberately deferred per this plan's Global Constraints.

---

## Self-Review

**Spec coverage:** `SQLAlchemyCacheBackend` via SQLAlchemy Core, same `CacheBackend` contract (Task 1) ✅. `SQLiteCacheBackend` left untouched — no task modifies `app/cache_backends/sqlite_backend.py` ✅. Env-var-driven selection, `VT_CACHE_DB_URL` read per-instantiation (Task 2) ✅. One new dependency, no bundled DB driver — only `sqlalchemy` added to `requirements.txt`, no `psycopg2`/`PyMySQL`/etc. added anywhere ✅. Insert-then-update-on-conflict upsert (Task 1, Step 4's `set()`) ✅. Tests run against `sqlite:///` URLs through the real engine, no external DB server needed (Task 1 & 2's tests) ✅. `.env.example` documents the new variable (Task 2, Step 4) ✅.

**Placeholder scan:** no TBD/TODO; every step shows complete code.

**Type/signature consistency:** `SQLAlchemyCacheBackend(db_url: str)` with `get(value_type: str, value: str) -> tuple[dict, str] | None` / `set(value_type: str, value: str, report: dict) -> None` / `close() -> None` (Task 1) matches exactly what `init.py` constructs and what `ReportCacheService` (unchanged, from B2) already expects from any `CacheBackend`. Task 2's `db_url = os.getenv("VT_CACHE_DB_URL")` / `SQLAlchemyCacheBackend(db_url) if db_url else SQLiteCacheBackend(DATABASE_FILE)` uses the same constructor signature Task 1 defines.

**One implementation-level refinement beyond the design doc's illustrative sketch, noted here:** the design doc's `set()` sketch didn't specify transaction handling around the insert-then-update path. This plan's Task 1 Step 4 uses two separate `with self.engine.begin() as conn:` blocks (one for the insert attempt, a second fresh one for the update on `IntegrityError`) rather than reusing one connection across the exception boundary. Reusing a single connection would risk carrying an aborted-transaction state into the subsequent `UPDATE` on databases (like Postgres) that require an explicit rollback before any further statement on a connection whose transaction failed — `engine.begin()`'s context manager already performs that rollback and closes the connection when the exception propagates out of its `with` block, so starting a fresh `with self.engine.begin()` for the update is the correct, portable way to recover cleanly. This doesn't change the design's intent (try-insert-then-update-on-conflict); it's the specific implementation of "on conflict" needed to make that portable across dialects, which the design doc left to implementation.
