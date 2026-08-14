# vt_tool Frontend v2 (MISP Push + History) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the two capabilities v1 explicitly deferred to `vt-tool-ui`/vt_tool's backend: pushing an analyzed batch of IOCs to MISP, and viewing past analyses (local history, recorded automatically once a batch's results resolve).

**Architecture:** A new backend `HistoryService` (its own raw SQLite connection/table, independent of the report cache's pluggable backend) stores finished batches; four new FastAPI endpoints (`POST /analyses`, `GET /analyses`, `GET /analyses/{id}`, `POST /analyses/{id}/misp-push`) expose save/list/get/push. The MISP push path reuses the CLI's existing `get_misp_event()`/`submit_misp_objects()` functions directly (they already take an `ExpandedPyMISP` instance as a parameter — only their CLI callers are interactive-specific) against the same `MISPURL`/`MISPKEY` server-side env vars the CLI already uses. On the frontend, the Analyze flow auto-saves a batch to history once every item resolves, and a new History section (list + detail pages) lets a user browse and push past batches, sharing the same `KpiCards`/`ResultsTable` components and a new `MispPushControl` the live Analyze results view also uses.

**Tech Stack:** Same as v1 — FastAPI/arq/pydantic backend (Python), React 19 + TypeScript + Vite + MUI + TanStack Query frontend (`vt-tool-ui/`), Vitest + Testing Library + Playwright for tests, `pnpm@9.15.0`, Node `^20.19.0 || >=22.12.0` (host Node may be older — build/test inside `node:22-alpine`, e2e inside `mcr.microsoft.com/playwright:v1.60.0-noble`, exactly as v1's plan established).

## Global Constraints

- MISP credentials (`MISPURL`/`MISPKEY`) stay exactly where they already are — server-side environment variables, read fresh via `os.getenv` at push time, never sent to or stored by the browser. This sub-project adds no new credential handling.
- History storage is an independent, raw `sqlite3` connection to its own table (`analyses`, in the same default `vttools.sqlite` file the cache falls back to) — deliberately NOT the cache's pluggable `SQLAlchemyCacheBackend`/`VT_CACHE_DB_URL` path. See the design spec's binding decision on this.
- Save-to-history is client-driven: the frontend calls `POST /analyses` itself once a batch's results all resolve (`AnalyzePage`'s existing `allResolved` condition). No server-side batch tracking from submission time, no changes to the arq worker.
- The case ID is one field, not two: an optional text field shown at push time, sent as `case_id` to the push endpoint, which both identifies/creates the MISP event AND becomes that analysis's `case_label` in history from then on. A freshly auto-saved (not-yet-pushed) history entry has no label.
- MISP push reuses `get_misp_event()`/`submit_misp_objects()` from `app/MISP/vt_tools2misp.py` directly — no rewrite of MISP submission logic. `MispService.create_object()` (already exists, unchanged) builds each `MISPObject`.
- A partial push is not a failure: an item `create_object` can't build (bad/missing data) is skipped and counted (`skipped_count`), not a hard error for the whole push.
- No auth, no per-user history scoping — one shared list, matching v1's stance and how MISP events are already shared.
- No retention/expiry policy, no edit/delete on history entries (beyond the push flow's own `case_label`/`misp_event_id` side effect), no re-running a past analysis against VT again, no change to `/analyze`'s or `/jobs/{id}`'s existing request/response shape. All out of scope per the design spec.
- Every backend test file in this repo runs via `source .venv/bin/activate && python -W ignore -m unittest discover -s tests -t . -v` from the repo root; `ruff check .` must stay clean. Every frontend command runs inside `node:22-alpine` via Docker (host Node is below the project floor) exactly as v1 established:
  ```bash
  cd vt-tool-ui && docker run --rm -v "$(pwd)":/app -w /app node:22-alpine sh -c "
    npm install -g pnpm@9.15.0 && pnpm install && pnpm test && pnpm run build && pnpm run lint
  "
  ```
  e2e uses `mcr.microsoft.com/playwright:v1.60.0-noble` instead of `node:22-alpine` (Alpine cannot run Playwright's browser install — a real gap v1 hit and fixed once already, don't rediscover it).

---

### Task 1: Promote the MISP attribute mapping to a shared constant

**Files:**
- Modify: `app/services/misp_service.py`
- Modify: `app/MISP/vt_tools2misp.py:11` (import), `app/MISP/vt_tools2misp.py:177-230` (replace the local dict literal)
- Test: `tests/test_misp_service.py`

**Interfaces:**
- Consumes: nothing from other tasks (pure refactor, independent).
- Produces: `ATTRIBUTE_TYPE_MAPPING: dict[str, dict[str, tuple]]` and `OBJECT_NAME_BY_VALUE_TYPE: dict[str, str]`, both importable from `app.services.misp_service` — Task 4's MISP push endpoint imports both by these exact names.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_misp_service.py` (append inside the existing `MispServiceTests` class, or as new top-level test functions in the same file — match whichever the file already uses; the existing class is `unittest.TestCase`-based, so add these as new methods on it):

```python
    def test_object_name_by_value_type_covers_all_four_types(self):
        from app.services.misp_service import OBJECT_NAME_BY_VALUE_TYPE
        self.assertEqual(OBJECT_NAME_BY_VALUE_TYPE, {
            "ips": "ip-port",
            "domains": "domain-ip",
            "urls": "url",
            "hashes": "file",
        })

    def test_attribute_type_mapping_covers_every_object_name_plus_general(self):
        from app.services.misp_service import ATTRIBUTE_TYPE_MAPPING, OBJECT_NAME_BY_VALUE_TYPE
        for object_name in OBJECT_NAME_BY_VALUE_TYPE.values():
            self.assertIn(object_name, ATTRIBUTE_TYPE_MAPPING)
        self.assertIn("general", ATTRIBUTE_TYPE_MAPPING)
        self.assertIn("malicious_score", ATTRIBUTE_TYPE_MAPPING["general"])
        self.assertIn("link", ATTRIBUTE_TYPE_MAPPING["general"])

    def test_attribute_type_mapping_file_entry_matches_hash_report_fields(self):
        from app.services.misp_service import ATTRIBUTE_TYPE_MAPPING
        file_mapping = ATTRIBUTE_TYPE_MAPPING["file"]
        self.assertEqual(file_mapping["sha256"], ("sha256", "sha256", "Payload delivery", False))
        self.assertEqual(file_mapping["meaningful_name"], ("filename", "text", "Payload delivery", False))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source .venv/bin/activate && python -W ignore -m unittest tests.test_misp_service -v`
Expected: FAIL — `ImportError: cannot import name 'OBJECT_NAME_BY_VALUE_TYPE'` (it doesn't exist yet).

- [ ] **Step 3: Add the shared constants to `misp_service.py`**

In `app/services/misp_service.py`, add these two module-level constants right after the existing `FILENAME_PATTERNS` list (before `class MispService:`):

```python
# value_type (as used by the API's AnalyzeItem / HistoryService) -> MISP
# object name. Distinct from FILENAME_PATTERNS above: that regex-detects an
# object type from a CSV filename (CLI-only, via identify_object_type()).
# This maps directly from the type the API already knows - there's no
# filename to sniff in that flow.
OBJECT_NAME_BY_VALUE_TYPE = {
    "ips": "ip-port",
    "domains": "domain-ip",
    "urls": "url",
    "hashes": "file",
}

# object_name -> {report-field -> (misp_attribute_type, misp_type, category, to_ids)}.
# "general" isn't a real MISP object name - its entries (malicious_score, link)
# get merged into every other object type's mapping by callers, since every
# analyzed value has them regardless of type. Shared by both the CLI
# (app/MISP/vt_tools2misp.py's process_and_submit_to_misp) and the API's MISP
# push endpoint - one place owns this mapping, not two independently
# maintained copies. Moved here verbatim from where it used to be defined
# locally inside process_and_submit_to_misp.
ATTRIBUTE_TYPE_MAPPING = {
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
    },
}
```

- [ ] **Step 4: Update `vt_tools2misp.py` to use the shared constant**

In `app/MISP/vt_tools2misp.py`, change the import on line 11 from:

```python
from app.services.misp_service import MispService
```

to:

```python
from app.services.misp_service import ATTRIBUTE_TYPE_MAPPING, MispService
```

Then replace lines 177-230 (the entire local `attribute_type_mapping = { ... }` dict literal, from the opening `attribute_type_mapping = {` through its matching closing `}`) with a single line:

```python
    attribute_type_mapping = ATTRIBUTE_TYPE_MAPPING
```

Everything else in `process_and_submit_to_misp` (the code using `attribute_type_mapping[object_type]`, `attribute_type_mapping["general"]`, etc., starting at the line right after where the dict literal used to end) stays exactly as-is — this is a pure data-source swap, not a logic change.

- [ ] **Step 5: Run tests to verify they pass, and confirm no regression on the CLI's own tests**

Run: `python -W ignore -m unittest tests.test_misp_service -v`
Expected: PASS (all tests, including the 3 new ones).

Then run the CLI's own MISP tests to confirm this refactor changed no observable behavior:
Run: `python -W ignore -m unittest tests.test_misp -v`
Expected: PASS (all pre-existing tests, unchanged).

Then the full suite: `python -W ignore -m unittest discover -s tests -t . -v` and `ruff check .`
Expected: all pass, clean.

- [ ] **Step 6: Commit**

```bash
git add app/services/misp_service.py app/MISP/vt_tools2misp.py tests/test_misp_service.py
git commit -m "refactor: share MISP attribute mapping between CLI and API"
```

---

### Task 2: `HistoryService` — local analysis history storage

**Files:**
- Create: `app/services/history_service.py`
- Test: `tests/test_history_service.py`

**Interfaces:**
- Consumes: nothing from other tasks (standalone, following `SQLiteCacheBackend`'s exact pattern in `app/cache_backends/sqlite_backend.py`).
- Produces: `HistoryService(db_path: str)` with methods `save(items: list[dict], case_label: str | None = None) -> dict`, `list(limit: int, offset: int) -> list[dict]`, `get(analysis_id: str) -> dict | None`, `set_misp_event_id(analysis_id: str, event_id: str, case_label: str | None) -> None`, `close() -> None` — Task 3's endpoints call `save`/`list`/`get`, Task 4's push endpoint calls `get`/`set_misp_event_id`.

- [ ] **Step 1: Write the failing tests**

`tests/test_history_service.py`:

```python
import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from app.services.history_service import HistoryService


class HistoryServiceTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)  # service creates it fresh
        self.service = HistoryService(self.db_path)

    def tearDown(self):
        self.service.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_save_returns_an_id_and_created_at(self):
        result = self.service.save([{"value": "8.8.8.8", "value_type": "ips", "report": {"malicious_score": 0}, "error": None}])
        self.assertIn("id", result)
        self.assertIn("created_at", result)
        self.assertIsNone(result["case_label"])

    def test_save_with_a_case_label(self):
        result = self.service.save([], case_label="incident-42")
        self.assertEqual(result["case_label"], "incident-42")

    def test_get_returns_none_when_absent(self):
        self.assertIsNone(self.service.get("nonexistent-id"))

    def test_save_then_get_round_trips_items(self):
        items = [{"value": "example.com", "value_type": "domains", "report": {"domain": "example.com"}, "error": None}]
        saved = self.service.save(items)
        result = self.service.get(saved["id"])
        self.assertEqual(result["items"], items)
        self.assertEqual(result["case_label"], None)
        self.assertIsNone(result["misp_event_id"])

    def test_list_returns_summaries_newest_first(self):
        first = self.service.save([{"value": "a", "value_type": "domains", "report": None, "error": "x"}])
        second = self.service.save([{"value": "b", "value_type": "ips", "report": None, "error": "x"}, {"value": "c", "value_type": "ips", "report": None, "error": "x"}])
        results = self.service.list(limit=10, offset=0)
        self.assertEqual([r["id"] for r in results], [second["id"], first["id"]])
        self.assertEqual(results[0]["item_count"], 2)
        self.assertEqual(results[1]["item_count"], 1)

    def test_list_respects_limit_and_offset(self):
        for i in range(5):
            self.service.save([{"value": str(i), "value_type": "domains", "report": None, "error": None}])
        page = self.service.list(limit=2, offset=1)
        self.assertEqual(len(page), 2)

    def test_set_misp_event_id_updates_event_id_and_label(self):
        saved = self.service.save([{"value": "a", "value_type": "domains", "report": None, "error": None}])
        self.service.set_misp_event_id(saved["id"], "123", "incident-42")
        result = self.service.get(saved["id"])
        self.assertEqual(result["misp_event_id"], "123")
        self.assertEqual(result["case_label"], "incident-42")

    def test_set_misp_event_id_without_a_case_label_leaves_label_unchanged(self):
        saved = self.service.save([{"value": "a", "value_type": "domains", "report": None, "error": None}], case_label="already-set")
        self.service.set_misp_event_id(saved["id"], "456", None)
        result = self.service.get(saved["id"])
        self.assertEqual(result["misp_event_id"], "456")
        self.assertEqual(result["case_label"], "already-set")


class ThreadSafetyTests(unittest.TestCase):
    """save()/list()/get() must be safe to call concurrently - the API calls
    this from concurrent request handlers, same reasoning as
    SQLiteCacheBackend's own thread-safety tests."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)
        self.service = HistoryService(self.db_path)

    def tearDown(self):
        self.service.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_concurrent_save_and_list_does_not_raise(self):
        errors = []

        def save_and_list(i):
            try:
                self.service.save([{"value": f"v{i}", "value_type": "domains", "report": None, "error": None}])
                self.service.list(limit=5, offset=0)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(save_and_list, range(50)))

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -W ignore -m unittest tests.test_history_service -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.history_service'`.

- [ ] **Step 3: Implement `HistoryService`**

`app/services/history_service.py`:

```python
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    case_label TEXT,
    created_at TEXT NOT NULL,
    items_json TEXT NOT NULL,
    misp_event_id TEXT
);
"""


class HistoryService:
    """Stores and retrieves finished analysis batches for the history
    feature. Deliberately independent of the report cache's pluggable SQL
    backend (VT_CACHE_DB_URL/SQLAlchemyCacheBackend) - always a raw sqlite3
    connection to its own local file, the same simplicity tradeoff the
    cache itself made before SQLAlchemy support was added later as its own
    separate concern.

    check_same_thread=False plus an internal lock, same pattern as
    SQLiteCacheBackend - needed because the API calls this from concurrent
    request handlers."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def save(self, items: list[dict], case_label: str | None = None) -> dict:
        analysis_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO analyses (id, case_label, created_at, items_json, misp_event_id) "
                "VALUES (?, ?, ?, ?, NULL)",
                (analysis_id, case_label, created_at, json.dumps(items)),
            )
            self._conn.commit()
        return {"id": analysis_id, "created_at": created_at, "case_label": case_label}

    def list(self, limit: int, offset: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, case_label, created_at, items_json, misp_event_id "
                "FROM analyses ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            {
                "id": row[0],
                "case_label": row[1],
                "created_at": row[2],
                "item_count": len(json.loads(row[3])),
                "misp_event_id": row[4],
            }
            for row in rows
        ]

    def get(self, analysis_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, case_label, created_at, items_json, misp_event_id "
                "FROM analyses WHERE id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "case_label": row[1],
            "created_at": row[2],
            "items": json.loads(row[3]),
            "misp_event_id": row[4],
        }

    def set_misp_event_id(self, analysis_id: str, event_id: str, case_label: str | None) -> None:
        with self._lock:
            if case_label:
                self._conn.execute(
                    "UPDATE analyses SET misp_event_id = ?, case_label = ? WHERE id = ?",
                    (event_id, case_label, analysis_id),
                )
            else:
                self._conn.execute(
                    "UPDATE analyses SET misp_event_id = ? WHERE id = ?",
                    (event_id, analysis_id),
                )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -W ignore -m unittest tests.test_history_service -v`
Expected: all pass (9 tests).

Then the full suite: `python -W ignore -m unittest discover -s tests -t . -v` and `ruff check .`
Expected: all pass, clean.

- [ ] **Step 5: Commit**

```bash
git add app/services/history_service.py tests/test_history_service.py
git commit -m "feat: add HistoryService for storing finished analysis batches"
```

---

### Task 3: History endpoints — save, list, get

**Files:**
- Modify: `app/api/main.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `HistoryService` from Task 2's `app.services.history_service`.
- Produces: `POST /analyses`, `GET /analyses`, `GET /analyses/{analysis_id}` — Task 4's push endpoint and every frontend task (5 onward) depend on these three existing and matching this exact request/response shape.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_api.py` (new test class; the file already imports `unittest`, `mock`, `TestClient`, `app`, `os`, `tempfile` — reuse those, add an import for `HistoryService`):

```python
from app.services.history_service import HistoryService


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -W ignore -m unittest tests.test_api.HistoryEndpointTests -v`
Expected: FAIL — `AttributeError: 'State' object has no attribute 'history'` (endpoints don't exist yet, `app.state.history` isn't wired).

- [ ] **Step 3: Add the endpoints**

In `app/api/main.py`, add to the imports (after the existing `from app.services.validation_service import ValidationService` line):

```python
from app.services.history_service import HistoryService
```

Also add `Query` to the existing `fastapi` import line — change:
```python
from fastapi import FastAPI, HTTPException, Request
```
to:
```python
from fastapi import FastAPI, HTTPException, Query, Request
```

In the `lifespan` function, add history service setup right after `app.state.redis = await create_pool(...)` and before `yield`:

```python
    app.state.history = HistoryService("vttools.sqlite")
```

And add its cleanup right after `app.state.analysis.cache.backend.close()` (before the `await app.state.redis.aclose()` line):

```python
    app.state.history.close()
```

At the end of the file (after the existing `get_job` function), add:

```python
class AnalysisItem(BaseModel):
    value: str
    value_type: Literal["ips", "domains", "urls", "hashes"]
    report: dict | None = None
    error: str | None = None


class SaveAnalysisRequest(BaseModel):
    case_label: str | None = None
    items: list[AnalysisItem]


@app.post("/analyses")
async def save_analysis(payload: SaveAnalysisRequest, request: Request):
    history: HistoryService = request.app.state.history
    items = [item.model_dump() for item in payload.items]
    return history.save(items, case_label=payload.case_label)


@app.get("/analyses")
async def list_analyses(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    history: HistoryService = request.app.state.history
    return history.list(limit=limit, offset=offset)


@app.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: str, request: Request):
    history: HistoryService = request.app.state.history
    result = history.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result
```

(`Query(..., le=100)` matches the design spec's "capped server-side (max 100) to avoid an accidental unbounded query" requirement, and rejecting an out-of-range `limit` with a 422 is FastAPI/pydantic's standard behavior for a `Query` constraint violation — no extra code needed to enforce it.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -W ignore -m unittest tests.test_api.HistoryEndpointTests -v`
Expected: PASS (6 tests).

Then the full suite: `python -W ignore -m unittest discover -s tests -t . -v` and `ruff check .`
Expected: all pass (including the pre-existing `AnalyzeEndpointTests`/`CorsTests` classes, which don't touch `app.state.history` and so are unaffected), clean.

- [ ] **Step 5: Commit**

```bash
git add app/api/main.py tests/test_api.py
git commit -m "feat: add save/list/get analysis history endpoints"
```

---

### Task 4: MISP push endpoint

**Files:**
- Modify: `app/api/main.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `ATTRIBUTE_TYPE_MAPPING`/`OBJECT_NAME_BY_VALUE_TYPE` (Task 1), `HistoryService.get`/`set_misp_event_id` (Task 2/3), `get_misp_event`/`submit_misp_objects` from `app.MISP.vt_tools2misp` (pre-existing, unchanged).
- Produces: `POST /analyses/{analysis_id}/misp-push` → `{event_id, pushed_count, skipped_count}` — Task 5's `pushToMisp()` API client function calls this exact endpoint/shape.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_api.py`, as a new test class (reuse the existing `HistoryEndpointTests.setUp`/`tearDown` pattern for `app.state.history`; mock `ExpandedPyMISP`/`get_misp_event`/`submit_misp_objects` at their `app.api.main` import location):

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -W ignore -m unittest tests.test_api.MispPushEndpointTests -v`
Expected: FAIL — `404 Not Found` for a route that doesn't exist yet (or an import error if `ExpandedPyMISP`/`get_misp_event`/`submit_misp_objects` aren't importable from `app.api.main` yet).

- [ ] **Step 3: Add the endpoint**

In `app/api/main.py`, add to the imports:

```python
from pymisp import ExpandedPyMISP

from app.MISP.vt_tools2misp import get_misp_event, submit_misp_objects
from app.services.misp_service import ATTRIBUTE_TYPE_MAPPING, MispService, OBJECT_NAME_BY_VALUE_TYPE
```

At the end of the file, after the endpoints from Task 3:

```python
class MispPushRequest(BaseModel):
    case_id: str | None = None


@app.post("/analyses/{analysis_id}/misp-push")
async def push_analysis_to_misp(analysis_id: str, payload: MispPushRequest, request: Request):
    history: HistoryService = request.app.state.history
    analysis = history.get(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    misp_url = os.getenv("MISPURL")
    misp_key = os.getenv("MISPKEY")
    if not misp_url or not misp_key:
        raise HTTPException(status_code=503, detail="MISP is not configured (MISPURL/MISPKEY unset)")

    try:
        misp = ExpandedPyMISP(misp_url, misp_key, False)
        misp_event = get_misp_event(misp, payload.case_id or analysis_id)

        misp_service = MispService()
        misp_objects = []
        skipped_count = 0
        for item in analysis["items"]:
            report = item.get("report")
            object_name = OBJECT_NAME_BY_VALUE_TYPE.get(item["value_type"])
            if not report or object_name is None:
                skipped_count += 1
                continue
            attribute_mapping = {**ATTRIBUTE_TYPE_MAPPING[object_name], **ATTRIBUTE_TYPE_MAPPING["general"]}
            misp_object = misp_service.create_object(report, object_name, attribute_mapping)
            if misp_object is None:
                skipped_count += 1
                continue
            misp_objects.append(misp_object)

        submit_misp_objects(misp, misp_event, misp_objects)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"MISP push failed: {e}")

    pushed_count = len(misp_objects)
    history.set_misp_event_id(analysis_id, str(misp_event.id), payload.case_id)
    return {"event_id": str(misp_event.id), "pushed_count": pushed_count, "skipped_count": skipped_count}
```

(`ExpandedPyMISP(misp_url, misp_key, False)` constructs the connection exactly the way the CLI already does in `app/MISP/vt_tools2misp.py`'s `misp_choice` — hardcoded `False` for TLS verification, not a new decision. `submit_misp_objects` is called once with every successfully-built object, matching the CLI's own `process_and_submit_to_misp` pattern — build everything first, one submission call — rather than once per item, which would mean one `misp.update_event()` round trip per item instead of one for the whole batch.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -W ignore -m unittest tests.test_api.MispPushEndpointTests -v`
Expected: PASS (5 tests).

Then the full suite: `python -W ignore -m unittest discover -s tests -t . -v` and `ruff check .`
Expected: all pass, clean.

- [ ] **Step 5: Commit**

```bash
git add app/api/main.py tests/test_api.py
git commit -m "feat: add MISP push endpoint for saved analyses"
```

---

### Task 5: Frontend API client types/functions + history hooks

**Files:**
- Modify: `vt-tool-ui/src/api/endpoints.ts`
- Create: `vt-tool-ui/src/features/analyze/hooks/useSaveAnalysis.ts`
- Create: `vt-tool-ui/src/features/history/hooks/useAnalysisHistory.ts`
- Create: `vt-tool-ui/src/features/history/hooks/useAnalysis.ts`
- Create: `vt-tool-ui/src/features/history/hooks/useMispPush.ts`
- Test: `vt-tool-ui/src/api/__tests__/endpoints.test.ts` (extend)
- Test: `vt-tool-ui/src/features/analyze/hooks/__tests__/useSaveAnalysis.test.tsx`
- Test: `vt-tool-ui/src/features/history/hooks/__tests__/useAnalysisHistory.test.tsx`
- Test: `vt-tool-ui/src/features/history/hooks/__tests__/useAnalysis.test.tsx`
- Test: `vt-tool-ui/src/features/history/hooks/__tests__/useMispPush.test.tsx`

**Interfaces:**
- Consumes: `client` from `../client` (existing), `IocType`/`Report` types (existing).
- Produces: `AnalysisItemPayload`, `SaveAnalysisRequest`, `SaveAnalysisResponse`, `AnalysisSummary`, `AnalysisDetail`, `MispPushResult` types and `saveAnalysis()`, `listAnalyses()`, `getAnalysis()`, `pushToMisp()` functions from `src/api/endpoints.ts`; `useSaveAnalysis()`, `useAnalysisHistory(limit?, offset?)`, `useAnalysis(id: string | undefined)`, `useMispPush(analysisId: string)` hooks — every later frontend task (6-9) imports these by these exact names.

- [ ] **Step 1: Write the failing tests**

Append to `vt-tool-ui/src/api/__tests__/endpoints.test.ts`:

```ts
describe("saveAnalysis", () => {
  it("posts the batch and returns the saved record", async () => {
    const spy = vi.spyOn(client, "post").mockResolvedValue({
      data: { id: "abc123", created_at: "2026-08-14T00:00:00Z", case_label: null },
    });

    const result = await saveAnalysis({ items: [{ value: "8.8.8.8", value_type: "ips", report: null, error: null }] });

    expect(spy).toHaveBeenCalledWith("/analyses", {
      items: [{ value: "8.8.8.8", value_type: "ips", report: null, error: null }],
    });
    expect(result).toEqual({ id: "abc123", created_at: "2026-08-14T00:00:00Z", case_label: null });
  });
});

describe("listAnalyses", () => {
  it("gets /analyses with pagination params and returns the summaries", async () => {
    const spy = vi.spyOn(client, "get").mockResolvedValue({
      data: [{ id: "abc123", case_label: null, created_at: "2026-08-14T00:00:00Z", item_count: 1, misp_event_id: null }],
    });

    const result = await listAnalyses(10, 5);

    expect(spy).toHaveBeenCalledWith("/analyses", { params: { limit: 10, offset: 5 } });
    expect(result).toHaveLength(1);
  });
});

describe("getAnalysis", () => {
  it("gets the analysis by id and returns the full detail", async () => {
    const spy = vi.spyOn(client, "get").mockResolvedValue({
      data: { id: "abc123", case_label: null, created_at: "2026-08-14T00:00:00Z", items: [], misp_event_id: null },
    });

    const result = await getAnalysis("abc123");

    expect(spy).toHaveBeenCalledWith("/analyses/abc123");
    expect(result.id).toBe("abc123");
  });
});

describe("pushToMisp", () => {
  it("posts the case id and returns the push result", async () => {
    const spy = vi.spyOn(client, "post").mockResolvedValue({
      data: { event_id: "42", pushed_count: 1, skipped_count: 0 },
    });

    const result = await pushToMisp("abc123", "incident-1");

    expect(spy).toHaveBeenCalledWith("/analyses/abc123/misp-push", { case_id: "incident-1" });
    expect(result).toEqual({ event_id: "42", pushed_count: 1, skipped_count: 0 });
  });
});
```

(Add `saveAnalysis, listAnalyses, getAnalysis, pushToMisp` to this file's existing `import { analyze, getJob, health } from "../endpoints";` line.)

`vt-tool-ui/src/features/analyze/hooks/__tests__/useSaveAnalysis.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useSaveAnalysis } from "../useSaveAnalysis";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useSaveAnalysis", () => {
  it("calls saveAnalysis() with the given request", async () => {
    const spy = vi.spyOn(endpoints, "saveAnalysis").mockResolvedValue({
      id: "abc123",
      created_at: "2026-08-14T00:00:00Z",
      case_label: null,
    });

    const { result } = renderHook(() => useSaveAnalysis(), { wrapper });
    result.current.mutate({ items: [{ value: "8.8.8.8", value_type: "ips", report: null, error: null }] });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({ items: [{ value: "8.8.8.8", value_type: "ips", report: null, error: null }] });
    expect(result.current.data?.id).toBe("abc123");
  });
});
```

`vt-tool-ui/src/features/history/hooks/__tests__/useAnalysisHistory.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useAnalysisHistory } from "../useAnalysisHistory";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useAnalysisHistory", () => {
  it("fetches the analysis list", async () => {
    const spy = vi.spyOn(endpoints, "listAnalyses").mockResolvedValue([
      { id: "abc123", case_label: null, created_at: "2026-08-14T00:00:00Z", item_count: 1, misp_event_id: null },
    ]);

    const { result } = renderHook(() => useAnalysisHistory(), { wrapper });

    await waitFor(() => expect(result.current.data).toHaveLength(1));
    expect(spy).toHaveBeenCalledWith(20, 0);
  });
});
```

`vt-tool-ui/src/features/history/hooks/__tests__/useAnalysis.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useAnalysis } from "../useAnalysis";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useAnalysis", () => {
  it("is disabled when id is undefined", () => {
    const spy = vi.spyOn(endpoints, "getAnalysis");
    const { result } = renderHook(() => useAnalysis(undefined), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });

  it("fetches the analysis when id is given", async () => {
    vi.spyOn(endpoints, "getAnalysis").mockResolvedValue({
      id: "abc123", case_label: null, created_at: "2026-08-14T00:00:00Z", items: [], misp_event_id: null,
    });

    const { result } = renderHook(() => useAnalysis("abc123"), { wrapper });

    await waitFor(() => expect(result.current.data?.id).toBe("abc123"));
  });
});
```

`vt-tool-ui/src/features/history/hooks/__tests__/useMispPush.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useMispPush } from "../useMispPush";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useMispPush", () => {
  it("calls pushToMisp() with the analysis id and the given case id", async () => {
    const spy = vi.spyOn(endpoints, "pushToMisp").mockResolvedValue({ event_id: "42", pushed_count: 1, skipped_count: 0 });

    const { result } = renderHook(() => useMispPush("abc123"), { wrapper });
    result.current.mutate("incident-1");

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith("abc123", "incident-1");
    expect(result.current.data?.event_id).toBe("42");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test` (inside `node:22-alpine`, from `vt-tool-ui/`)
Expected: FAIL — the new endpoint functions/hooks don't exist yet.

- [ ] **Step 3: Extend `endpoints.ts`**

Append to `vt-tool-ui/src/api/endpoints.ts` (after the existing `health()` function):

```ts
export interface AnalysisItemPayload {
  value: string;
  value_type: IocType;
  report: Report | null;
  error: string | null;
}

export interface SaveAnalysisRequest {
  case_label?: string;
  items: AnalysisItemPayload[];
}

export interface SaveAnalysisResponse {
  id: string;
  created_at: string;
  case_label: string | null;
}

export interface AnalysisSummary {
  id: string;
  case_label: string | null;
  created_at: string;
  item_count: number;
  misp_event_id: string | null;
}

export interface AnalysisDetail {
  id: string;
  case_label: string | null;
  created_at: string;
  items: AnalysisItemPayload[];
  misp_event_id: string | null;
}

export interface MispPushResult {
  event_id: string;
  pushed_count: number;
  skipped_count: number;
}

export async function saveAnalysis(request: SaveAnalysisRequest): Promise<SaveAnalysisResponse> {
  const response = await client.post<SaveAnalysisResponse>("/analyses", request);
  return response.data;
}

export async function listAnalyses(limit = 20, offset = 0): Promise<AnalysisSummary[]> {
  const response = await client.get<AnalysisSummary[]>("/analyses", { params: { limit, offset } });
  return response.data;
}

export async function getAnalysis(id: string): Promise<AnalysisDetail> {
  const response = await client.get<AnalysisDetail>(`/analyses/${id}`);
  return response.data;
}

export async function pushToMisp(id: string, caseId?: string): Promise<MispPushResult> {
  const response = await client.post<MispPushResult>(`/analyses/${id}/misp-push`, { case_id: caseId });
  return response.data;
}
```

- [ ] **Step 4: Implement the hooks**

`vt-tool-ui/src/features/analyze/hooks/useSaveAnalysis.ts`:

```ts
import { useMutation } from "@tanstack/react-query";
import { saveAnalysis, type SaveAnalysisRequest } from "../../../api/endpoints";

export function useSaveAnalysis() {
  return useMutation({
    mutationFn: (request: SaveAnalysisRequest) => saveAnalysis(request),
  });
}
```

`vt-tool-ui/src/features/history/hooks/useAnalysisHistory.ts`:

```ts
import { useQuery } from "@tanstack/react-query";
import { listAnalyses } from "../../../api/endpoints";

export function useAnalysisHistory(limit = 20, offset = 0) {
  return useQuery({
    queryKey: ["analyses", limit, offset],
    queryFn: () => listAnalyses(limit, offset),
  });
}
```

`vt-tool-ui/src/features/history/hooks/useAnalysis.ts`:

```ts
import { useQuery } from "@tanstack/react-query";
import { getAnalysis } from "../../../api/endpoints";

export function useAnalysis(id: string | undefined) {
  return useQuery({
    queryKey: ["analysis", id],
    queryFn: () => getAnalysis(id as string),
    enabled: id !== undefined,
    retry: false,
  });
}
```

(`retry: false` matters for Task 8's "not found" test: without it, TanStack Query's default 3-retry behavior on a rejected query would make that test flaky/slow. It's also just correct behavior — a 404 on "fetch this one analysis by id" isn't a transient failure worth retrying, unlike `useAnalysisHistory`'s list query, which keeps its default retry behavior.)

`vt-tool-ui/src/features/history/hooks/useMispPush.ts`:

```ts
import { useMutation } from "@tanstack/react-query";
import { pushToMisp } from "../../../api/endpoints";

export function useMispPush(analysisId: string) {
  return useMutation({
    mutationFn: (caseId?: string) => pushToMisp(analysisId, caseId),
  });
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (56 previous + 9 new = 65). Then `pnpm run build` and `pnpm run lint` both clean.

- [ ] **Step 6: Commit**

```bash
git add vt-tool-ui/src/api/endpoints.ts vt-tool-ui/src/api/__tests__/endpoints.test.ts vt-tool-ui/src/features/analyze/hooks/useSaveAnalysis.ts vt-tool-ui/src/features/analyze/hooks/__tests__/useSaveAnalysis.test.tsx vt-tool-ui/src/features/history/
git commit -m "feat: add history/MISP-push API client functions and hooks"
```

---

### Task 6: `MispPushControl` shared component

**Files:**
- Create: `vt-tool-ui/src/features/history/components/MispPushControl.tsx`
- Test: `vt-tool-ui/src/features/history/components/__tests__/MispPushControl.test.tsx`

**Interfaces:**
- Consumes: `useMispPush` from Task 5's `../hooks/useMispPush`.
- Produces: `MispPushControl` (props: `analysisId: string`, `mispEventId: string | null`) — Task 8's `AnalysisDetailPage` and Task 9's `AnalyzePage` both render this identically.

- [ ] **Step 1: Write the failing tests**

`vt-tool-ui/src/features/history/components/__tests__/MispPushControl.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import MispPushControl from "../MispPushControl";
import * as endpoints from "../../../../api/endpoints";

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient();
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("MispPushControl", () => {
  it("shows the case-id field and push button when not yet pushed", () => {
    renderWithClient(<MispPushControl analysisId="abc123" mispEventId={null} />);
    expect(screen.getByLabelText(/case id/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /push to misp/i })).toBeInTheDocument();
  });

  it("shows the already-pushed state directly when mispEventId is set and nothing was pushed this session", () => {
    renderWithClient(<MispPushControl analysisId="abc123" mispEventId="42" />);
    expect(screen.getByText(/pushed as misp event #42/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /push to misp/i })).not.toBeInTheDocument();
  });

  it("pushes with the entered case id and shows the result", async () => {
    const spy = vi.spyOn(endpoints, "pushToMisp").mockResolvedValue({ event_id: "42", pushed_count: 3, skipped_count: 1 });
    renderWithClient(<MispPushControl analysisId="abc123" mispEventId={null} />);

    await userEvent.type(screen.getByLabelText(/case id/i), "incident-1");
    await userEvent.click(screen.getByRole("button", { name: /push to misp/i }));

    await waitFor(() => expect(screen.getByText(/pushed as misp event #42/i)).toBeInTheDocument());
    expect(screen.getByText(/3 pushed, 1 skipped/i)).toBeInTheDocument();
    expect(spy).toHaveBeenCalledWith("abc123", "incident-1");
  });

  it("shows an inline error when the push fails", async () => {
    vi.spyOn(endpoints, "pushToMisp").mockRejectedValue(new Error("MISP push failed: connection refused"));
    renderWithClient(<MispPushControl analysisId="abc123" mispEventId={null} />);

    await userEvent.click(screen.getByRole("button", { name: /push to misp/i }));

    expect(await screen.findByText(/connection refused/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test`
Expected: FAIL — `../MispPushControl` doesn't exist.

- [ ] **Step 3: Implement `MispPushControl.tsx`**

`vt-tool-ui/src/features/history/components/MispPushControl.tsx`:

```tsx
import { useState } from "react";
import { Alert, Button, Stack, TextField, Typography } from "@mui/material";
import { useMispPush } from "../hooks/useMispPush";

interface MispPushControlProps {
  analysisId: string;
  mispEventId: string | null;
}

export default function MispPushControl({ analysisId, mispEventId }: MispPushControlProps) {
  const [caseId, setCaseId] = useState("");
  const { mutate, data, isPending, isError, error } = useMispPush(analysisId);

  if (data) {
    return (
      <Typography>
        Pushed as MISP event #{data.event_id} ({data.pushed_count} pushed, {data.skipped_count} skipped)
      </Typography>
    );
  }

  if (mispEventId) {
    return <Typography>Pushed as MISP event #{mispEventId}</Typography>;
  }

  return (
    <Stack direction="row" spacing={2} alignItems="center">
      <TextField
        label="Case ID (optional)"
        size="small"
        value={caseId}
        onChange={(e) => setCaseId(e.target.value)}
      />
      <Button variant="contained" disabled={isPending} onClick={() => mutate(caseId || undefined)}>
        Push to MISP
      </Button>
      {isError && (
        <Alert severity="error">
          {error instanceof Error ? error.message : "Failed to push to MISP."}
        </Alert>
      )}
    </Stack>
  );
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (65 previous + 4 new = 69). Then `pnpm run build` and `pnpm run lint` both clean.

- [ ] **Step 5: Commit**

```bash
git add vt-tool-ui/src/features/history/components/
git commit -m "feat: add shared MispPushControl component"
```

---

### Task 7: `HistoryPage` — analysis list

**Files:**
- Create: `vt-tool-ui/src/pages/HistoryPage.tsx`
- Modify: `vt-tool-ui/src/app/router.tsx`
- Test: `vt-tool-ui/src/pages/__tests__/HistoryPage.test.tsx`

**Interfaces:**
- Consumes: `useAnalysisHistory` from Task 5's `../features/history/hooks/useAnalysisHistory`.
- Produces: `HistoryPage` component, wired at route `/history` with a nav link — nothing later depends on its exports beyond the route existing (Task 8's detail links target `/history/:id`, which this task's table rows already link to).

- [ ] **Step 1: Write the failing test**

`vt-tool-ui/src/pages/__tests__/HistoryPage.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import HistoryPage from "../HistoryPage";
import * as endpoints from "../../api/endpoints";

function renderPage() {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("HistoryPage", () => {
  it("lists past analyses with a link to each detail page", async () => {
    vi.spyOn(endpoints, "listAnalyses").mockResolvedValue([
      { id: "abc123", case_label: "incident-1", created_at: "2026-08-14T00:00:00Z", item_count: 3, misp_event_id: "42" },
      { id: "def456", case_label: null, created_at: "2026-08-13T00:00:00Z", item_count: 1, misp_event_id: null },
    ]);

    renderPage();

    expect(await screen.findByText("incident-1")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "incident-1" })).toHaveAttribute("href", "/history/abc123");
    expect(screen.getByText(/pushed as event #42/i)).toBeInTheDocument();
    expect(screen.getByText(/not pushed/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test`
Expected: FAIL — `../HistoryPage` doesn't exist.

- [ ] **Step 3: Implement `HistoryPage.tsx`**

`vt-tool-ui/src/pages/HistoryPage.tsx`:

```tsx
import { Link as RouterLink } from "react-router-dom";
import { Link, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";
import { useAnalysisHistory } from "../features/history/hooks/useAnalysisHistory";

export default function HistoryPage() {
  const { data, isPending, isError } = useAnalysisHistory();

  return (
    <>
      <Typography variant="h4" gutterBottom>
        History
      </Typography>
      {isPending && <Typography>Loading…</Typography>}
      {isError && <Typography color="error">Failed to load history.</Typography>}
      {data && (
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Case</TableCell>
              <TableCell>Date</TableCell>
              <TableCell>Items</TableCell>
              <TableCell>MISP</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.map((analysis) => (
              <TableRow key={analysis.id}>
                <TableCell>
                  <Link component={RouterLink} to={`/history/${analysis.id}`}>
                    {analysis.case_label ?? "—"}
                  </Link>
                </TableCell>
                <TableCell>{new Date(analysis.created_at).toLocaleString()}</TableCell>
                <TableCell>{analysis.item_count}</TableCell>
                <TableCell>
                  {analysis.misp_event_id ? `Pushed as event #${analysis.misp_event_id}` : "Not pushed"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </>
  );
}
```

- [ ] **Step 4: Wire the route and nav link**

In `vt-tool-ui/src/app/router.tsx`, add the import:

```tsx
import HistoryPage from "../pages/HistoryPage";
```

Add a nav link in the `Toolbar`, right after the existing Analyze link and before the Settings link:

```tsx
          <Link component={RouterLink} to="/history" color="inherit">
            History
          </Link>
```

Add the route inside `<Routes>`, after the `/` route:

```tsx
          <Route path="/history" element={<HistoryPage />} />
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (69 previous + 1 new = 70). Then `pnpm run build` and `pnpm run lint` both clean.

- [ ] **Step 6: Commit**

```bash
git add vt-tool-ui/src/pages/HistoryPage.tsx vt-tool-ui/src/pages/__tests__/HistoryPage.test.tsx vt-tool-ui/src/app/router.tsx
git commit -m "feat: add history list page"
```

---

### Task 8: `AnalysisDetailPage` — one past analysis

**Files:**
- Create: `vt-tool-ui/src/pages/AnalysisDetailPage.tsx`
- Modify: `vt-tool-ui/src/app/router.tsx`
- Test: `vt-tool-ui/src/pages/__tests__/AnalysisDetailPage.test.tsx`

**Interfaces:**
- Consumes: `useAnalysis` (Task 5), `MispPushControl` (Task 6), `KpiCards`/`ResultsTable` (existing, from v1's Task 7).
- Produces: `AnalysisDetailPage` component, wired at route `/history/:id` — the plan's final task (10, e2e) navigates here.

- [ ] **Step 1: Write the failing test**

`vt-tool-ui/src/pages/__tests__/AnalysisDetailPage.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import AnalysisDetailPage from "../AnalysisDetailPage";
import * as endpoints from "../../api/endpoints";

function renderAt(path: string) {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/history/:id" element={<AnalysisDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AnalysisDetailPage", () => {
  it("renders a past analysis's KPI cards, results, and push control", async () => {
    vi.spyOn(endpoints, "getAnalysis").mockResolvedValue({
      id: "abc123",
      case_label: "incident-1",
      created_at: "2026-08-14T00:00:00Z",
      items: [
        { value: "8.8.8.8", value_type: "ips", report: { malicious_score: 0, total_scans: 90 }, error: null },
      ],
      misp_event_id: null,
    });

    renderAt("/history/abc123");

    expect(await screen.findByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("CLEAN")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /push to misp/i })).toBeInTheDocument();
  });

  it("shows a not-found state when the analysis doesn't exist", async () => {
    vi.spyOn(endpoints, "getAnalysis").mockRejectedValue(new Error("Request failed with status code 404"));

    renderAt("/history/does-not-exist");

    expect(await screen.findByText(/analysis not found/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test`
Expected: FAIL — `../AnalysisDetailPage` doesn't exist.

- [ ] **Step 3: Implement `AnalysisDetailPage.tsx`**

`vt-tool-ui/src/pages/AnalysisDetailPage.tsx`:

```tsx
import { useParams } from "react-router-dom";
import { Stack, Typography } from "@mui/material";
import KpiCards from "../features/analyze/components/KpiCards";
import ResultsTable from "../features/analyze/components/ResultsTable";
import MispPushControl from "../features/history/components/MispPushControl";
import { useAnalysis } from "../features/history/hooks/useAnalysis";

export default function AnalysisDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, isPending, isError } = useAnalysis(id);

  if (isPending) {
    return <Typography>Loading…</Typography>;
  }
  if (isError || !data) {
    return <Typography color="error">Analysis not found.</Typography>;
  }

  const rows = data.items.map((item) => ({
    value: item.value,
    report: item.report,
    error: item.error ?? undefined,
  }));

  return (
    <Stack spacing={3}>
      <Typography variant="h4">
        {data.case_label ?? "Analysis"} — {new Date(data.created_at).toLocaleString()}
      </Typography>
      <KpiCards reports={rows.map((row) => row.report)} />
      <ResultsTable rows={rows} />
      <MispPushControl analysisId={data.id} mispEventId={data.misp_event_id} />
    </Stack>
  );
}
```

- [ ] **Step 4: Wire the route**

In `vt-tool-ui/src/app/router.tsx`, add the import:

```tsx
import AnalysisDetailPage from "../pages/AnalysisDetailPage";
```

Add the route inside `<Routes>`, after the `/history` route added in Task 7:

```tsx
          <Route path="/history/:id" element={<AnalysisDetailPage />} />
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (70 previous + 2 new = 72). Then `pnpm run build` and `pnpm run lint` both clean.

- [ ] **Step 6: Commit**

```bash
git add vt-tool-ui/src/pages/AnalysisDetailPage.tsx vt-tool-ui/src/pages/__tests__/AnalysisDetailPage.test.tsx vt-tool-ui/src/app/router.tsx
git commit -m "feat: add analysis detail page"
```

---

### Task 9: Wire auto-save and MISP push into `AnalyzePage`

**Files:**
- Modify: `vt-tool-ui/src/pages/AnalyzePage.tsx`
- Modify: `vt-tool-ui/src/pages/__tests__/AnalyzePage.test.tsx`

**Interfaces:**
- Consumes: `useSaveAnalysis` (Task 5), `MispPushControl` (Task 6).
- Produces: the complete, usable v2 application — no later task depends on this beyond Task 10 (e2e) driving it.

- [ ] **Step 1: Update the existing tests**

`AnalyzePage.test.tsx`'s existing `beforeEach` mocks `endpoints.health` but not `endpoints.saveAnalysis` — once `AnalyzePage` calls it automatically on every resolved batch, the 4 existing tests (from v1 plus the polish round) would each trigger a real, unmocked `saveAnalysis()` call. Add this mock to the shared `beforeEach` so every existing test's save call is handled cleanly:

In `vt-tool-ui/src/pages/__tests__/AnalyzePage.test.tsx`, change the `beforeEach` from:

```tsx
  beforeEach(() => {
    setApiKey("fake-key");
    vi.spyOn(endpoints, "health").mockResolvedValue({ status: "ok" });
  });
```

to:

```tsx
  beforeEach(() => {
    setApiKey("fake-key");
    vi.spyOn(endpoints, "health").mockResolvedValue({ status: "ok" });
    vi.spyOn(endpoints, "saveAnalysis").mockResolvedValue({
      id: "saved-analysis-1",
      created_at: "2026-08-14T00:00:00Z",
      case_label: null,
    });
  });
```

Then add one new test to the same `describe("AnalyzePage", ...)` block, after the existing `"resolves a mixed queued/invalid response..."` test:

```tsx
  it("auto-saves the batch to history once resolved, and shows the push-to-MISP control", async () => {
    const saveSpy = vi.spyOn(endpoints, "saveAnalysis");
    vi.spyOn(endpoints, "analyze").mockResolvedValue([
      { status: "hit", report: { domain: "example.com", malicious_score: 0, total_scans: 90 } },
    ]);

    renderPage();

    await userEvent.type(screen.getByRole("textbox", { name: /paste iocs/i }), "example.com");
    await userEvent.click(screen.getByRole("button", { name: /review/i }));
    await userEvent.click(screen.getByRole("button", { name: /^analyze$/i }));

    await waitFor(() => expect(screen.getByText("CLEAN")).toBeInTheDocument());
    await waitFor(() => expect(saveSpy).toHaveBeenCalledWith({
      items: [{ value: "example.com", value_type: "domains", report: { domain: "example.com", malicious_score: 0, total_scans: 90 }, error: null }],
    }));
    expect(screen.getByRole("button", { name: /push to misp/i })).toBeInTheDocument();
  });
```

- [ ] **Step 2: Run tests to verify the new test fails**

Run: `pnpm test`
Expected: FAIL — `saveSpy` is never called (`AnalyzePage` doesn't save yet), and there's no "Push to MISP" button.

- [ ] **Step 3: Update `AnalyzePage.tsx`**

Replace the full contents of `vt-tool-ui/src/pages/AnalyzePage.tsx` with:

```tsx
import { useEffect, useState } from "react";
import { Alert, Button, Link, Stack, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router-dom";
import IocInput from "../features/analyze/components/IocInput";
import IocReviewTable from "../features/analyze/components/IocReviewTable";
import KpiCards from "../features/analyze/components/KpiCards";
import ResultsTable from "../features/analyze/components/ResultsTable";
import { useAnalyze } from "../features/analyze/hooks/useAnalyze";
import { useJobsPolling } from "../features/analyze/hooks/useJobPolling";
import { useSaveAnalysis } from "../features/analyze/hooks/useSaveAnalysis";
import MispPushControl from "../features/history/components/MispPushControl";
import type { ClassifiedIoc } from "../features/analyze/lib/classifyIoc";
import type { AnalyzeResult, IocType, Report } from "../api/endpoints";
import { getApiKey } from "../shared/lib/apiKeyStorage";

interface ResolvedRow {
  value: string;
  value_type: IocType;
  report: Report | null;
  error?: string;
}

export default function AnalyzePage() {
  const [reviewItems, setReviewItems] = useState<ClassifiedIoc[] | null>(null);
  const [submittedItems, setSubmittedItems] = useState<ClassifiedIoc[] | null>(null);
  const [hasSaved, setHasSaved] = useState(false);
  const { mutate, data: results, isError, error, reset } = useAnalyze();
  const { mutate: saveAnalysis, data: savedAnalysis, isError: saveFailed } = useSaveAnalysis();
  const hasApiKey = Boolean(getApiKey());

  // Job ids for whichever results came back "queued" - this array's length
  // changes between renders (0 before submit, N after), which is exactly why
  // useJobsPolling (TanStack's useQueries under the hood) is used here rather
  // than calling useJobPolling once per item in a loop - React forbids a
  // hook's call count varying across renders.
  const queuedJobIds = (results ?? [])
    .filter((result): result is Extract<AnalyzeResult, { status: "queued" }> => result.status === "queued")
    .map((result) => result.job_id);
  const jobQueries = useJobsPolling(queuedJobIds);

  const rows: ResolvedRow[] = (results ?? []).map((result, index) => {
    const item = submittedItems![index];
    const value_type = item.type as IocType;
    if (result.status === "hit") {
      return { value: item.value, value_type, report: result.report };
    }
    if (result.status === "invalid") {
      return { value: item.value, value_type, report: null, error: result.error };
    }
    const jobIndex = queuedJobIds.indexOf(result.job_id);
    const jobQuery = jobQueries[jobIndex];
    const jobData = jobQuery?.data;
    const jobError = jobQuery?.error;
    return {
      value: item.value,
      value_type,
      report: jobData?.report ?? null,
      error: jobData?.error ?? (jobError instanceof Error ? jobError.message : undefined),
    };
  });

  const allResolved =
    submittedItems !== null &&
    results !== undefined &&
    rows.every((row) => row.report !== null || row.error !== undefined);

  // Once every item resolves, the batch is saved to history automatically -
  // no user action needed. hasSaved guards against re-saving on every
  // re-render once allResolved stays true (e.g. a job-polling refetch).
  useEffect(() => {
    if (allResolved && !hasSaved) {
      setHasSaved(true);
      saveAnalysis({
        items: rows.map((row) => ({
          value: row.value,
          value_type: row.value_type,
          report: row.report,
          error: row.error ?? null,
        })),
      });
    }
  }, [allResolved, hasSaved, rows, saveAnalysis]);

  const handleSubmit = (items: ClassifiedIoc[]) => {
    setSubmittedItems(items);
    mutate(items.map((item) => ({ value: item.value, value_type: item.type as IocType })));
  };

  const handleReset = () => {
    setReviewItems(null);
    setSubmittedItems(null);
    setHasSaved(false);
    reset();
  };

  return (
    <Stack spacing={3}>
      <Typography variant="h4">Analyze</Typography>
      {!hasApiKey && (
        <Alert severity="warning">
          No VirusTotal API key set. <Link component={RouterLink} to="/settings">Add one in Settings</Link> before
          analyzing.
        </Alert>
      )}
      {!reviewItems && <IocInput onParsed={setReviewItems} />}
      {reviewItems && (
        <>
          {results === undefined ? (
            <>
              {isError && (
                <Alert severity="error">
                  {error instanceof Error ? error.message : "Failed to submit analysis. Please try again."}
                </Alert>
              )}
              <IocReviewTable items={reviewItems} onChange={setReviewItems} onSubmit={handleSubmit} />
            </>
          ) : (
            <>
              <KpiCards reports={rows.map((row) => row.report)} />
              <ResultsTable rows={rows} />
              {!allResolved && <Typography>Waiting for results…</Typography>}
              {saveFailed && <Typography color="warning.main">Couldn't save to history.</Typography>}
              {allResolved && savedAnalysis && (
                <MispPushControl analysisId={savedAnalysis.id} mispEventId={null} />
              )}
            </>
          )}
          <Button variant="outlined" onClick={handleReset} sx={{ alignSelf: "flex-start" }}>
            New analysis
          </Button>
        </>
      )}
    </Stack>
  );
}
```

(`IocType` is imported from `../api/endpoints` instead of inlining the `"ips" | "domains" | "urls" | "hashes"` union everywhere, replacing the ad-hoc casts v1 had — same 4 values, just named instead of repeated three times.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (72 previous + 1 new = 73). Then `pnpm run build` and `pnpm run lint` both clean.

- [ ] **Step 5: Commit**

```bash
git add vt-tool-ui/src/pages/AnalyzePage.tsx vt-tool-ui/src/pages/__tests__/AnalyzePage.test.tsx
git commit -m "feat: auto-save analyses to history and add MISP push to results"
```

---

### Task 10: Playwright e2e coverage + full verification pass

**Files:**
- Modify: `vt-tool-ui/e2e/analyze.spec.ts`

**Interfaces:**
- Consumes: the complete v2 application from Tasks 1-9.
- Produces: nothing consumed by a later task — this is the plan's final task.

- [ ] **Step 1: Extend the e2e spec**

Append to `vt-tool-ui/e2e/analyze.spec.ts` (add a second `test(...)` block after the existing one; keep the existing test unchanged):

```ts
test("submit -> auto-save -> push to MISP -> visible in history, against a mocked API", async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("vt-tool-ui:api-key", "fake-key");
  });

  await page.route("**/health", (route) => route.fulfill({ json: { status: "ok" } }));
  await page.route("**/analyze", (route) =>
    route.fulfill({
      json: [{ status: "hit", report: { domain: "example.com", malicious_score: 0, total_scans: 90 } }],
    }),
  );
  await page.route("**/analyses", (route) => {
    if (route.request().method() === "POST") {
      return route.fulfill({
        json: { id: "analysis-1", created_at: "2026-08-14T00:00:00Z", case_label: null },
      });
    }
    return route.fulfill({
      json: [{ id: "analysis-1", case_label: null, created_at: "2026-08-14T00:00:00Z", item_count: 1, misp_event_id: "42" }],
    });
  });
  await page.route("**/analyses/analysis-1", (route) =>
    route.fulfill({
      json: {
        id: "analysis-1",
        case_label: "incident-1",
        created_at: "2026-08-14T00:00:00Z",
        items: [{ value: "example.com", value_type: "domains", report: { domain: "example.com", malicious_score: 0, total_scans: 90 }, error: null }],
        misp_event_id: "42",
      },
    }),
  );
  await page.route("**/analyses/analysis-1/misp-push", (route) =>
    route.fulfill({ json: { event_id: "42", pushed_count: 1, skipped_count: 0 } }),
  );

  await page.goto("/");
  await page.getByRole("textbox", { name: /paste iocs/i }).fill("example.com");
  await page.getByRole("button", { name: /review/i }).click();
  await page.getByRole("button", { name: /^analyze$/i }).click();

  await expect(page.getByText("CLEAN")).toBeVisible();
  await page.getByRole("button", { name: /push to misp/i }).click();
  await expect(page.getByText(/pushed as misp event #42/i)).toBeVisible();

  await page.getByRole("link", { name: "History" }).click();
  await expect(page.getByRole("link", { name: "incident-1" })).toBeVisible();
  await page.getByRole("link", { name: "incident-1" }).click();
  await expect(page.getByText("example.com")).toBeVisible();
  await expect(page.getByText(/pushed as misp event #42/i)).toBeVisible();
});
```

- [ ] **Step 2: Run the e2e suite for real**

```bash
cd vt-tool-ui
docker run --rm -v "$(pwd)":/app -w /app mcr.microsoft.com/playwright:v1.60.0-noble sh -c "
  npm install -g pnpm@9.15.0 &&
  pnpm install &&
  pnpm run build &&
  pnpm run test:e2e
"
```

Expected: both e2e tests pass (2/2) — Playwright starts the preview server itself per `playwright.config.ts`'s `webServer` block.

- [ ] **Step 3: Full verification pass — everything, one more time, from a clean state**

```bash
cd vt-tool-ui
docker run --rm -v "$(pwd)":/app -w /app node:22-alpine sh -c "
  npm install -g pnpm@9.15.0 &&
  pnpm install &&
  pnpm run lint &&
  pnpm test &&
  pnpm run build
"
cd ../deployment
python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml')); yaml.safe_load(open('compose_apps.yaml')); print('valid YAML')"
cd ..
source .venv/bin/activate
ruff check .
python -W ignore -m unittest discover -s tests -t . -v
```

Expected: frontend lint clean, 73/73 vitest tests passing, frontend build clean; both compose YAML files parse; backend ruff clean, all unittest tests passing (199 from v1 + 3 from Task 1 + 9 from Task 2 + 6 from Task 3 + 5 from Task 4 = 222).

- [ ] **Step 4: Commit**

```bash
git add vt-tool-ui/e2e/analyze.spec.ts
git commit -m "test: add e2e coverage for save-to-history and MISP push"
```

- [ ] **Step 5: Report to the user**

No commit for this step. Summarize: final test counts (frontend 73 vitest + 2 e2e; backend 222 unittest), confirmation the new endpoints work end to end against a real MISP-push code path (mocked `ExpandedPyMISP`, not a real MISP instance — no real MISP server exists in this environment to verify against for real, same reasoning as v1 never standing up a real VT account in CI), and a reminder that a real end-to-end MISP push (an actual reachable MISP instance with real `MISPURL`/`MISPKEY`) has not been exercised by this plan and should be smoke-tested manually against a real MISP instance before this is relied on in production.

---

## Self-Review

**Spec coverage:** local history recorded automatically on resolve (Task 9) ✅. Push from the results view right after analyzing, and identically from history (Task 6 shared component, used by both Task 8 and Task 9) ✅. Single optional case-ID field doubling as MISP event id and history label (Task 4's `case_id` → `set_misp_event_id`, Task 6's UI) ✅. MISP push reuses `get_misp_event`/`submit_misp_objects` directly, no rewrite (Task 4) ✅. Partial push reports `skipped_count`, not a hard failure (Task 4) ✅. History storage independent of the cache's pluggable backend (Task 2, raw `sqlite3`, ignores `VT_CACHE_DB_URL`) ✅. No auth/no retention policy/no edit-delete — none of these were built, matching Out of Scope ✅. `/analyze`/`/jobs/{id}` untouched — confirmed no task modifies those handlers ✅.

**Placeholder scan:** no TBD/TODO; every step has complete, real code.

**Type/signature consistency:** `AnalysisItem`/`SaveAnalysisRequest` (Task 3, backend) match `AnalysisItemPayload`/`SaveAnalysisRequest` (Task 5, frontend) field-for-field (`value`, `value_type`, `report`, `error`). `HistoryService.save/list/get/set_misp_event_id` (Task 2) are called with matching signatures in Task 3/4's endpoints. `useMispPush(analysisId: string)` (Task 5) matches `MispPushControl`'s (Task 6) internal usage and both its callers' (`AnalysisDetailPage` Task 8, `AnalyzePage` Task 9) `analysisId`/`mispEventId` prop names. `IocType` (existing, re-exported from `api/endpoints.ts`) is used identically across Tasks 5, 6, 9 instead of Task 9 re-inlining the `"ips" | "domains" | "urls" | "hashes"` union v1 had duplicated three times.

**Cumulative test counts recomputed from the actual test blocks written in each task** (not estimated): backend +3 (Task 1) +9 (Task 2) +6 (Task 3) +5 (Task 4) = 199 (v1) + 23 = 222. Frontend +9 (Task 5) +4 (Task 6) +1 (Task 7) +2 (Task 8) +1 (Task 9) = 56 (v1 final) + 17 = 73, +1 new e2e spec (2 total e2e).

**Scope discipline:** no task touches `/analyze`'s or `/jobs/{id}`'s request/response shape. No task adds authentication or per-user scoping. No task adds edit/delete endpoints for history entries, or a retention/expiry mechanism. `HistoryService` deliberately does not use `SQLAlchemyCacheBackend`/`VT_CACHE_DB_URL` — confirmed as a binding decision, not an oversight, and reflected consistently in Task 2's docstring and Task 3's `HistoryService("vttools.sqlite")` construction (a plain path string, no `VT_CACHE_DB_URL` read anywhere in this plan).
