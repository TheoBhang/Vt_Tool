# Core Library Extraction (Sub-project B1) — Design

**Date:** 2026-08-06
**Status:** Approved by user, ready for implementation plan.

## Goal

Extract vt_tool's business logic (validate → check cache → query VirusTotal → shape report → cache → return) out of `vt_tools.py` and the `DBHandler`/`VTReporter` classes into a small set of service classes with no dependency on the terminal (no `Rich` console, no `argparse`, no interactive prompts). This is sub-project B1 of a larger four-part effort (B1 core library → B2 pluggable/TTL cache → B3 API service with a job queue → B4 Docker deployment), each a separate design/plan cycle. B1 is foundational: B2 needs the `CacheBackend` seam it creates, B3 needs the CLI-independent services it creates.

This also permanently fixes the root cause behind two bugs found and fixed earlier this session: `VTReporter` and `DBHandler` each independently re-implemented report-shaping logic (one from a live API object, one from raw SQL columns), and the two implementations silently drifted out of sync with each other and with the table schema. B1 makes report-shaping happen in exactly one place.

## Decisions made during brainstorming (binding, not open for re-litigation during implementation)

- **Service-oriented, class-based design**, explicit user request: five narrow service classes (Validation, VirusTotal, ReportCache, Misp, Analysis-orchestrator) rather than free functions or a single god-object.
- **Cache stores an already-shaped report as JSON**, not one column per field. The cache becomes a pure store/retrieve with zero shaping logic — there is nothing left in it to drift out of sync with `VirusTotalService`.
- **One unified `cached_reports` table** replaces the four near-identical `urls`/`hashes`/`ips`/`domains` tables. Confirmed nothing in the current code does per-column SQL filtering that the unified shape would break.
- **`cached_at` column added now**, even though B1 does not enforce TTL (that's B2's job) — avoids a second schema migration later for something already planned.
- **No migration for existing `vttools.sqlite` files.** New schema, fresh table. It's a cache — the cost of a miss is re-querying VirusTotal (and spending quota) for values already seen before, which is acceptable and simpler than writing a one-time migration for data that isn't a system of record.
- **`ReportCacheService` depends on a `CacheBackend` interface**, with `SQLiteCacheBackend` as B1's only implementation — this is the seam B2's `PostgresCacheBackend` slots into later without touching `ReportCacheService` or its callers.
- **Services raise typed exceptions, never print.** `AnalysisError` base, with `ValidationError`, `VirusTotalAPIError`, `CacheError` subclasses. The CLI layer (and, later, the API layer) is the only place that turns an exception into console output or an HTTP response.
- **The "ratio of empty fields" cache-miss heuristic stays**, now correctly working (fixed earlier this session), but is expected to be retired once B2 adds real TTL-based expiry — noting this so B2's design doesn't need to rediscover it.

## Architecture

```
vt_tools.py (CLI)          [future] api/ (B3, not built yet)
       \                          /
        \                        /
         AnalysisService (orchestrator)
          |        |         |
   Validation  VirusTotal  ReportCache -> CacheBackend -> SQLiteCacheBackend
   Service     Service     Service
                  |
             MispService (separate call path, not part of the analyze-one-value flow)
```

`AnalysisService.analyze(value, value_type) -> AnalysisResult`: check `ReportCacheService` for a fresh hit; on hit, return it. On miss, `ValidationService` classifies the value (raises `ValidationError` if unsupported), `VirusTotalService` fetches and shapes the report (raises `VirusTotalAPIError` on failure), `ReportCacheService` stores it, return it. This single method is what `vt_tools.py` calls today and what a B3 API job worker will call tomorrow.

## Components

### `ValidationService`

Wraps today's `DataValidator` (`app/DataHandler/validator.py`, stays where it is) plus the free helper functions (`get_service_name`, `get_port_from_service_name`, `extract_ip_address`, `get_url_details`, also staying in `validator.py`). `ValidationService` is a thin class over these — the existing validation logic itself isn't being rewritten, just given a service-class entry point (`classify(value) -> str | None`) that `AnalysisService` calls instead of reaching into `DataValidator` directly.

### `VirusTotalService` (`app/services/virustotal_service.py`, replaces `app/VirusTotal/vt_reporter.py`'s `VTReporter`)

Owns the VirusTotal API call (via the existing `VirusTotalClient`, unchanged in `app/VirusTotal/vt_client.py`) and *all* report-shaping. This absorbs `VTReporter`'s `create_report`/`populate_*`/`get_report` methods essentially as-is (the logic itself was correct — it's the *second* implementation in `DBHandler` that was buggy) — the class is renamed and relocated, not rewritten from scratch. Returns a plain `dict` (or the `AnalysisResult` dataclass from `app/models.py` — implementer's call during planning, whichever is less churn) shaped exactly like today's `value_object`.

### `ReportCacheService` + `CacheBackend` (`app/services/cache_service.py`, `app/cache_backends/sqlite_backend.py`)

```python
class CacheBackend(Protocol):
    def get(self, value_type: str, value: str) -> dict | None: ...
    def set(self, value_type: str, value: str, report: dict) -> None: ...
```

`ReportCacheService` wraps a `CacheBackend` and owns the "ratio of empty fields counts as a miss" heuristic (today's `DBHandler.exists()` logic, moved here, bug already fixed). It does NOT know how to turn a report into SQL columns — that's the backend's problem, and `SQLiteCacheBackend`'s problem is trivial now: `json.dumps`/`json.loads` a blob column, no per-field mapping.

`SQLiteCacheBackend` replaces `app/DBHandler/db_handler.py` entirely: one table,

```sql
CREATE TABLE IF NOT EXISTS cached_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value_type TEXT NOT NULL,
    value TEXT NOT NULL,
    report_json TEXT NOT NULL,
    cached_at TEXT NOT NULL,
    UNIQUE(value_type, value)
);
```

### `MispService` (`app/services/misp_service.py`)

The non-interactive core pulled out of `app/MISP/vt_tools2misp.py`: `create_misp_object`, `identify_object_type`, `get_attribute_mapping`, `process_and_submit_to_misp`'s actual submission logic — i.e., everything that doesn't call `Prompt.ask`. `vt_tools2misp.py` keeps `misp_choice`, the CSV/template-file reading, and the interactive prompts, calling into `MispService` for the actual object-building/submission work.

### `AnalysisService` (`app/services/analysis_service.py`)

The orchestrator described above. Constructed once (by `init.py`'s factory) with its four dependencies injected — no service reaches for a global or constructs its own dependencies, matching the existing `Initializator` pattern's spirit but now wiring services instead of the old mixed-concern classes.

## Data Flow

1. CLI (or, later, an API job worker) calls `AnalysisService.analyze(value, value_type)`.
2. `AnalysisService` asks `ReportCacheService.get(value_type, value)`. Hit → return.
3. Miss → `ValidationService.classify(value)`. Unsupported/invalid → raise `ValidationError`, `AnalysisService` does not proceed to a network call.
4. `VirusTotalService.get_report(classified_type, value)` → raises `VirusTotalAPIError` on failure, otherwise returns the shaped report.
5. `ReportCacheService.set(value_type, value, report)`.
6. Return the report to the caller.

## File Layout

```
app/
  services/
    validation_service.py
    virustotal_service.py   # was VirusTotal/vt_reporter.py's VTReporter
    cache_service.py        # ReportCacheService + CacheBackend protocol
    misp_service.py         # non-interactive core pulled from MISP/vt_tools2misp.py
    analysis_service.py     # AnalysisService orchestrator
  cache_backends/
    sqlite_backend.py       # was DBHandler/db_handler.py
  models.py                 # AnalysisResult / typed result dataclass(es)
  DataHandler/validator.py  # stays (DataValidator + helpers, used by ValidationService)
  VirusTotal/vt_client.py   # stays (thin API client, used by VirusTotalService)
  MISP/vt_tools2misp.py     # trimmed to interactive prompts + CSV/template file handling
  FileHandler/               # stays as-is (CLI-only: ValueReader, OutputHandler, CustomPrettyTable)
init.py                     # becomes a thin factory wiring the 5 services together
vt_tools.py                 # shrinks to: argparse -> AnalysisService calls -> Rich output
```

`app/DBHandler/` and `app/VirusTotal/vt_reporter.py` are removed once their contents move — not kept as compatibility shims (nothing outside this codebase imports them).

## Error Handling

New exception module, e.g. `app/errors.py`:

```python
class AnalysisError(Exception): ...
class ValidationError(AnalysisError): ...
class VirusTotalAPIError(AnalysisError): ...
class CacheError(AnalysisError): ...
```

Services raise these; `vt_tools.py` catches `AnalysisError` (and subclasses, where it wants different messages) and does today's `console.print`/logging — no service prints anything. This is what lets a B3 API layer catch the exact same exceptions and turn them into HTTP responses without touching the services.

## Testing

The testing *conventions* established this session carry over unchanged: stdlib `unittest`, mock only at real boundaries (network, filesystem, `vt.Client`), assert on real behavior. What changes is which test files exist — `test_db_handler.py`, `test_vt_reporter.py`, and the analysis-related tests in `test_vt_tools.py`/`test_init.py` map onto classes being moved/merged, so they get rewritten against the new service interfaces rather than mechanically renamed. This is TDD from the new interfaces outward, not a refactor-and-hope-tests-still-pass exercise — every service class gets its own test file (`test_validation_service.py`, `test_virustotal_service.py`, `test_cache_service.py`, `test_misp_service.py`, `test_analysis_service.py`), and `test_vt_tools.py` shrinks to whatever CLI-only glue remains (arg parsing, output formatting) once the business logic moves out.

## Out of scope (explicitly deferred)

- B2: pluggable cache backend (Postgres adapter), TTL/expiry enforcement, retiring the empty-field-ratio heuristic.
- B3: the API service itself (FastAPI + `arq`/Redis job queue).
- B4: Docker Compose wiring for the new services.
- Any change to the CLI's actual behavior/output as seen by a user — this is an internal restructure; `vt_tools.py --help` and its output format should be unchanged when B1 is done.
