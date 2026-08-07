# TTL-Based Cache Expiry (Sub-project B2) — Design

**Date:** 2026-08-07
**Status:** Approved by user, ready for implementation plan.

## Goal

Replace the empty-field-ratio cache-miss heuristic (`ReportCacheService`'s current "≥80% of fields are 'Not found'" rule) with real TTL-based expiry, and formalize `CacheBackend` as an actual interface rather than a duck-typed convention. This is sub-project B2 of the four-part effort that started with B1 (core library extraction, merged). B2 does not include a Postgres adapter — that's deferred until B3 (the API service) makes a concrete concurrent-access need real; building it now would be guessing at requirements nothing has stated yet.

## Decisions made during brainstorming (binding, not open for re-litigation during implementation)

- **Postgres adapter is out of scope for B2.** Only `SQLiteCacheBackend` exists after this sub-project; `CacheBackend` becomes a real `typing.Protocol` so a future backend has a contract to implement against, but nothing beyond SQLite ships here.
- **TTL is a single fixed default (24 hours), overridable via one env var** (`VT_CACHE_TTL_HOURS`). No per-value-type TTLs, no new CLI flag. VT verdicts don't change often enough to justify more config surface than this.
- **A cached "not found" result is a real cache hit**, honored until it expires like any other report. This is a deliberate behavior change from today's ratio heuristic (which never let a mostly-empty report count as a hit, so not-found values were re-queried on every run). Saves API quota; the tradeoff is a value that newly appears on VT during a TTL window won't be seen until that window elapses — same staleness bound as everything else in the cache.
- **TTL policy lives in `ReportCacheService`, not the backend.** `CacheBackend` implementations only fetch/store raw data (report + `cached_at`); they know nothing about freshness rules. This preserves the split B1 established (backend = dumb store, service = policy) and means a future backend inherits TTL behavior for free just by implementing `get`/`set`.
- **Lazy expiry, no active cleanup.** An expired row is simply treated as a miss on read and gets overwritten the next time that `(value_type, value)` is fetched and cached again. No `purge_expired()` method, no scheduled job. This is a local file-based cache with no evidence of unbounded-growth problems; a cleanup mechanism is speculative until one shows up.
- **The ratio heuristic and its `threshold` parameter are deleted outright**, not deprecated or kept alongside TTL. It's being replaced, not supplemented.

## Architecture

```
AnalysisService (unchanged - still just calls cache.get()/cache.set())
       |
ReportCacheService  <-- TTL policy lives here now (was: ratio heuristic)
       |
CacheBackend (Protocol, formalized in this sub-project)
       |
SQLiteCacheBackend  <-- only implementation; returns (report, cached_at)
```

`AnalysisService` is untouched by this sub-project — it has no idea TTL exists, exactly as it had no idea the ratio heuristic existed. All the change is contained inside `ReportCacheService` and the `CacheBackend` contract it depends on.

## Components

### `CacheBackend` (formalized as a `typing.Protocol`, `app/cache_backends/__init__.py`)

```python
from typing import Protocol

class CacheBackend(Protocol):
    def get(self, value_type: str, value: str) -> tuple[dict, str] | None: ...
    def set(self, value_type: str, value: str, report: dict) -> None: ...
```

This was specified in the B1 design doc but never actually written as a `Protocol` — B1 shipped with `SQLiteCacheBackend` duck-typed against an implicit contract. B2 makes it real. The shape of `get()` changes from B1: it now returns a `(report, cached_at)` tuple instead of just `report`, so the service layer has what it needs to evaluate freshness without the backend knowing what "fresh" means.

### `SQLiteCacheBackend` (`app/cache_backends/sqlite_backend.py`, modified)

`get()` changes to return `(json.loads(report_json), cached_at)` instead of just the parsed report. `set()`, `SCHEMA`, and `close()` are unchanged — `cached_at` has been a column since B1, stamped on every write already.

### `ReportCacheService` (`app/services/cache_service.py`, modified)

```python
from datetime import datetime, timedelta, timezone

class ReportCacheService:
    def __init__(self, backend, ttl: timedelta):
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

`NOT_FOUND_ERROR`, the `threshold` parameter, and all ratio-counting logic are removed entirely.

### TTL configuration (`init.py`, modified)

```python
import os
from datetime import timedelta

CACHE_TTL = timedelta(hours=float(os.getenv("VT_CACHE_TTL_HOURS", "24")))
```

Read the same way `get_api_key`/`get_proxy` read their env vars in `app/DataHandler/utils.py` — a plain `os.getenv` call, no new helper function for a single call site. Passed into `ReportCacheService(backend, ttl=CACHE_TTL)` where it's currently constructed with `ReportCacheService(backend)`.

## Data Flow

1. `AnalysisService.analyze()` calls `cache.get(value_type, cache_key)`, exactly as it does today.
2. `ReportCacheService.get()` asks the backend for `(report, cached_at)`.
   - No row exists → backend returns `None` → miss. `AnalysisService` proceeds to classify + fetch from VT.
   - Row exists, `age <= ttl` → hit. The stored report (found or not-found — no distinction) is returned as-is.
   - Row exists, `age > ttl` → miss. `AnalysisService` proceeds to classify + fetch from VT, exactly as a true miss would.
3. On a real miss (of either kind), `AnalysisService` calls `cache.set(value_type, cache_key, report)`, which `SQLiteCacheBackend` writes via its existing `INSERT ... ON CONFLICT ... DO UPDATE`, refreshing `cached_at` to now. This is the only "expiry" mechanism — a stale row rewrites itself the next time it's looked up, nothing proactively deletes it.

## Error Handling

No new exception handling needed. `datetime.fromisoformat(cached_at)` parses a string this codebase wrote itself in `SQLiteCacheBackend.set()` (`datetime.now(timezone.utc).isoformat()`), so a parse failure isn't a realistic failure mode to guard against. `CacheError` (declared in `app/errors.py` during B1, never raised anywhere) stays unwired — giving the cache layer real I/O error handling was flagged as a B1 follow-up item, separate from TTL work, and bundling it into B2 would be scope creep beyond what this sub-project is for.

## Testing

`tests/test_sqlite_backend.py`: update assertions for `get()`'s new `(report, cached_at)` return shape; the `cached_at` value already gets written today, only the read-side return shape changes.

`tests/test_cache_service.py`: every ratio-heuristic test (mostly-empty-report-counts-as-miss, threshold boundary, etc.) is deleted, not adapted — that policy no longer exists. New tests cover: fresh hit returns the report, stale row (inject an old `cached_at` string directly, not via mocking `datetime.now`) returns `None`, a not-found report within TTL is a real hit (the deliberate behavior change), no-row-at-all is a miss. Time is controlled by writing a known `cached_at` string into the fixture, consistent with this repo's "mock only at real boundaries" testing convention — `datetime.now` itself is not a boundary worth mocking here.

`tests/test_init.py`: one test confirming `ReportCacheService` is constructed with the TTL read from `VT_CACHE_TTL_HOURS` (or the 24-hour default when unset).

## Out of scope (explicitly deferred)

- Postgres (or any other) `CacheBackend` implementation — deferred to whenever B3 makes a concrete need for it.
- Per-value-type TTL configuration.
- Active/scheduled expired-row cleanup.
- Wiring `CacheError` into the cache backend's error handling.
- Any change to `AnalysisService`, `VirusTotalService`, `ValidationService`, or `vt_tools.py`'s CLI surface.
