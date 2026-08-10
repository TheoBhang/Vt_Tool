# Pluggable Database Connector (Sub-project B3) — Design

**Date:** 2026-08-10
**Status:** Approved by user, ready for implementation plan.

## Goal

Let users point vt_tool's report cache at whatever SQL database they want (Postgres, MySQL, MSSQL, Oracle, another SQLite file, etc.) via a connection URL, without vt_tool hand-writing a separate backend class per database. This is sub-project B3 of the four-part effort that started with B1 (core library extraction, merged) and B2 (TTL-based cache expiry, merged). B4 (the API service + job queue, previously bundled into "B3") is deferred to its own future design cycle — it doesn't need to exist for this sub-project to ship value, and designing it now would mean guessing at requirements this sub-project doesn't need to guess at.

## Decisions made during brainstorming (binding, not open for re-litigation during implementation)

- **SQL databases only.** No MongoDB, Redis, DynamoDB, or other non-SQL stores. The `cached_reports` table is already a plain 4-column relational shape; one SQL-dialect-agnostic library covers "any SQL database" in a way nothing spans both SQL and NoSQL.
- **One new backend, not one per database.** `SQLAlchemyCacheBackend` uses SQLAlchemy Core (not the ORM — the schema is a plain table, not an object graph) to speak every SQL dialect SQLAlchemy supports through one implementation.
- **`SQLiteCacheBackend` is untouched.** It stays exactly as it is (raw `sqlite3`, already tested, already the default) and remains the zero-config path when no database URL is configured. This preserves the airgapped/standalone CLI guarantee this project has maintained throughout — no new dependency, no network, no configuration required for the common case (a solo analyst running the CLI locally).
- **Selection is env-var-driven, not a CLI flag.** `VT_CACHE_DB_URL` unset → `SQLiteCacheBackend`. Set → `SQLAlchemyCacheBackend(VT_CACHE_DB_URL)`. Matches the existing `VTAPIKEY`/`PROXY`/`VT_CACHE_TTL_HOURS` convention.
- **One new dependency: `sqlalchemy`.** Users add their own DB driver package (`psycopg2-binary`, `PyMySQL`, etc.) for whichever database they choose — the same convention SQLAlchemy itself uses. vt_tool's own `requirements.txt` grows by exactly one package regardless of how many databases this unlocks.
- **Portable upserts via insert-then-update-on-conflict**, not dialect-specific `ON CONFLICT`/`ON DUPLICATE KEY` syntax. SQLAlchemy Core doesn't unify upsert syntax across dialects on its own; try-`INSERT`-then-`UPDATE`-on-constraint-violation is the approach that works identically everywhere Core runs, at the cost of a second round-trip only on the (less common) update path.
- **No CI infrastructure for real Postgres/MySQL servers.** Tests exercise `SQLAlchemyCacheBackend` against a `sqlite:///`-style URL through the SQLAlchemy engine — this proves the Core code path (schema creation, the upsert logic, the `CacheBackend` contract) without needing external services in CI. Per-dialect SQL correctness is SQLAlchemy's own tested responsibility, not something this sub-project re-verifies per database.

## Architecture

```
Initializator.__init__
       |
  VT_CACHE_DB_URL set?
    /            \
  no              yes
   |                |
SQLiteCacheBackend   SQLAlchemyCacheBackend(VT_CACHE_DB_URL)
   |                |
   \________________/
            |
   CacheBackend Protocol (unchanged, from B2)
            |
   ReportCacheService (unchanged, from B2 - TTL policy, value_type namespacing)
            |
   AnalysisService (unchanged, from B1)
```

Nothing above the backend layer changes. `ReportCacheService`'s TTL comparison and `AnalysisService`'s cache-key namespacing (established in B1/B2) are backend-agnostic already, by design — that's the seam this sub-project slots into.

## Components

### `SQLAlchemyCacheBackend` (`app/cache_backends/sqlalchemy_backend.py`, new)

```python
import sqlalchemy

class SQLAlchemyCacheBackend:
    """SQLAlchemy Core implementation of the report-cache backend: same
    contract as SQLiteCacheBackend, but works against any SQL database
    SQLAlchemy supports via a connection URL. No report-shaping logic here -
    that's VirusTotalService's job alone, same as SQLiteCacheBackend."""

    def __init__(self, db_url: str):
        self.engine = sqlalchemy.create_engine(db_url)
        self.metadata = sqlalchemy.MetaData()
        self.table = sqlalchemy.Table(
            "cached_reports", self.metadata,
            sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
            sqlalchemy.Column("value_type", sqlalchemy.String, nullable=False),
            sqlalchemy.Column("value", sqlalchemy.String, nullable=False),
            sqlalchemy.Column("report_json", sqlalchemy.Text, nullable=False),
            sqlalchemy.Column("cached_at", sqlalchemy.String, nullable=False),
            sqlalchemy.UniqueConstraint("value_type", "value", name="uq_value_type_value"),
        )
        self.metadata.create_all(self.engine)

    def get(self, value_type: str, value: str) -> tuple[dict, str] | None:
        # SELECT report_json, cached_at WHERE value_type = ? AND value = ?
        # Returns (json.loads(report_json), cached_at) or None - same shape
        # SQLiteCacheBackend.get() already returns.
        ...

    def set(self, value_type: str, value: str, report: dict) -> None:
        # Try INSERT; on a unique-constraint violation (row already exists),
        # UPDATE report_json and cached_at instead. Two round-trips only on
        # the update path - the common case (new value) is a single INSERT.
        ...

    def close(self) -> None:
        self.engine.dispose()
```

Same 4 real columns as `SQLiteCacheBackend`'s existing `cached_reports` schema — this is the existing schema expressed in SQLAlchemy's dialect-agnostic Core language, not a new design.

### `init.py` (modified)

```python
db_url = os.getenv("VT_CACHE_DB_URL")
cache_backend = SQLAlchemyCacheBackend(db_url) if db_url else SQLiteCacheBackend(DATABASE_FILE)
```

Replaces the current unconditional `cache_backend = SQLiteCacheBackend(DATABASE_FILE)` line. Everything downstream (`ReportCacheService(cache_backend, ttl=cache_ttl)`) is unchanged.

### `requirements.txt` (modified)

Add `sqlalchemy`. No specific DB driver is bundled — that's the user's choice, installed separately based on which database they point `VT_CACHE_DB_URL` at (e.g. `pip install psycopg2-binary` for Postgres).

### `.env.example` (modified)

Add `VT_CACHE_DB_URL=`, matching the file's existing bare-`KEY=` style, alongside `VT_CACHE_TTL_HOURS`.

## Data Flow

1. `Initializator.__init__` reads `VT_CACHE_DB_URL`. Unset → `SQLiteCacheBackend`, exactly today's behavior. Set → `SQLAlchemyCacheBackend(db_url)`.
2. `AnalysisService.analyze()` calls `cache.get(value_type, cache_key)` / `cache.set(value_type, cache_key, report)`, identical to today — it has no idea which backend is underneath.
3. `SQLAlchemyCacheBackend.get()`: a `SELECT` via Core, returning `(report, cached_at)` or `None`.
4. `SQLAlchemyCacheBackend.set()`: attempt an `INSERT`. If the database raises a unique-constraint violation (the `(value_type, value)` pair already exists), catch it and issue an `UPDATE` instead, refreshing both `report_json` and `cached_at`.

## Error Handling

A bad `VT_CACHE_DB_URL` (unreachable host, bad credentials, malformed URL) fails at `Initializator` construction, at the same point `SQLiteCacheBackend`'s own connection would fail today — no new exception wrapping needed; `main()`'s existing top-level catch-all handles it the same way it handles any other startup failure. A missing DB driver package produces SQLAlchemy's own clear import-error message naming the missing package, which is directly actionable without vt_tool adding its own translation layer. `CacheError` (declared in B1, still never raised) stays out of scope for this sub-project too, consistent with B1 and B2's prior decisions to defer that wiring.

## Testing

`tests/test_sqlalchemy_backend.py` (new): exercises `SQLAlchemyCacheBackend` against a `sqlite:///`-style URL (a temp file or `sqlite:///:memory:`) through the real SQLAlchemy engine — round-trip get/set, the insert-then-update-on-conflict path (set the same `(value_type, value)` twice, confirm one row and the second write's data wins), the `(report, cached_at)` tuple contract matching `SQLiteCacheBackend`'s. This proves the Core code path end-to-end without needing a live Postgres/MySQL server in CI.

`tests/test_init.py`: one test confirming `VT_CACHE_DB_URL` set → `Initializator.analysis.cache.backend` is a `SQLAlchemyCacheBackend`; unset → still `SQLiteCacheBackend`, unchanged from B2.

No test asserts dialect-specific SQL correctness (e.g. against a real Postgres) — that's SQLAlchemy's own tested responsibility, not something this sub-project re-verifies.

## Out of scope (explicitly deferred)

- Non-SQL databases (MongoDB, Redis, DynamoDB, etc.).
- The API service + job queue (now B4) — designed separately, once needed.
- Bundling any specific DB driver package — users install their own.
- Migrating existing SQLite cache data into a newly-configured external database — switching `VT_CACHE_DB_URL` starts that backend's cache empty, same "it's just a cache" reasoning B1 used for the original schema change.
- Wiring `CacheError` into either backend's error handling.
- Connection pooling tuning, retry logic, or any other production-database operational concern beyond what SQLAlchemy's defaults already provide.
