# API Service + Job Queue (Sub-project B4) — Design

**Date:** 2026-08-11
**Status:** Approved by user, ready for implementation plan.

## Goal

Add an HTTP API + background job queue for vt_tool, built entirely on top of the service layer B1 already extracted (`AnalysisService`, `ValidationService`, `ReportCacheService`) and the pluggable cache backend B2/B3 already built. This is sub-project B4 of a multi-part effort; B1 (core library extraction), B2 (TTL-based cache expiry), and B3 (pluggable database connector) are already merged to master. Deployment/Docker Compose wiring for the new API and worker services is explicitly deferred to its own future sub-project — this one is about the API and worker code itself.

The CLI (`vt_tools.py`) is completely unaffected by this sub-project. It remains fully standalone and airgapped-capable, with zero dependency on the API, the worker, or Redis — this was a binding requirement from the original brainstorming that produced B1 through B4, and nothing in this design touches `vt_tools.py`, `init.py`, or any existing service class.

## Decisions made during brainstorming (binding, not open for re-litigation during implementation)

- **Sync on cache hit, async on miss.** `POST /analyze` returns a report immediately for a cache hit (a direct `ReportCacheService.get()` call, no queue involved) and a job ID for a cache miss (enqueued for the worker). Every request does not pay for a queue round-trip when the answer was already cached.
- **arq + Redis for the job queue**, not Celery and not a database-polling queue. arq is async-native (pairs naturally with FastAPI), has far less operational surface than Celery (no Beat, no multi-broker config), and Redis is already present in this repo's deployment stack for MISP — no new piece of infrastructure, just reused infrastructure with its own key namespace.
- **Core analysis only — no MISP submission, no CSV/TXT export via the API.** Those CLI features are built around local files and interactive prompts that don't map onto a stateless API and don't need a job queue. `MispService` is not touched by this sub-project.
- **Per-request VirusTotal API key**, not a single shared server-side key. Each `POST /analyze` call includes the caller's own `api_key`; different callers use their own VT quotas. Consequence, stated explicitly rather than glossed over: the API key travels through the Redis-backed job queue as job-argument data for the lifetime of a queued job. Acceptable for this org's existing closed/internal deployment (same network the MISP stack already runs on) — not something this design adds new encryption or secrets-handling for.
- **No new service classes.** The API and worker are new *callers* of `AnalysisService`/`ValidationService`/`ReportCacheService`, unchanged. `ReportCacheService.get()` already does a cache-only lookup (never fetches) — that's the sync-hit path verbatim. `AnalysisService.analyze()` already does check-cache-then-fetch-then-cache — that's the worker's job function verbatim, just called with a per-job `VirusTotalService` instance instead of the CLI's per-run one.
- **A fresh `vt.Client` per job, not pooled per API key.** Simplest thing that works; no evidence yet that `vt.Client` construction overhead is a real cost. The cache (`ReportCacheService`/backend) is the one thing shared across all jobs in the worker process — only the VT client differs per job, scoped to that job's caller-supplied key.
- **No real Redis (or Postgres/MySQL) required in CI.** FastAPI endpoint tests mock the arq pool's `enqueue_job` call; the worker's job function is tested as a plain async function call with a mocked `vt.Client`. One true end-to-end test uses a real `SQLiteCacheBackend` against a temp file for the hit path, not a mock, per the lesson from B1's review passes (mocked-everywhere tests hid real bugs that only a real-object test caught). arq's own enqueue/dequeue mechanics are its tested responsibility, not re-verified here — same precedent B3 set for not re-testing SQLAlchemy's per-dialect SQL correctness.
- **Validation happens before queueing.** An invalid value never reaches the job queue — `ValidationService.classify()` runs synchronously in the API handler, and a validation failure is an immediate per-item error in the `POST /analyze` response.

## Architecture

```
Client
  |
  | POST /analyze {values: [{value, value_type}], api_key, proxy}
  v
FastAPI app (app/api/main.py)
  |
  |-- per item: ValidationService.classify() -> invalid? immediate error, no queue
  |-- per item: ReportCacheService.get(value_type, value)
  |     |-- hit  -> return report immediately (no queue)
  |     '-- miss -> arq.enqueue_job("analyze_value", value, value_type, api_key, proxy)
  |                 -> return {status: "queued", job_id}
  v
Redis (reused from existing deployment/docker-compose.yml, separate namespace from MISP's usage)
  v
arq worker (app/worker/tasks.py)
  |
  '-- analyze_value(ctx, value, value_type, api_key, proxy):
        virustotal = VirusTotalService(VirusTotalClient(api_key, proxy).init_client())
        analysis = AnalysisService(validation, virustotal, shared_cache)
        report, from_cache = analysis.analyze(value, value_type)   # same call the CLI makes
        # AnalysisService.analyze() already calls cache.set() on a real miss

GET /jobs/{job_id} -> arq's own job status (queued/in_progress/complete/failed) + report on completion
```

`ReportCacheService`/`CacheBackend` (`SQLiteCacheBackend` or `SQLAlchemyCacheBackend`, whichever `VT_CACHE_DB_URL` configures) is constructed once at worker/API startup and shared across every request/job — this is the same object graph `Initializator` already builds for the CLI, just instantiated in a long-running process instead of once per CLI invocation.

## Components

### `app/api/main.py` (new)

FastAPI app with two endpoints:

- `POST /analyze` — body: `{"values": [{"value": str, "value_type": str}], "api_key": str, "proxy": str | None}`. For each item in `values`: validate, then check cache. Response is an array, one entry per input item, each either `{"status": "hit", "report": {...}}` or `{"status": "invalid", "error": "..."}` or `{"status": "queued", "job_id": "..."}`.
- `GET /jobs/{job_id}` — returns `{"status": "queued" | "in_progress" | "complete" | "failed", "report": {...} | null, "error": str | null}`, reading arq's own job-result API.

### `app/worker/tasks.py` (new)

```python
async def analyze_value(ctx, value, value_type, api_key, proxy):
    virustotal = VirusTotalService(VirusTotalClient(api_key, proxy).init_client())
    analysis = AnalysisService(
        validation=ctx["validation"],   # shared, stateless, safe to reuse across jobs
        virustotal=virustotal,          # fresh per job, scoped to this job's api_key
        cache=ctx["cache"],             # shared ReportCacheService, one per worker process
    )
    report, _ = analysis.analyze(value, value_type)
    return report
```

`ctx` is arq's per-worker context dict, populated once at worker startup (`on_startup` hook) with the shared `ValidationService`/`ReportCacheService` instances — not reconstructed per job.

### `app/worker/settings.py` (new)

arq's `WorkerSettings` class: registers `analyze_value` as the queued function, wires the `on_startup` hook that builds the shared `ValidationService`/`ReportCacheService` (reading `VT_CACHE_DB_URL`/`VT_CACHE_TTL_HOURS` the same way `init.py` does today, so the worker's cache config matches the CLI's), and points at the Redis connection.

### `requirements.txt` (modified)

Add `fastapi`, `uvicorn`, `arq`.

## Data Flow

1. Client `POST`s a batch to `/analyze` with values, `value_type`s, an `api_key`, and an optional `proxy`.
2. For each item: `ValidationService.classify(value, value_type)`. Invalid → that item's response entry is an immediate error; no queue interaction for it.
3. Valid → `ReportCacheService.get(value_type, cache_key)`. Hit → that item's response entry is the report, returned synchronously.
4. Miss → enqueue an arq job with `(value, value_type, api_key, proxy)`; that item's response entry is `{"status": "queued", "job_id": ...}`.
5. The worker picks up the job, builds a fresh `VirusTotalService` scoped to that job's `api_key`, and calls the shared `AnalysisService.analyze(value, value_type)` — identical to what the CLI calls. This itself re-checks the cache first, so a race between two concurrent misses for the same value results in at most one real VT fetch (whichever job's worker runs second sees the first job's cached result).
6. `AnalysisService.analyze()` calls `cache.set()` on a genuine miss, exactly as it does for the CLI — the result is now cached for every future caller, regardless of which API key eventually asks for it.
7. Client polls `GET /jobs/{job_id}` until `complete` (report available) or `failed` (error message available).

## Error Handling

`ValidationError` (raised by `ValidationService.classify` returning `None`/unsupported) → surfaces as an immediate per-item error in the `POST /analyze` response, never reaches the queue. `VirusTotalAPIError` (bad API key, VT-side failure, network error) raised inside the worker's `analyze_value` → arq marks the job `failed`; `GET /jobs/{job_id}` surfaces the error message from the exception. No new exception types — this sub-project reuses `app/errors.py`'s existing `AnalysisError` hierarchy from B1 unchanged. If Redis is unreachable at the moment `POST /analyze` tries to enqueue a job, the API returns a `5xx` for that request immediately rather than returning a fake `"queued"` status — a genuine dependency failure, not something to paper over.

## Testing

`tests/test_api.py` (new): `fastapi.testclient.TestClient`-based tests (stdlib-`unittest`-compatible, no pytest) for `POST /analyze` and `GET /jobs/{id}`. The arq pool's `enqueue_job` is mocked for miss-path tests (asserting it's called with the right job name/args, not that arq itself works). At least one hit-path test uses a real `SQLiteCacheBackend` against a temp file with a pre-seeded row, proving the synchronous cache-hit path works end to end through real cache code, not a mock standing in for it.

`tests/test_worker.py` (new): calls `analyze_value(ctx, ...)` directly as a plain `async def` (via `asyncio.run` or `unittest.IsolatedAsyncioTestCase`), with a mocked `vt.Client` (the actual external boundary) and a real `ReportCacheService`/`SQLiteCacheBackend` pair, proving the job function correctly populates the cache — this is the test that would have caught the kind of "worked in isolation, broke in the real object graph" bug B1's final review found, applied here before merge instead of after.

No test in this suite requires a real Redis connection or a real arq worker process running — consistent with B3's precedent for not needing a live external database server in CI.

## Out of scope (explicitly deferred)

- Docker Compose wiring for the new API and worker services (a new `redis` entry or namespace, `vt-tool-api`/`vt-tool-worker` service definitions) — its own future sub-project. The stale `Dockerfile`/`docker-compose.yml` references to a `vt-tool-web` service and `webapp/` directory found during brainstorming are pre-existing, unfinished scaffolding, not something this sub-project resurrects or is bound by.
- MISP submission and CSV/TXT export via the API.
- A shared server-side VT API key option (per-request keys only, per the binding decision above).
- Authentication/authorization on the API itself (who is allowed to call `POST /analyze` at all) — deferred to network-level controls (the same internal-network assumption the existing MISP deployment stack already relies on).
- Connection pooling or per-API-key `vt.Client` reuse in the worker.
- Rate limiting, request throttling, or per-caller quota tracking beyond what VirusTotal's own API already enforces per key.
