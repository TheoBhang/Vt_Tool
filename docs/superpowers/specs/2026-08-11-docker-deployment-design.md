# Docker Compose Deployment Wiring (Sub-project B5) — Design

**Date:** 2026-08-11
**Status:** Approved by user, ready for implementation plan.

## Goal

Wire vt_tool's API (`app/api/main.py`) and worker (`app/worker/settings.py`), built in B4, into the existing `deployment/` Docker Compose stack. This is sub-project B5 of the B1–B5 effort; B1 (core library extraction), B2 (TTL cache), B3 (pluggable database connector), and B4 (API + job queue) are already merged to master. B5 is deployment wiring only — no application-logic changes beyond one small addition (a health-check endpoint the deployment needs).

**Scope expansion (added mid-implementation, after the technical design below was already verified working):** the existing `deployment/` stack locally orchestrates MISP's own application containers (`misp-core`, `misp-modules`, `misp-guard`) plus their supporting infrastructure (`db`, `mail`). B5 now also removes these — MISP becomes an externally-managed instance this deployment stack has no opinion about, not something it runs. This was raised and scoped after the vt-tool-api/vt-tool-worker design (below) was already dry-run verified end to end against real Docker; that verification remains valid, since none of it depended on the MISP services being present. See the new Decisions bullets and Components section for the removal's exact scope.

## Prior art: `thalesgroup-cert/suspicious`

At the user's request, `suspicious` (a sibling project by the same author/org, already used as the model for this repo's governance/CI conventions in an earlier sub-project) was used as a reference for its own Docker Compose deployment. Findings, verified by reading the actual repository rather than assumed:

- `suspicious`'s `deployment/` directory already has the exact same `compose_apps.yaml`/`compose_databases.yaml`/`docker-compose.yml`/`Makefile`/`.env.example` split vt_tool's `deployment/` directory already follows — confirming vt_tool's deployment scaffolding was modeled on (or shares lineage with) `suspicious`'s.
- `suspicious`'s `suspicious` (Gunicorn/Django) and `suspicious_celery` (Celery worker) services `extend` the **same image**, differing only in their `command:` — one shared image, not two.
- Health checks hit a real app-level endpoint (`/api/health/`) that pings the app's actual dependencies (DB + Redis), not just "is the process running."
- The Celery worker's health check uses `celery -A suspicious inspect ping` — a real, built-in Celery CLI health-check command, not a custom script.

vt_tool's own `deployment/` directory turned out to already have unfinished scaffolding for exactly this: `.env.example` has `VT_TOOL_WEB_VERSION`/`VT_TOOL_WEB_PORT=8080`, and `docker-compose.yml` has a commented-out `vt-tool-web` service pointing at a `Dockerfile` that references a `webapp/` directory that was never built. This is being replaced, not repurposed (see Decisions below).

`arq` (B4's job queue library) ships the equivalent of Celery's `inspect ping` — a real `--check` CLI flag, confirmed against the installed library (`arq <WorkerSettings path> --check`, backed by `arq.worker.check_health()`), which pings the same Redis health-check key the running worker writes to.

## Decisions made during brainstorming (binding, not open for re-litigation during implementation)

- **The stale `VT_TOOL_WEB_*`/`webapp/`/commented-out `vt-tool-web` scaffolding is replaced, not repurposed.** It named a web UI that was never built; B4 built an HTTP API + job worker, not a UI. New naming: `vt-tool-api`, `vt-tool-worker`, `VT_TOOL_API_VERSION`, `VT_TOOL_API_PORT`.
- **One shared Docker image for both the API and the worker**, matching `suspicious`'s own pattern. Same codebase, same dependencies (`fastapi`/`uvicorn`/`arq` are already in `requirements.txt` from B4) — one `Dockerfile`, two services with different `command:`.
- **Cache defaults to SQLite on a shared named Docker volume**, not a new database service. Matches B2/B3's zero-config-by-default philosophy; a shared local Docker volume is a genuinely safe use case for SQLite (its file-locking is built for multi-*process* access — B4's Task 1 fixed multi-*threaded* single-connection access, a different concern). `VT_CACHE_DB_URL` remains available in `.env.example` for anyone who wants a real database instead — B5 doesn't force MISP's existing MariaDB into a role it was never scoped for.
- **Redis is reused from the existing `redis` service** (already declared for MISP), not duplicated — matching the decision already made in B4's own design. A distinct Redis DB index is used for vt_tool's arq queue so it can never collide with MISP's own Redis usage on the same instance.
- **`GET /health` is added to `app/api/main.py`**, pinging the real cache backend and Redis, returning 503 if either fails. This is the one code change in B5 — needed because Docker's `healthcheck:` and `depends_on: condition: service_healthy` elsewhere in the compose file need a real signal, not just "the process started."
- **The worker's healthcheck uses arq's built-in `--check` flag**, not a custom script — same reasoning as `suspicious` using Celery's own `inspect ping` rather than inventing a bespoke health probe.
- **No reverse proxy / TLS termination wiring in B5.** `suspicious` has a full Traefik setup (`traefik/`, `compose_reverse_proxy.yaml`) that's out of scope here — vt_tool's API is exposed on `127.0.0.1` only by default, matching `suspicious`'s own convention for its Django service, deferred to a future sub-project if external exposure is ever needed.
- **No Vault / secrets-management wiring.** `suspicious` uses HashiCorp Vault for secrets; vt_tool's existing `.env`-file convention (already used for `MYSQL_PASSWORD`, `REDIS_PASSWORD`, etc.) is left as-is — introducing Vault would be a disproportionate amount of new infrastructure for what this deployment actually needs.
- **Single replica by default for both services.** No scaling configuration in B5; `docker compose up --scale vt-tool-worker=N` remains available later without any design changes needed now.
- **MISP's own application stack — `misp-core`, `misp-modules`, `misp-guard`, `db`, `mail` — is removed from `deployment/`, not made optional or profile-gated.** All five exist only to serve `misp-core` (its enrichment modules, its guard proxy, its database, its outbound mail relay); none has independent purpose once `misp-core` itself is external. `redis` is kept — it's already vt_tool's own arq queue infrastructure per B4/B5's design, not MISP-specific, and stops being dual-purposed with any local MISP service once MISP moves external.
- **Dead scaffolding that only existed to support the removed MISP services is deleted, not left in place.** The `misp/` directory (`.env.example`/`guard/config.json` — config templates for `MISP_PATH` mounts that no longer exist), `deployment/scripts/init.sh`'s `MISP_PATH` directory check and MISP `.env` bootstrapping steps, and its automatic TLS-certificate-generation step (the only consumer of those certificates was `misp-core`'s HTTPS listener) are all removed. `deployment/certificates/` and `scripts/openssl-certificates-generator.sh` themselves, and the Makefile's `create-certs` target, are kept (not automatically invoked anymore, but still available if a future reverse-proxy sub-project wants them) — explicitly narrower than the scaffolding removal, not itself removed.
- **vt_tool's own MISP-submission feature (`app/MISP/vt_tools2misp.py`, driven by `MISPURL`/`MISPKEY`/`MISPSSLVERIFY` in the repository's root-level `.env`) is completely unaffected.** That's a CLI feature pointing at whatever MISP instance the user configures — it never depended on `deployment/`'s local MISP containers, and `deployment/README.md` gains a short note clarifying this now that the local containers are gone.

## Architecture

```
docker compose up
       |
   redis (vt_tool's own arq queue - no longer shared with any local MISP service)
       |
   healthy? ──yes──> vt-tool-api (uvicorn)      vt-tool-worker (arq)
                          |                            |
                     GET /health                  arq --check
                     (cache + redis ping)          (Redis health-check key)
                          |                            |
                     127.0.0.1:${VT_TOOL_API_PORT} exposed
```

Both `vt-tool-api` and `vt-tool-worker` extend the same image (built from one `Dockerfile`), differ only in `command:`, and share a Docker named volume (mounted at `/app/data`, not `/app` - mounting the volume at `/app` itself would shadow the application code the image's `COPY` steps put there) for the default SQLite cache file.

## Components

### `Dockerfile` (rewritten)

Replaces the current stale version. `FROM python:3.11-slim` (matching CI's Python version), installs `requirements.txt`, copies `app/`, `vt_tools.py`, `init.py` — no `git clone`, no `webapp/` reference.

### `deployment/compose_apps.yaml` (modified — two new service blocks)

```yaml
  vt-tool-api:
    init: true
    restart: always
    command: uvicorn app.api.main:app --host 0.0.0.0 --port 8080
    ports:
      - "127.0.0.1:${VT_TOOL_API_PORT:-8080}:8080"
    env_file:
      - .env
    environment:
      REDIS_URL: "redis://:${REDIS_PASSWORD:-redispassword}@redis:${REDIS_PORT:-6379}/${VT_TOOL_REDIS_DB:-1}"
      VT_CACHE_DB_URL: "${VT_CACHE_DB_URL:-sqlite:////app/data/vttools.sqlite}"
      VT_CACHE_TTL_HOURS: "${VT_CACHE_TTL_HOURS:-24}"
    volumes:
      - vt_tool_cache:/app/data
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:8080/health || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 5
      start_period: 15s
    networks:
      - vt_tool_network

  vt-tool-worker:
    init: true
    restart: always
    command: arq app.worker.settings.WorkerSettings
    env_file:
      - .env
    environment:
      REDIS_URL: "redis://:${REDIS_PASSWORD:-redispassword}@redis:${REDIS_PORT:-6379}/${VT_TOOL_REDIS_DB:-1}"
      VT_CACHE_DB_URL: "${VT_CACHE_DB_URL:-sqlite:////app/data/vttools.sqlite}"
      VT_CACHE_TTL_HOURS: "${VT_CACHE_TTL_HOURS:-24}"
    volumes:
      - vt_tool_cache:/app/data
    healthcheck:
      test: ["CMD-SHELL", "arq app.worker.settings.WorkerSettings --check"]
      interval: 30s
      timeout: 5s
      retries: 5
      start_period: 15s
    networks:
      - vt_tool_network
```

`REDIS_URL`/`VT_CACHE_DB_URL`/`VT_CACHE_TTL_HOURS` are built via Compose's own `${VAR:-default}` interpolation in the `environment:` block, not literal `.env` lines - `.env` files can't reference other variables within themselves, so `REDIS_URL` (which needs `REDIS_PASSWORD`/`REDIS_PORT`/`VT_TOOL_REDIS_DB`) has to be assembled here, matching how `deployment/compose_databases.yaml`'s own `redis:` service already builds its `REDIS_PASSWORD` this same way. The `sqlite:////app/data/vttools.sqlite` default's four slashes were verified directly against a real `sqlalchemy.create_engine(...)` call, not assumed: three literal slashes in SQLAlchemy's sqlite URL scheme plus the leading slash of the absolute path `/app/data/vttools.sqlite`.

### `deployment/docker-compose.yml` (modified)

The commented-out `vt-tool-web` block is replaced with real entries `extends`-ing the two blocks above:

```yaml
  vt-tool-api:
    extends:
      file: compose_apps.yaml
      service: vt-tool-api
    image: ${REGISTRY_MIRROR_URL:-}ghcr.io/thalesgroup-cert/vt-tool-api:${VT_TOOL_API_VERSION:-latest}
    container_name: vt-tool-api
    depends_on:
      redis:
        condition: service_healthy

  vt-tool-worker:
    extends:
      file: compose_apps.yaml
      service: vt-tool-worker
    image: ${REGISTRY_MIRROR_URL:-}ghcr.io/thalesgroup-cert/vt-tool-api:${VT_TOOL_API_VERSION:-latest}
    container_name: vt-tool-worker
    depends_on:
      redis:
        condition: service_healthy
```

(Both use the same image tag — one image, two roles, per the binding decision above.)

`volumes:` gains `vt_tool_cache:`. `db_data`/`db_log`/`misp_guard_ca` are removed (they belonged exclusively to the now-removed `db`/`misp-guard` services); `cache_data` (redis's own volume) stays.

### MISP application services removed

`misp-core`, `misp-modules`, `misp-guard` (from `deployment/compose_apps.yaml` and `deployment/docker-compose.yml`), and `db` (from `deployment/compose_databases.yaml` and `deployment/docker-compose.yml`), and `mail` (from `deployment/compose_apps.yaml` and `deployment/docker-compose.yml`) are deleted outright — not commented out, not made optional via a Compose profile. `redis` (in `deployment/compose_databases.yaml`) is unchanged.

### `deployment/.env.example` (MISP/DB/mail vars removed)

`CORE_HTTP_PORT`, `CORE_HTTPS_PORT`, `MISP_VERSION`, `MISP_MODULES_VERSION`, `MISP_GUARD_VERSION`, `MISP_PATH`, `GUARD_PORT`, `GUARD_ARGS`, `SMARTHOST_ADDRESS`, `SMARTHOST_PORT`, `SMARTHOST_USER`, `SMARTHOST_PASSWORD`, `SMARTHOST_ALIASES`, `DB_VERSION`, `DB_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD` are all removed — every one was consumed exclusively by a service this sub-project now removes.

### `deployment/scripts/init.sh` (MISP-specific steps removed)

The `${MISP_PATH}` directory-existence check, the `${MISP_PATH}/.env` bootstrapping step (copying `${MISP_PATH}/.env.example` to `${MISP_PATH}/.env`), and the automatic TLS-certificate-generation step (the only consumer of those certificates was `misp-core`'s HTTPS listener, now gone) are removed. The script's remaining steps (binary checks, `deployment/.env` bootstrapping) are unchanged. `deployment/scripts/openssl-certificates-generator.sh` itself and the Makefile's `create-certs` target are NOT removed — they're simply no longer invoked automatically by `init.sh`, kept available for manual use if a future sub-project adds a reverse proxy.

### `misp/` directory removed

`misp/.env.example` and `misp/guard/config.json` were config templates for `${MISP_PATH}` mounts that no longer exist once `misp-core`/`misp-guard` are removed. Deleted.

### `deployment/README.md` (new section)

A short note clarifying that this stack does not run a local MISP instance, and that vt_tool's own MISP-submission feature (`app/MISP/vt_tools2misp.py`) is configured independently via `MISPURL`/`MISPKEY`/`MISPSSLVERIFY` in the repository's root-level `.env` file, pointed at whatever MISP instance the operator actually runs.

### `app/api/main.py` (modified — one new endpoint)

```python
@app.get("/health")
async def health(request: Request):
    analysis: AnalysisService = request.app.state.analysis
    redis = request.app.state.redis
    try:
        analysis.check_cache("healthcheck", "domains")
        await redis.ping()
    except Exception:
        raise HTTPException(status_code=503, detail="not ready")
    return {"status": "ok"}
```

### `deployment/.env.example` (modified)

`VT_TOOL_WEB_VERSION=latest` / `VT_TOOL_WEB_PORT=8080` replaced with:

```
VT_TOOL_API_VERSION=latest
VT_TOOL_API_PORT=8080

VT_TOOL_REDIS_DB=1

VT_CACHE_DB_URL=
VT_CACHE_TTL_HOURS=
```

`VT_TOOL_REDIS_DB` namespaces vt_tool's arq queue to its own Redis database index - no longer strictly needed to avoid a MISP collision (MISP's Redis usage is gone along with the rest of its stack), but kept as a clean, explicit default rather than assuming index 0 forever.

## Data Flow

1. Operator runs `make init` (existing target: network, config files - the MISP-specific and certificate-generation steps are removed per the Decisions above), edits `deployment/.env`, runs `make deploy` or `make up`.
2. Compose starts `redis` (existing, now solely vt_tool's own arq queue), waits for its healthcheck.
3. `vt-tool-api` and `vt-tool-worker` start once Redis is healthy; each reports its own healthy status only once `GET /health` (API) / `arq ... --check` (worker) genuinely succeed against real dependencies.
4. A client calls `POST /analyze`/`GET /jobs/{job_id}` against the exposed API port — B4's application code is completely unchanged by this sub-project, this is purely the deployment wiring around it.

## Error Handling

If Redis becomes unreachable after startup, both services' healthchecks start failing and `restart: always` keeps retrying — `docker compose ps` surfaces `unhealthy`/`restarting` rather than a silently broken deployment. No new application-level error handling beyond the `/health` endpoint itself; B4 already built the app layer to fail loud on a real dependency outage.

## Testing

`tests/test_api.py` gains tests for `GET /health`: a success case (cache + Redis both reachable → 200) and a failure case (mock either the cache backend or `redis.ping()` to raise → 503), consistent with every other sub-project's `unittest`-based conventions.

The Compose wiring itself has no unit-test equivalent (this repo's CI has no Docker-in-Docker). Verification is `docker compose config` (validates YAML syntax and variable interpolation without starting anything) plus a manual `docker compose up` smoke test if Docker is available in the implementation environment — the same category of manual verification B1–B4's final passes already used for anything that couldn't be expressed as a `unittest`.

## Out of scope (explicitly deferred)

- Reverse proxy / TLS termination (Traefik) for the API.
- Vault or any other secrets-management system beyond the existing `.env` file convention.
- Multi-replica scaling configuration.
- A real (non-SQLite) database wired in by default — `VT_CACHE_DB_URL` remains available, but B5 doesn't choose or provision one.
- CI-level Docker Compose integration testing (building and starting the actual stack in GitHub Actions).
- Any change to `app/MISP/vt_tools2misp.py` or the CLI's own MISP-submission flow — that feature is untouched, only where the MISP *instance* it talks to is expected to run (external, not locally orchestrated by this stack) is a documentation change.
- Removing `deployment/certificates/`, `scripts/openssl-certificates-generator.sh`, or the Makefile's `create-certs` target — kept available for a future reverse-proxy sub-project even though nothing currently invokes them automatically.
