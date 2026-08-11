# Docker Compose Deployment Wiring (Sub-project B5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire B4's API (`app/api/main.py`) and worker (`app/worker/settings.py`) into the `deployment/` Docker Compose stack, and remove MISP's own locally-orchestrated application containers (`misp-core`, `misp-modules`, `misp-guard`, `db`, `mail`) in favor of documenting an externally-managed MISP instance.

**Architecture:** A rewritten `Dockerfile` builds one image containing vt_tool's codebase. Two new Compose services, `vt-tool-api` (`uvicorn`) and `vt-tool-worker` (`arq`), extend that image with different `command:` overrides, replacing the stale, never-finished `vt-tool-web`/`webapp/` scaffolding already present in `deployment/`. Both depend on the existing `redis` service being healthy; `vt-tool-api` gets a new `GET /health` endpoint for its own Docker healthcheck. Separately, `misp-core`/`misp-modules`/`misp-guard`/`db`/`mail` — MISP's own application stack, which exists only to serve `misp-core` — are removed entirely; `redis` stays, now purely as vt_tool's own arq queue infrastructure.

**Tech Stack:** Docker, Docker Compose v2, the existing `deployment/` Makefile/scripts. stdlib `unittest` for the one new Python endpoint.

## Global Constraints

- stdlib `unittest` + `unittest.mock` only — no pytest.
- `ruff check .` must stay clean (rule set: E4, E7, E9, F).
- One shared Docker image for both `vt-tool-api` and `vt-tool-worker` — same `image:` tag, different `command:`.
- The stale `VT_TOOL_WEB_*`/`webapp/`/commented-out `vt-tool-web` scaffolding is replaced, not repurposed — new naming is `vt-tool-api`/`vt-tool-worker`/`VT_TOOL_API_*`.
- Cache defaults to SQLite on a shared named Docker volume mounted at `/app/data` (NOT `/app` — that would shadow the application code the image's `COPY` steps place there). `VT_CACHE_DB_URL` stays available in `.env.example` for anyone who wants a real database instead.
- `misp-core`, `misp-modules`, `misp-guard`, `db`, `mail` are deleted outright from `deployment/compose_apps.yaml`, `deployment/compose_databases.yaml`, and `deployment/docker-compose.yml` — not commented out, not made optional. `redis` (in `compose_databases.yaml`) is unchanged and kept.
- `deployment/scripts/init.sh`'s `MISP_PATH` directory check, MISP `.env` bootstrapping, and automatic TLS-certificate-generation steps are removed (their only consumers — `misp-core`'s config mounts and HTTPS listener — no longer exist). `deployment/certificates/`, `scripts/openssl-certificates-generator.sh`, and the Makefile's `create-certs` target are NOT removed — kept available for manual/future use, just no longer auto-invoked.
- The `misp/` directory (`.env.example`, `guard/config.json` — config templates for the now-gone `MISP_PATH` mounts) is deleted.
- `app/MISP/vt_tools2misp.py` and the CLI's own MISP-submission flow are completely unchanged — only where the MISP instance it talks to is expected to run (external, documented via the repo-root `.env`'s `MISPURL`/`MISPKEY`/`MISPSSLVERIFY`) is a documentation change, in `deployment/README.md`.
- No reverse proxy/TLS wiring, no Vault/secrets-management system, no multi-replica scaling configuration, no CI-level Docker integration testing, no change to `AnalysisService`/`ValidationService`/`ReportCacheService`/`VirusTotalService`/the worker's `analyze_value` job beyond the one new `GET /health` endpoint — all explicitly out of scope per the design spec (`docs/superpowers/specs/2026-08-11-docker-deployment-design.md`).

---

### Task 1: `GET /health` endpoint

**Files:**
- Modify: `app/api/main.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `AnalysisService.check_cache(value, value_type) -> dict | None` (unchanged, from the earlier cache-config-dedup refactor), `request.app.state.redis` (an `ArqRedis` instance, already set up by `lifespan`).
- Produces: `GET /health` → `200 {"status": "ok"}` if both the cache backend and Redis are reachable, `503` otherwise. This is what Task 2's Docker `healthcheck:` directive calls via `curl`.

- [ ] **Step 1: Write the failing tests**

Add this class to `tests/test_api.py` (the file already imports `os`, `tempfile`, `unittest`, `mock`, `TestClient`, `DataValidator`, `app`, `SQLiteCacheBackend`, `AnalysisService`, `ReportCacheService`, `ValidationService` — no new imports needed). Place it anywhere after the existing imports, e.g. between `AnalyzeEndpointTests` and `JobStatusEndpointTests`:

```python
class HealthEndpointTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        os.remove(self.db_path)
        app.state.analysis = AnalysisService(
            validation=ValidationService(DataValidator()),
            virustotal=None,
            cache=ReportCacheService(SQLiteCacheBackend(self.db_path)),
        )
        app.state.redis = mock.Mock()
        app.state.redis.ping = mock.AsyncMock(return_value=True)
        self.client = TestClient(app)

    def tearDown(self):
        app.state.analysis.cache.backend.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_returns_ok_when_cache_and_redis_are_reachable(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_returns_503_when_redis_ping_fails(self):
        app.state.redis.ping = mock.AsyncMock(side_effect=Exception("connection refused"))
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)

    def test_returns_503_when_cache_backend_is_unreachable(self):
        # A closed sqlite3 connection raises ProgrammingError on any further
        # call - a real, verifiable "backend unreachable" condition, not a
        # mocked stand-in for one.
        app.state.analysis.cache.backend.close()
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 503)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `source .venv/bin/activate && python -W ignore -m unittest tests.test_api.HealthEndpointTests -v`
Expected: FAIL — `404` (route doesn't exist yet) instead of `200`/`503` for all three tests.

- [ ] **Step 3: Implement the endpoint**

Add this to `app/api/main.py`, immediately after `app = FastAPI(lifespan=lifespan)`:

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

No new imports needed — `HTTPException`, `Request`, `AnalysisService` are already imported in `app/api/main.py`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `source .venv/bin/activate && python -W ignore -m unittest tests.test_api -v`
Expected: PASS, all tests in the file (existing `AnalyzeEndpointTests`/`JobStatusEndpointTests` plus the 3 new `HealthEndpointTests`).

- [ ] **Step 5: Run the full suite and ruff**

```bash
source .venv/bin/activate
python -W ignore -m unittest discover -s tests -t . -v
ruff check .
```

Expected: full suite passes (expect 186 = 183 pre-B5 + 3 new tests), ruff clean.

- [ ] **Step 6: Commit**

```bash
git add app/api/main.py tests/test_api.py
git commit -m "feat: add GET /health endpoint for Docker healthchecks"
```

---

### Task 2: Dockerfile + Compose wiring (add vt-tool-api/worker, remove MISP's application stack)

**Files:**
- Modify: `Dockerfile`
- Modify: `deployment/compose_apps.yaml`
- Modify: `deployment/compose_databases.yaml`
- Modify: `deployment/docker-compose.yml`
- Modify: `deployment/.env.example`

**Interfaces:**
- Consumes: `GET /health` (Task 1, for the API healthcheck), `arq app.worker.settings.WorkerSettings --check` (a real, built-in arq CLI flag, confirmed against the installed library), `uvicorn app.api.main:app` (the ASGI app object Task 1 modified), the existing `redis` service (kept, unchanged in its own service definition).
- Produces: three runnable Compose services — `redis`, `vt-tool-api`, `vt-tool-worker` — the complete deployment stack (MISP's own containers are no longer part of it at all).

This task is not `unittest`-verifiable (it's Docker/YAML, not Python) — verification is `docker compose config` in this task; a real `docker compose up` smoke test is Task 4.

- [ ] **Step 1: Rewrite the Dockerfile**

Replace the entire contents of `Dockerfile` (currently references a `webapp/` directory that was never built and does a `git clone` instead of building from the local checkout):

```dockerfile
FROM python:3.11-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY

ENV https_proxy=${HTTPS_PROXY:-$HTTP_PROXY}
ENV http_proxy=${HTTP_PROXY:-$HTTPS_PROXY}

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY vt_tools.py init.py ./

EXPOSE 8080

CMD ["python", "vt_tools.py", "--help"]
```

(`curl` is kept — it's what the `vt-tool-api` service's healthcheck runs *inside* the container. `git`/`unzip` are dropped — nothing clones a repo anymore, the image is built directly from this checkout via `build: context: ../` in Step 4. The proxy `ARG`/`ENV` lines are unchanged from the original Dockerfile. `CMD` defaults to the CLI's own `--help` — a harmless default for anyone who runs the image directly without one of Compose's `command:` overrides.)

- [ ] **Step 2: Rewrite `deployment/compose_apps.yaml`**

Replace the entire contents of `deployment/compose_apps.yaml`:

```yaml
services:
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

networks:
  vt_tool_network:
    external: true
    name: ${NETWORK_NAME}

volumes:
  vt_tool_cache:
```

(This entirely replaces the old file's `vt_tool_web`/`misp-core`/`misp-modules`/`misp-guard`/`mail` blocks — none of those services exist in this file anymore.)

`REDIS_URL`'s value is built via Compose's own `${VAR:-default}` interpolation, not a literal `.env` line — `.env` files can't reference other variables within themselves, so this has to live in the `environment:` block, matching how `deployment/compose_databases.yaml`'s own `redis:` service already builds its `REDIS_PASSWORD` this same way.

`VT_CACHE_DB_URL: "${VT_CACHE_DB_URL:-sqlite:////app/data/vttools.sqlite}"` — Compose's `:-` operator supplies the default for both an unset AND an empty-string variable (shell semantics), so `.env.example`'s blank `VT_CACHE_DB_URL=` line correctly falls through to the volume-backed default. The four slashes are deliberate and verified directly (not assumed): SQLAlchemy's sqlite URL scheme is `sqlite:///` (3 literal slashes) followed by the path; for the absolute path `/app/data/vttools.sqlite`, that's `sqlite:///` + `/app/data/vttools.sqlite` = `sqlite:////app/data/vttools.sqlite` (4 slashes total before `app`) — confirmed via `sqlalchemy.create_engine("sqlite:////app/data/vttools.sqlite").url.database == "/app/data/vttools.sqlite"`.

The volume is mounted at `/app/data`, NOT `/app` — mounting a volume at `/app` (the `WORKDIR`, where `COPY app/ ./app/` etc. put the actual code) would shadow the application code with an empty named volume, breaking the container entirely. This was caught directly: an earlier draft of this plan used `/app` and it broke `docker compose up` (`ModuleNotFoundError` — the code was shadowed) during verification.

- [ ] **Step 3: Rewrite `deployment/compose_databases.yaml`**

Replace the entire contents of `deployment/compose_databases.yaml` (the current file's `db:` service — MariaDB, exclusively for `misp-core` — is removed; `redis` is unchanged):

```yaml
services:
  redis:
    init: true
    restart: always
    command: |
      sh -c '
        if [ "$${ENABLE_REDIS_EMPTY_PASSWORD:-false}" = "true" ]; then
          exec valkey-server
        else
          exec valkey-server --requirepass "$${REDIS_PASSWORD:-redispassword}"
        fi
      '
    environment:
      - "ENABLE_REDIS_EMPTY_PASSWORD=${ENABLE_REDIS_EMPTY_PASSWORD:-false}"
      - "REDIS_PASSWORD=${REDIS_PASSWORD:-redispassword}"
    healthcheck:
      test: |
        sh -c '
          if [ "$${ENABLE_REDIS_EMPTY_PASSWORD:-false}" = "true" ]; then
            valkey-cli -p $${REDIS_PORT:-6379} ping | grep -q PONG || exit 1
          else
            valkey-cli -a "$${REDIS_PASSWORD:-redispassword}" -p $${REDIS_PORT:-6379} ping | grep -q PONG || exit 1
          fi
        '
      interval: 2s
      timeout: 1s
      retries: 3
      start_period: 5s
      start_interval: 5s
    volumes:
      - cache_data:/data:Z
    networks:
      - vt_tool_network

volumes:
  cache_data:

networks:
  vt_tool_network:
    external: true
    name: ${NETWORK_NAME}
```

- [ ] **Step 4: Rewrite `deployment/docker-compose.yml`**

Replace the entire contents of `deployment/docker-compose.yml`:

```yaml
name: vt_tool
services:

  vt-tool-api:
    extends:
      file: compose_apps.yaml
      service: vt-tool-api
    image: ${REGISTRY_MIRROR_URL:-}ghcr.io/thalesgroup-cert/vt-tool-api:${VT_TOOL_API_VERSION:-latest}
    build:
      context: ../
      dockerfile: Dockerfile
    container_name: vt-tool-api
    depends_on:
      redis:
        condition: service_healthy

  vt-tool-worker:
    extends:
      file: compose_apps.yaml
      service: vt-tool-worker
    image: ${REGISTRY_MIRROR_URL:-}ghcr.io/thalesgroup-cert/vt-tool-api:${VT_TOOL_API_VERSION:-latest}
    build:
      context: ../
      dockerfile: Dockerfile
    container_name: vt-tool-worker
    depends_on:
      redis:
        condition: service_healthy

  redis:
    extends:
      file: compose_databases.yaml
      service: redis
    image: ${REGISTRY_MIRROR_URL:-}valkey/valkey:${REDIS_VERSION:-latest}
    container_name: redis
    restart: always
    healthcheck:
      test: "valkey-cli -a ${REDIS_PASSWORD:-redispassword} ping || exit 1"
      interval: 2s
      timeout: 1s
      retries: 10
      start_period: 30s

networks:
  vt_tool_network:
    external: true
    name: ${NETWORK_NAME}

volumes:
  cache_data:
  vt_tool_cache:
```

(Both `vt-tool-api`/`vt-tool-worker` use the SAME `image:` tag — one shared image, per the binding "one image, two commands" decision. `misp-core`/`misp-modules`/`misp-guard`/`db`/`mail` and their volumes (`db_data`, `db_log`, `misp_guard_ca`) are entirely gone from this file — this is a full replacement, not an incremental edit.)

- [ ] **Step 5: Rewrite `deployment/.env.example`**

Replace the entire contents of `deployment/.env.example`:

```
#############################################
# ENVIRONMENT TEMPLATE
#############################################

# --- Application versions ---
VT_TOOL_API_VERSION=latest
REDIS_VERSION=7.2

REGISTRY_MIRROR_URL=

# --- Application ports ---
VT_TOOL_API_PORT=8080
REDIS_PORT=6379

# --- REDIS ---
REDIS_PASSWORD=redispassword
ENABLE_REDIS_EMPTY_PASSWORD=false
VT_TOOL_REDIS_DB=1

# --- vt_tool cache ---
VT_CACHE_DB_URL=
VT_CACHE_TTL_HOURS=

# --- Network Configuration ---
DOMAIN_CORP=your.corporate.domain
NETWORK_NAME=vt_tool_net
NETWORK_SUBNET=172.30.0.0/16
NETWORK_GATEWAY=172.30.0.1
NETWORK_IP_RANGE=172.30.0.0/24

# (Optional proxies)
HTTP_PROXY=http://proxy.com:8080
HTTPS_PROXY=http://proxy.com:8080
NO_PROXY=localhost
```

(Removed: `DB_VERSION`, `MISP_VERSION`, `MISP_MODULES_VERSION`, `MISP_GUARD_VERSION`, `DB_PORT`, `GUARD_PORT`, `GUARD_ARGS`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `SMARTHOST_ADDRESS`, `SMARTHOST_PORT`, `SMARTHOST_USER`, `SMARTHOST_PASSWORD`, `SMARTHOST_ALIASES`, `ROOT_PATH`, `MISP_PATH`, `CA_PATH` — every one was consumed exclusively by a service or script step this plan removes; confirmed by grepping the whole `deployment/` directory for each before removing it. `VT_TOOL_WEB_VERSION`/`VT_TOOL_WEB_PORT` replaced with `VT_TOOL_API_VERSION`/`VT_TOOL_API_PORT`.)

- [ ] **Step 6: Validate the Compose configuration**

```bash
cd deployment
cp .env.example .env
docker compose --env-file .env -f docker-compose.yml config --quiet
echo "exit code: $?"
docker compose --env-file .env -f docker-compose.yml config --services
rm .env
```

Expected: exit code `0`; `config --services` lists exactly `redis`, `vt-tool-api`, `vt-tool-worker` — nothing else. (Unlike an earlier draft of this plan that kept the MISP services, this validates cleanly with no external `MISP_PATH`/`misp/.env` file needed at all — confirmed directly: with the MISP services removed, `docker compose config` no longer has any `env_file:` directive pointing outside this checkout.)

- [ ] **Step 7: Commit**

```bash
git add Dockerfile deployment/compose_apps.yaml deployment/compose_databases.yaml deployment/docker-compose.yml deployment/.env.example
git commit -m "feat: wire vt-tool-api/worker into Compose, remove MISP's app stack"
```

---

### Task 3: Remove dead scaffolding (init.sh, misp/ directory) and document external MISP

**Files:**
- Modify: `deployment/scripts/init.sh`
- Modify: `deployment/README.md`
- Delete: `misp/.env.example`
- Delete: `misp/guard/config.json`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: a `make init` that no longer references MISP or generates certificates nobody consumes anymore; a README that tells operators where MISP integration actually lives now.

- [ ] **Step 1: Rewrite `deployment/scripts/init.sh`**

Replace the entire contents of `deployment/scripts/init.sh`:

```sh
#!/usr/bin/env sh
set -eu

echo "============================================"
echo "      vt tool – CHECKLIST"
echo "============================================"

# -------------------------------------------------
# 1. Required binaries
# -------------------------------------------------
echo "[1/2] Checking required binaries..."

# Check for docker binary
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: docker"
fi

# Check that docker supports the compose subcommand
if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: Docker Compose is not available (docker compose subcommand required)"
fi

# Check curl
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: curl"
fi

echo "→ OK"

# -------------------------------------------------
# 2. Ensure .env exists
# -------------------------------------------------
echo "[2/2] Checking .env..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "→ .env created from .env.example"
    else
        echo "ERROR: Missing both .env and .env.example"
    fi
else
    echo "→ .env present"
fi

# Load environment variables
set -a
. ./.env
set +a

# -------------------------------------------------
# Completion
# -------------------------------------------------
echo "============================================"
echo "    CHECKLIST COMPLETED"
echo "    All required components are in place."
echo "    You can now modify:"
echo "        - .env for network and other settings"
echo "    Then run 'make deploy' to start the application."
echo "============================================"
```

(Removed: the old steps 3 "Directory structure check" (`MISP_PATH` existence), step 4 "Check misp ENV" (`MISP_PATH/.env` bootstrapping), and step 5 "Certificates" (TLS cert generation — its only consumer, `misp-core`'s HTTPS listener, is gone). Steps renumbered `[1/2]`/`[2/2]`. `deployment/scripts/openssl-certificates-generator.sh` itself is untouched and still exists for manual use; only the automatic invocation from `init.sh` is removed.)

Ensure the file keeps its executable bit: `chmod +x deployment/scripts/init.sh`.

- [ ] **Step 2: Remove the `misp/` directory**

```bash
git rm misp/.env.example misp/guard/config.json
```

(Use `git rm`, not a bare `rm -rf` — this is a deliberate, git-tracked removal, not a scratch file cleanup. If the `misp/guard/` directory becomes empty after this, that's fine; git doesn't track empty directories, so nothing further to do.)

- [ ] **Step 3: Add a MISP-integration note to `deployment/README.md`**

Add this new section immediately before the existing `## Project Structure` section:

```markdown
## MISP Integration

This stack does not run a local MISP instance. vt_tool's MISP-submission feature (`vt_tools.py`'s template-file workflow, implemented in `app/MISP/vt_tools2misp.py`) is configured independently of this deployment: set `MISPURL`, `MISPKEY`, and `MISPSSLVERIFY` in the repository's root-level `.env` file (see the root `.env.example`), pointed at whichever MISP instance you actually run. This deployment stack has no opinion about where that instance lives.

```

- [ ] **Step 4: Commit**

```bash
git add deployment/scripts/init.sh deployment/README.md
git commit -m "chore: drop MISP-specific setup steps, document external MISP"
```

(`git rm` from Step 2 stages the `misp/` deletions automatically — they'll be included in this commit alongside the `git add` files above. Confirm with `git status` before committing that both the deletions and the two modified files are staged together.)

---

### Task 4: Full verification pass

**Files:** none (verification only)

This task brings up the real, complete stack (`redis` + `vt-tool-api` + `vt-tool-worker` — the entire stack now, not a subset, since MISP's services are gone) and proves the whole chain works end to end against real Docker, not mocks.

- [ ] **Step 1: Full lint + test run from a clean shell**

```bash
cd <worktree>
source .venv/bin/activate
ruff check .
python -W ignore -m unittest discover -s tests -t . -v
```

Expected: ruff clean, full suite green (186 tests).

- [ ] **Step 2: CLI behavior spot-check — confirm `vt_tools.py --help` is unchanged**

No task in this plan touches `vt_tools.py`. Confirm:

```bash
git log --oneline -- vt_tools.py | head -3
```

Expected: the most recent commit touching `vt_tools.py` predates this plan's first commit. Then run `python vt_tools.py --help` once and visually confirm the full argument list is intact.

- [ ] **Step 3: Confirm `app/MISP/vt_tools2misp.py` is untouched**

```bash
git log --oneline -- app/MISP/ | head -3
```

Expected: the most recent commit touching `app/MISP/` predates this plan's first commit — this plan only changes deployment infrastructure and documentation around where a MISP instance lives, never the CLI's own MISP-submission code.

- [ ] **Step 4: Bring up the full stack for real**

```bash
cd deployment
cp .env.example .env
docker network inspect vt_tool_net >/dev/null 2>&1 || \
  docker network create --subnet=172.30.0.0/16 --gateway=172.30.0.1 --ip-range=172.30.0.0/24 vt_tool_net

docker compose --env-file .env up -d --build
```

Expected: builds the image from the local checkout (via `build: context: ../`), starts exactly three containers (`redis`, `vt-tool-api`, `vt-tool-worker`) — confirm with `docker compose --env-file .env ps` that nothing else came up (no `misp-core`, no `db`, etc. — there's nothing left in the file to start).

If port `8080` is already in use on the host by something unrelated, override it for this verification only: `VT_TOOL_API_PORT=<some other port> docker compose --env-file .env up -d --build`, and use that port in the subsequent `curl` commands.

- [ ] **Step 5: Wait for all three containers to report healthy**

```bash
timeout 90 sh -c 'until [ "$(docker inspect -f "{{.State.Health.Status}}" redis)" = "healthy" ] && \
  [ "$(docker inspect -f "{{.State.Health.Status}}" vt-tool-api)" = "healthy" ] && \
  [ "$(docker inspect -f "{{.State.Health.Status}}" vt-tool-worker)" = "healthy" ]; do sleep 2; done'
echo "all healthy: $?"
docker compose --env-file .env ps
```

Expected: `all healthy: 0`, and `docker compose ps` shows all three containers `(healthy)`. If this times out, run `docker compose --env-file .env logs vt-tool-api vt-tool-worker` to diagnose before proceeding — do not skip this step or treat a timeout as passing.

- [ ] **Step 6: Hit the real API's `/health` endpoint**

```bash
curl -sf http://127.0.0.1:8080/health   # or your overridden port from Step 4
echo
```

Expected: `{"status":"ok"}`.

- [ ] **Step 7: Submit a real analysis request end-to-end and confirm the job reaches the worker**

```bash
curl -s -X POST http://127.0.0.1:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"values": [{"value": "example.com", "value_type": "domains"}], "api_key": "fake-key-for-smoke-test"}'
echo
```

Expected: `[{"status":"queued","job_id":"<some-id>"}]` — a real cache miss, a real job enqueued into the real Redis, no mocks anywhere in this call path.

Extract the `job_id`, then poll its status:

```bash
JOB_ID="<paste the job_id from the previous response>"
sleep 3
curl -s "http://127.0.0.1:8080/jobs/${JOB_ID}"
echo
```

Expected: `{"status":"failed","report":null,"error":"..."}` — the worker picked up the job, tried to fetch from VirusTotal with the fake API key, and the resulting `VirusTotalAPIError` correctly surfaces as a failed job. This proves the full chain (API → Redis → worker → `VirusTotalClient`/`AnalysisService.analyze()` → job failure → `GET /jobs/{id}`) works end to end against real, running containers.

- [ ] **Step 8: Tear down**

```bash
docker compose --env-file .env down --remove-orphans
rm -f .env
docker network rm vt_tool_net 2>/dev/null || true
cd ..
```

Expected: clean teardown, no leftover containers (`docker ps -a | grep vt-tool` should show nothing afterward; `docker ps -a | grep redis` may still show OTHER, unrelated `redis`-named containers on a shared host — that's fine, only confirm the specific containers this stack created are gone).

- [ ] **Step 9: Confirm no stray files, clean working tree**

```bash
git status --short
```

Expected: empty (Step 4's `.env` and Step 8's teardown both stay outside version control — `.env` is already gitignored).

- [ ] **Step 10: Report to the user**

No commit for this step. Summarize: final test count, confirmation `vt_tools.py --help` and `app/MISP/vt_tools2misp.py` are both unchanged, confirmation the real Docker smoke test passed with exactly the three expected containers (no MISP services), and that this closes out sub-project B5 — the entire B1-B5 effort from the original brainstorm is now complete. Note explicitly what's still deferred: reverse proxy/TLS, Vault/secrets management, multi-replica scaling, a real (non-SQLite) database wired in by default, and CI-level Docker integration testing.

---

## Self-Review

**Spec coverage:** `GET /health` pinging cache + Redis (Task 1) ✅. One shared image, `vt-tool-api`/`vt-tool-worker` with different commands (Task 2) ✅. Stale `VT_TOOL_WEB_*`/`webapp/`/commented-out block replaced (Task 2) ✅. SQLite-on-shared-volume default at `/app/data`, `VT_CACHE_DB_URL` opt-out preserved (Task 2, Step 2) ✅. Redis reused via a distinct DB index (Task 2, Step 2's `VT_TOOL_REDIS_DB`) ✅. arq's built-in `--check` flag (Task 2, Step 2) ✅. `misp-core`/`misp-modules`/`misp-guard`/`db`/`mail` removed outright (Task 2, Steps 2-4) ✅. Their `.env.example` vars removed (Task 2, Step 5) ✅. `init.sh`'s MISP/cert steps removed, `misp/` deleted, README documents external MISP (Task 3) ✅. `deployment/certificates/`/`openssl-certificates-generator.sh`/`make create-certs` NOT removed — no task touches them ✅. `app/MISP/vt_tools2misp.py` untouched — no task modifies it, Task 4 Step 3 explicitly verifies this ✅. Real Docker verification, not just YAML validation (Task 4) ✅.

**Placeholder scan:** no TBD/TODO; every step shows complete file contents or exact commands.

**Type/signature consistency:** `GET /health`'s use of `AnalysisService.check_cache(value, value_type)` (Task 1) matches the existing signature exactly — no new methods needed on any service class. `uvicorn app.api.main:app` (Task 2's compose `command:`) matches the actual module path and `app` variable name in `app/api/main.py`. `arq app.worker.settings.WorkerSettings` (Task 2's compose `command:` and healthcheck) matches the actual module path and class name in `app/worker/settings.py`, confirmed by reading the file directly before writing this plan.

**Every file in this plan was verified against real Docker before being written down, not just reasoned about.** All four tasks' file contents (Dockerfile, all three Compose YAML files, `.env.example`, `init.sh`, the README addition) were applied to a scratch copy of the repo, validated with a real `docker compose config`, and brought up with real `docker compose up` — the full three-container stack reached healthy, `GET /health` returned 200, and a real `POST /analyze` → real Redis → real worker → real job-failure round trip succeeded end to end — before this plan was finalized. One real bug was caught this way and is already reflected in the plan text above: an earlier draft mounted the cache volume at `/app` instead of `/app/data`, which silently shadowed the application code and broke the container; this is now Task 2 Step 2's stated design, with the failure mode documented inline as the reason.

**One late-arriving scope addition, handled mid-planning rather than silently folded in:** the MISP-externalization work (removing `misp-core`/`misp-modules`/`misp-guard`/`db`/`mail`) was not part of this plan's first draft — it was raised by the user after the original vt-tool-api/vt-tool-worker design had already been dry-run verified working. That verification remained valid (none of it depended on the MISP services), so the addition was scoped via targeted questions (which services, whether to also remove now-dead `misp/`/cert-generation scaffolding), folded into the same design doc and this plan, and re-verified end to end with the full expanded scope before finalizing — rather than either ignoring the request or silently expanding scope without confirming exactly what "external" meant first (an early, overly broad interpretation would have removed `redis` too, which is wrong — it's vt_tool's own arq queue infrastructure, not MISP's).
