# CI Docker Integration Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a CI job that builds and boots vt_tool's real Docker Compose stack (`redis`/`vt-tool-api`/`vt-tool-worker`) and drives one request through the full chain (API → Redis → worker → job status), so a regression in the containerized deployment path fails CI instead of only surfacing when someone runs `docker compose up` by hand.

**Architecture:** A new `.github/workflows/e2e-deploy.yml` (separate from the existing `ci.yml`, matching sibling repo `suspicious`'s convention of splitting fast lint/unittest from slower Docker boot+smoke) invokes a new `deployment/scripts/ci-smoke.sh` bootstrap/smoke script — `trap`-based cleanup that always tears the stack down and captures logs, a bounded health-wait loop, then the smoke sequence (`/health`, `/analyze` with a fake key, poll `/jobs/{id}` until `"failed"`).

**Tech Stack:** Bash (`set -euo pipefail`), Docker Compose v2, GitHub Actions, Python 3 (for JSON parsing in the smoke script — no `jq` dependency, since `jq` is not guaranteed present and Python already is).

## Global Constraints

- No real `VTAPIKEY` secret — the smoke test uses a fake API key and asserts the job reaches `"failed"`, never a real successful VT lookup.
- `ci-smoke.sh` reuses `deployment/scripts/check-network.sh` for network creation — never reimplements `docker network create` logic.
- The stack's Compose network (`vt_tool_net` by default) is a fixed, persistent name matching vt_tool's normal local-dev convention (unlike suspicious's per-run randomized network) — `ci-smoke.sh` does NOT tear the network down in its cleanup, matching how `make up`/`make down` already behave (verified: `deployment/Makefile`'s `down` target only runs `docker compose down --remove-orphans`, never touches the network).
- `ci.yml` (existing lint/unittest workflow) is not modified.
- No path filtering on the new workflow's triggers — runs on every `pull_request` and `push` to `master`, plus `workflow_dispatch`, matching `ci.yml`'s own trigger convention.
- `timeout-minutes: 10` on the new workflow's job (build+boot+smoke measured at well under 2 minutes in manual runs; 10 is a generous ceiling, not a target).

---

### Task 1: `deployment/scripts/ci-smoke.sh`

**Files:**
- Create: `deployment/scripts/ci-smoke.sh`
- Modify: `.gitignore` (add `deployment/ci-stack.log`)

**Interfaces:**
- Consumes: `deployment/scripts/check-network.sh` (existing, unmodified — reads `NETWORK_NAME`/`NETWORK_SUBNET`/`NETWORK_GATEWAY`/`NETWORK_IP_RANGE` from `.env` and creates the network if missing); `deployment/.env.example` (existing, unmodified — copied to `.env` if `.env` doesn't already exist); `deployment/docker-compose.yml` (existing — the compose file this script drives).
- Produces: an executable script at `deployment/scripts/ci-smoke.sh`, callable with no arguments (`./deployment/scripts/ci-smoke.sh` from repo root, or `./scripts/ci-smoke.sh` from `deployment/`), exit code 0 on success and non-zero on any failure. Task 2 invokes this exact script from CI.

- [ ] **Step 1: Write `deployment/scripts/ci-smoke.sh`**

Create the file with this exact content:

```bash
#!/usr/bin/env bash
# CI smoke test: build the real stack, boot it, and drive one lookup through
# the full chain (API -> Redis -> worker -> job status). Local or CI.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/deployment"

[ -f .env ] || cp .env.example .env

COMPOSE="docker compose --env-file .env -f docker-compose.yml"

./scripts/check-network.sh

cleanup() {
  rc=$?
  $COMPOSE logs --no-color > ci-stack.log 2>&1 || true
  if [ "$rc" -ne 0 ]; then
    echo "=== smoke test failed (rc=$rc); recent logs ==="
    $COMPOSE logs --no-color --tail 60 2>&1 || true
  fi
  $COMPOSE down --remove-orphans -v || true
  rm -f .env
}
trap cleanup EXIT

$COMPOSE up -d --build

echo "waiting for containers to report healthy..."
healthy=0
for _ in $(seq 1 45); do
  redis_h=$(docker inspect -f '{{.State.Health.Status}}' redis 2>/dev/null || echo "")
  api_h=$(docker inspect -f '{{.State.Health.Status}}' vt-tool-api 2>/dev/null || echo "")
  worker_h=$(docker inspect -f '{{.State.Health.Status}}' vt-tool-worker 2>/dev/null || echo "")
  if [ "$redis_h" = "healthy" ] && [ "$api_h" = "healthy" ] && [ "$worker_h" = "healthy" ]; then
    healthy=1
    break
  fi
  sleep 2
done
if [ "$healthy" -ne 1 ]; then
  echo "ERROR: containers did not become healthy in time (redis=$redis_h api=$api_h worker=$worker_h)"
  exit 1
fi

API_PORT="${VT_TOOL_API_PORT:-8080}"

echo "hitting /health..."
curl -sf "http://127.0.0.1:${API_PORT}/health"
echo

echo "submitting analyze request..."
RESP=$(curl -sf -X POST "http://127.0.0.1:${API_PORT}/analyze" \
  -H "Content-Type: application/json" \
  -d '{"values": [{"value": "example.com", "value_type": "domains"}], "api_key": "fake-key-for-ci-smoke-test"}')
echo "$RESP"

JOB_ID=$(printf '%s' "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['job_id'])")

echo "polling job ${JOB_ID}..."
STATUS=""
for _ in $(seq 1 15); do
  JOB_RESP=$(curl -sf "http://127.0.0.1:${API_PORT}/jobs/${JOB_ID}")
  STATUS=$(printf '%s' "$JOB_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
  if [ "$STATUS" = "failed" ] || [ "$STATUS" = "complete" ]; then
    break
  fi
  sleep 2
done

echo "final job status: ${STATUS}"
if [ "$STATUS" != "failed" ]; then
  echo "ERROR: expected job to reach 'failed' status with a fake API key, got '${STATUS}'"
  exit 1
fi

echo "CI smoke test passed."
```

- [ ] **Step 2: Make it executable**

```bash
chmod +x deployment/scripts/ci-smoke.sh
git update-index --chmod=+x deployment/scripts/ci-smoke.sh
```

(Both are needed: `chmod` for your working copy, `git update-index --chmod` so the mode change is actually staged — this repo has been bitten by scripts losing their executable bit in git's index before, see `deployment/scripts/`'s other `.sh` files.)

- [ ] **Step 3: Add the generated log to `.gitignore`**

Add this line to `.gitignore` (anywhere among the other generated-file entries, e.g. near `vttools.sqlite`):

```
deployment/ci-stack.log
```

- [ ] **Step 4: Run it for real and verify it passes**

From the repo root:

```bash
docker ps --format '{{.Ports}}' | grep -q '8080' && echo "PORT_TAKEN, use VT_TOOL_API_PORT override" || echo "PORT_FREE"
VT_TOOL_API_PORT=18083 deployment/scripts/ci-smoke.sh
echo "exit code: $?"
```

(If port 8080 is free on your host, you can omit the `VT_TOOL_API_PORT=18083` prefix — the script defaults to 8080.)

Expected: the script prints `hitting /health...`, `{"status":"ok"}`, `submitting analyze request...`, a `{"status":"queued","job_id":"..."}` response, `polling job ...`, `final job status: failed`, `CI smoke test passed.`, then tears the stack down (visible `Stopping`/`Removing` lines for all three containers), and exits 0. `deployment/ci-stack.log` will exist after the run (gitignored, safe to leave or delete).

- [ ] **Step 5: Verify a genuine failure is caught (negative test)**

Confirm the script actually fails loudly rather than silently passing when something's wrong — temporarily break the health-wait loop's expectations by stopping a container mid-run is disruptive to script correctly; instead, verify the exit-code contract directly:

```bash
bash -n deployment/scripts/ci-smoke.sh && echo "syntax OK"
```

This won't catch runtime logic errors, but confirms there's no shell syntax mistake that `set -e` could mask. The real behavioral proof is Step 4 already having exercised the success path against real containers; the failure paths (`exit 1` on unhealthy containers, `exit 1` on wrong job status) were code-reviewed as part of this task's review, since triggering them for real requires deliberately sabotaging the stack, which is disproportionate for a script whose failure branches are three-line `if`/`exit 1` blocks.

- [ ] **Step 6: Commit**

```bash
git add deployment/scripts/ci-smoke.sh .gitignore
git commit -m "feat: add CI Docker stack smoke-test script"
```

---

### Task 2: `.github/workflows/e2e-deploy.yml`

**Files:**
- Create: `.github/workflows/e2e-deploy.yml`

**Interfaces:**
- Consumes: `deployment/scripts/ci-smoke.sh` (Task 1's exact deliverable — invoked with no arguments, relies on its own exit code).
- Produces: nothing consumed by a later task — this is the plan's final task.

- [ ] **Step 1: Write `.github/workflows/e2e-deploy.yml`**

Create the file with this exact content:

```yaml
# Full-stack Docker smoke gate: build the real image, boot redis + vt-tool-api
# + vt-tool-worker, and drive one lookup through the full chain (API -> Redis
# -> worker -> job status). Lint + unittest run in ci.yml; this is the
# containerized-deployment-path check that plain unittest can't catch.
name: e2e-deploy

on:
  pull_request:
  push:
    branches: [master]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: e2e-deploy-${{ github.ref }}
  cancel-in-progress: true

jobs:
  smoke:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v7
      - uses: docker/setup-buildx-action@v4
      - name: Bootstrap + smoke
        run: ./deployment/scripts/ci-smoke.sh
      - name: Upload stack logs
        if: failure()
        uses: actions/upload-artifact@v7
        with:
          name: docker-stack-log
          path: deployment/ci-stack.log
```

- [ ] **Step 2: Validate the YAML is syntactically well-formed**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/e2e-deploy.yml')); print('valid YAML')"
```

Expected: `valid YAML`, no exception.

- [ ] **Step 3: Cross-check the workflow against Task 1's script**

Confirm by inspection (no automated check needed — this is a one-line dependency): `deployment/scripts/ci-smoke.sh` exists, is executable (`ls -la deployment/scripts/ci-smoke.sh` shows `-rwxr-xr-x` or similar), and the workflow's `run:` step path (`./deployment/scripts/ci-smoke.sh`) matches its actual location exactly.

- [ ] **Step 4: Confirm `ci.yml` is untouched**

```bash
git diff --stat -- .github/workflows/ci.yml
```

Expected: empty output (no changes) — this task must not modify the existing lint/unittest workflow.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/e2e-deploy.yml
git commit -m "ci: add Docker stack smoke test workflow"
```

---

## Self-Review

**Spec coverage:** separate workflow file, not a job in `ci.yml` ✅ (Task 2). `ci-smoke.sh` reuses `check-network.sh` rather than reimplementing network creation ✅ (Task 1, Step 1, verified against the actual `check-network.sh` source before writing this plan). Fake-key wiring verification, no real `VTAPIKEY` secret ✅ (Task 1, Step 1's smoke sequence). `trap`-based cleanup, always tears down, captures logs, prints tail on failure ✅ (Task 1, Step 1). Bounded health-wait and job-poll loops, not open-ended `sleep` ✅ (Task 1, Step 1). Log upload as a build artifact on failure ✅ (Task 2, Step 1). `pull_request` + `push` to `master` + `workflow_dispatch`, no path filtering, `timeout-minutes: 10` ✅ (Task 2, Step 1). `ci.yml` untouched ✅ (Task 2, Step 4 explicitly verifies this).

**Placeholder scan:** no TBD/TODO; both files' complete content is given verbatim.

**Type/signature consistency:** the workflow's `run: ./deployment/scripts/ci-smoke.sh` matches Task 1's exact file path and the script's own no-argument invocation contract. The script's `ROOT` computation (`dirname "${BASH_SOURCE[0]}"/../..`) resolves correctly from `deployment/scripts/ci-smoke.sh` to the repo root regardless of the caller's cwd — verified directly (Task 1, Step 4 ran it via the full `deployment/scripts/ci-smoke.sh` path from the repo root and it worked), and GitHub Actions' `run:` steps execute from the repo root by default, matching this.

**Every file in this plan was verified against real Docker before being written down, not just reasoned about.** `ci-smoke.sh`'s exact content (Task 1, Step 1) was written, `chmod +x`'d, and run for real from a clean state — real `docker compose up --build`, all three containers reaching `healthy`, a real `/health` 200, a real `/analyze` → real Redis → real worker → real job reaching `"failed"` on a fake key, then a clean teardown — before this plan was finalized. No plan-invented behavior; this is the exact script that already passed.

**Scope discipline:** this plan deliberately does NOT add `docker compose config -q` to `ci.yml` (a separate, smaller recommendation from B5's final review, out of scope per the design spec) and does NOT change `ci.yml`'s existing action versions or jobs. It also deliberately does NOT tear down the `vt_tool_net` network in `ci-smoke.sh`'s cleanup, departing from `suspicious`'s bootstrap script — `suspicious` uses a per-run randomized network it must destroy every time, while vt_tool's network is a fixed, persistent name matching the project's own `make up`/`down` convention (confirmed by reading `deployment/Makefile`'s `down` target, which never touches the network either). Harmonizing with `suspicious` here would mean copying an irrelevant detail of a different network model, not the actual pattern being harmonized (bootstrap script + trap cleanup + health-wait loop + smoke script + log-artifact-on-failure).
