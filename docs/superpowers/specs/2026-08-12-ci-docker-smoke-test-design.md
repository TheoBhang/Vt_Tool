# CI Docker Integration Testing — Design

> Harmonized with `thalesgroup-cert/suspicious`'s CI conventions, scaled to vt_tool's actual deployment.

## Goal

Add a CI job that actually builds and boots vt_tool's Docker Compose stack
(`redis`/`vt-tool-api`/`vt-tool-worker`) and drives one request through the
full chain (API → Redis → worker → job status), so a change that breaks the
containerized deployment path — but not the plain `unittest` suite — fails
CI instead of surfacing only when someone runs `docker compose up` by hand.
This closes a gap explicitly flagged (but not required) by B5's final
whole-branch review, and follows the pattern already proven manually,
repeatedly, throughout the B5 session.

## Why harmonize with `suspicious`

`suspicious` (a sibling Thales CERT repo, same deployment conventions this
whole B5 effort was modeled on) already solved "boot the real stack in CI
and smoke-test it" via a separate `e2e-deploy.yml` workflow that calls a
`scripts/ci/bootstrap.sh` script: `trap`-based cleanup that always tears
down and dumps `docker compose logs` on failure, a bounded health-wait loop,
then a smoke script, with logs uploaded as a build artifact on failure.
vt_tool's stack is much simpler than suspicious's (no DB migrations, no
multi-tenant setup, no external-service stub) — this design borrows the
*pattern*, not suspicious's full complexity, and not its exact file layout
(vt_tool already has its own `deployment/scripts/` convention; the new
script lives there, not in a new top-level `scripts/ci/`).

## Architecture

A new `.github/workflows/e2e-deploy.yml`, separate from the existing
`ci.yml` (which stays untouched — lint + `unittest`, fast feedback). The new
workflow:

1. Checks out the repo, sets up `docker/setup-buildx-action`.
2. Runs a new `deployment/scripts/ci-smoke.sh` — the bootstrap/smoke script.
3. On failure, uploads the stack's captured Docker Compose logs as a build
   artifact (`docker-stack-log`).

`ci-smoke.sh` reuses vt_tool's existing conventions rather than
reimplementing them:

- Reuses `deployment/scripts/check-network.sh` for network creation (reads
  `NETWORK_NAME`/`NETWORK_SUBNET`/`NETWORK_GATEWAY`/`NETWORK_IP_RANGE` from
  `.env`, same as `make up`/`make deploy` already do) — not a second
  network-creation implementation.
- Copies `.env.example` → `.env` if missing, same as `init.sh` does.
- Brings the stack up via `docker compose --env-file .env -f
  docker-compose.yml up -d --build`, waits (bounded loop, not open-ended
  `sleep`) for all three containers to report `healthy` via
  `docker inspect -f '{{.State.Health.Status}}'`.
- Smoke sequence — the same one manually run (successfully, repeatedly)
  throughout this session's B5 work: `GET /health` (expect 200), `POST
  /analyze` with a fake API key (expect a queued `job_id`), poll `GET
  /jobs/{job_id}` (bounded loop) until it reaches `"failed"` — a fake key
  correctly surfacing as a failed job proves the full chain works without
  needing a real `VTAPIKEY` secret or touching real VT API quota.
- `trap`-based cleanup that always runs on exit (success or failure):
  captures `docker compose logs` to `deployment/ci-stack.log`, prints the
  tail of logs to stdout if the run failed (visible directly in the Actions
  log, not just the uploaded artifact), tears the stack down
  (`down --remove-orphans`), removes the generated `.env`. The network is
  intentionally NOT removed: it uses a fixed persistent name and
  `external: true` in `docker-compose.yml`, matching the `make up`/`make
  down` convention.
- `set -euo pipefail`; any step failing (including the health-wait loop
  timing out, or the job not reaching `"failed"`) is a hard CI failure.

## Data Flow

```
e2e-deploy.yml
  └─ checkout, setup-buildx-action
  └─ run deployment/scripts/ci-smoke.sh
       ├─ cp .env.example .env (if missing)
       ├─ ./check-network.sh
       ├─ docker compose up -d --build
       ├─ wait-until-healthy loop (redis, vt-tool-api, vt-tool-worker)
       ├─ curl GET /health
       ├─ curl POST /analyze  → job_id
       ├─ poll GET /jobs/{job_id} → "failed"
       └─ trap: capture logs, tear down, always
  └─ (on failure) upload deployment/ci-stack.log as build artifact
```

## Error Handling

- Any curl call failing (`curl -sf`), the health-wait loop exhausting its
  retries, or the job not reaching `"failed"` within its own bounded poll —
  each is an explicit non-zero exit with a descriptive message, not a
  silent pass-through.
- The `trap` guarantees teardown (containers, network, generated `.env`)
  runs even on a mid-script failure, so a failed CI run doesn't leave
  dangling state on the runner (irrelevant for ephemeral GitHub-hosted
  runners, but keeps the script equally safe to run locally).
- On failure, logs are both printed inline (fast triage from the Actions UI)
  and uploaded as an artifact (full detail, downloadable).

## Testing

The workflow run *is* the test — this is an integration/smoke test, not
something with its own unit tests. `ci-smoke.sh` is validated by running it
directly (locally, against real Docker, exactly as this session's manual B5
verification runs already did) before merging.

## Triggers

`pull_request` (any branch, matching `ci.yml`'s existing convention) + `push`
to `master` + `workflow_dispatch`. No path filtering — runs on every PR/push,
same as `ci.yml`, since a regression in the containerized path can originate
from a change anywhere in `app/` (e.g. `app/services/`), not just
`deployment/`. `timeout-minutes: 10` (suspicious uses 40 for its much
heavier Django/migrations stack; vt_tool's build+boot+smoke completes in
well under 2 minutes based on this session's repeated manual runs).

## Out of scope

- Using a real `VTAPIKEY` secret to verify an actual successful VT lookup —
  explicitly declined; fake-key wiring verification only (see design Q&A).
- DB migrations, multi-tenant/company generation, external-service
  stubbing — none of these apply to vt_tool's stack; suspicious needs them,
  vt_tool doesn't.
- Adding the `docker compose config -q` lint step to the existing `ci.yml`
  (a separate, smaller recommendation from B5's final review) — not
  requested here; this design is scoped to the full boot+smoke test only.
- Changing `ci.yml`'s existing lint/unittest job or its action versions.
