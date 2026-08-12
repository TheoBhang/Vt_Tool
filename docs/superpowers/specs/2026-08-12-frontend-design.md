# vt_tool Frontend (v1) — Design

## Goal

Give vt_tool a real web frontend — a React SPA that submits IOCs for analysis
against the existing FastAPI backend (`app/api/main.py`), polls job status,
and displays results with the KPI/status-badge presentation the two
hackathon dashboard PRs (#11, #12) prototyped. This replaces those PRs
entirely rather than merging either — neither uses the FastAPI/arq service
this project already built in B4 (both shell out to the CLI via
`subprocess.run`), and both only handle IP addresses.

## Background: what prompted this

Two hackathon groups ("Lycée Jacquard") independently built near-identical
Flask/Jinja2 dashboards (PR #11, #12): upload a `.txt` file → shell out to
`vt_tools.py` → parse the resulting CSV → push to MISP → read back from MISP
as "source of truth" → render a results table with KPI cards and status
badges, plus a history page of past MISP events. Both PRs stay open per the
user's decision (superseded by this work, not merged) — see git history for
the review that extracted their good ideas.

**Real problems in both** (why this is a redo, not a patch): neither uses
the API/worker infrastructure this project already has; only IP addresses
are handled; PR #12 doesn't sanitize the uploaded filename before using it
in a filesystem path; PR #12 runs Flask with `debug=True`; PR #11 hardcodes
a static secret key in source; neither has tests.

**Good ideas kept from both, reimplemented properly:** KPI summary cards
(total/malicious/suspect/clean/unknown), per-row status badges with the
same score thresholds (`malicious_score` > 5 → MALICIOUS, > 0 → SUSPECT, 0 →
CLEAN, not-found → UNKNOWN), drag-and-drop upload, a pre-submit review step,
direct links out to the VT GUI per IOC, and (from PR #11 specifically) an
optional/toggleable extra step rather than forcing it — carried forward here
as "submission is always to the API, MISP push is a v2 concept, not forced
into v1 at all."

## Decisions made during brainstorming (binding, not open for re-litigation during implementation)

- **v1 excludes MISP push and history entirely.** Neither is a backend
  capability today (`app/api/main.py` has no MISP awareness; `MispService`
  is CSV-file-shaped and CLI-only; there's no "list past analyses"
  endpoint). Building either into the browser directly would mean exposing
  the MISP API key client-side — not acceptable. Both become a follow-up
  sub-project once v1 ships and is real.
- **Input: paste/type (textarea) + drag-and-drop file upload, both through
  the same client-side parser.** Not file-upload-only (loses quick
  copy-paste from a ticket) and not manual-form-only (too tedious for a
  batch).
- **Classification is deliberately shallow on the client.** `classifyIoc.ts`
  only decides which of the 4 base types (`ips`/`domains`/`urls`/`hashes`) a
  value looks like — it does NOT reimplement the server's denylist (private
  IPs, unsupported hash lengths, etc.). That logic stays exactly once, in
  `ValidationService`/`classify_or_raise` server-side. Misclassified/
  unsupported values come back as `status: "invalid"` from `/analyze` and
  are shown inline — no duplicated source of truth between client and
  server.
- **API key: user-entered, stored in browser `localStorage`, never a
  backend default.** Matches `/analyze`'s existing per-request `api_key`
  field exactly — no backend change needed. Rejected: a server-side env-var
  default, because that changes the API's contract, which is out of scope
  for this sub-project (v1 is frontend-only, no backend changes beyond
  CORS).
- **Docker deployment IS in scope for this sub-project**, not deferred — a
  `vt-tool-ui` service alongside `vt-tool-api`/`vt-tool-worker`/`redis` in
  `deployment/`, so this sub-project ends with something runnable via
  `docker compose up`, matching how B4 (API) and B5 (deployment) both
  shipped something concretely runnable.
- **Stack: React 19 + TypeScript + Vite + MUI + TanStack Query**, matching
  `suspicious-ui` exactly (not a lighter/leaner alternative). Chosen over a
  smaller custom-CSS build because this project explicitly wants
  harmonization with the sibling repo, the org already has this stack's
  expertise live in that repo, and MUI/TanStack Query's overhead pays for
  itself the moment MISP/history (v2) turn this into a real multi-page app.
- **CORS via `CORSMiddleware` on `app/api/main.py`, not a reverse proxy.**
  `suspicious-ui`'s own nginx config explicitly does NOT proxy `/api/*` —
  it relies on an external Traefik instance sitting in front of both
  services to unify origins. vt_tool's deployment doesn't have a reverse
  proxy yet (explicitly deferred in B5's final review). Adding CORS
  middleware is a few lines, self-contained, and doesn't make this
  sub-project depend on standing up a reverse proxy first.
- **Runtime env config is harmonized from `suspicious-ui`'s actual pattern**:
  an nginx `docker-entrypoint.d` script regenerates `env-config.js`
  (`window.__ENV__`) from the container's environment at container startup,
  read by a `runtimeEnv.ts` helper that falls back to Vite's build-time env
  for local dev. One built image, configured per deployment via `.env` —
  matches how every other service in `deployment/` already works.

## Architecture

`vt-tool-ui/` at the repo root, sibling to `app/` and `deployment/` — naming
matches the `vt-tool-api`/`vt-tool-worker` service names already established
in B4/B5. A single-page app with two routes (`/` analyze, `/settings` API
key entry), talking directly to the existing three API endpoints. No new
backend endpoints; the only backend change is adding `CORSMiddleware`.

```
Browser (vt-tool-ui, served by nginx)
   │  fetch (CORS-enabled)
   ▼
vt-tool-api (FastAPI) ── POST /analyze, GET /jobs/{id}, GET /health
   │
   ▼
Redis (arq queue) ── vt-tool-worker ── VirusTotal
```

## Components

```
vt-tool-ui/
├── Dockerfile                          # multi-stage: node build -> nginx:alpine serve
├── docker/
│   ├── nginx.conf                      # serve SPA, /healthz, no /api proxy (see CORS decision)
│   └── docker-entrypoint.sh            # regenerates env-config.js from container env at startup
├── package.json                        # pnpm, matching suspicious-ui's package manager
├── vite.config.ts
├── src/
│   ├── main.tsx
│   ├── app/
│   │   └── router.tsx                  # react-router: "/" -> AnalyzePage, "/settings" -> SettingsPage
│   ├── pages/
│   │   ├── AnalyzePage.tsx
│   │   └── SettingsPage.tsx            # API key entry/edit, stored in localStorage
│   ├── features/
│   │   └── analyze/
│   │       ├── components/
│   │       │   ├── IocInput.tsx        # textarea + react-dropzone upload, shared entry point
│   │       │   ├── IocReviewTable.tsx  # editable pre-submit list (fix type, drop a line)
│   │       │   ├── ResultsTable.tsx
│   │       │   ├── KpiCards.tsx
│   │       │   └── StatusBadge.tsx     # MALICIOUS/SUSPECT/CLEAN/UNKNOWN, threshold logic
│   │       ├── hooks/
│   │       │   ├── useAnalyze.ts       # TanStack Query mutation: POST /analyze
│   │       │   └── useJobPolling.ts    # TanStack Query query w/ refetchInterval: GET /jobs/{id}
│   │       └── lib/
│   │           └── classifyIoc.ts      # regex classifier: ips/domains/urls/hashes/unrecognized
│   ├── api/
│   │   ├── client.ts                   # axios instance, base URL from runtimeEnv
│   │   └── endpoints.ts                # analyze(), getJob(), health() - typed request/response
│   ├── shared/
│   │   ├── components/
│   │   │   └── ApiHealthIndicator.tsx  # polls /health, shows online/offline
│   │   └── lib/
│   │       └── runtimeEnv.ts           # harmonized verbatim from suspicious-ui's pattern
│   ├── styles/
│   └── test/
│       ├── setup.ts
│       └── fixtures.ts                 # sample AnalyzeResponse/JobStatus payloads
└── e2e/
    └── analyze.spec.ts                 # Playwright, mocked API (MSW or route interception)
```

**Backend change (`app/api/main.py`):** add `fastapi.middleware.cors.CORSMiddleware`,
origins configurable via an env var (default permissive for local dev,
tightenable in deployment) — the smallest change that makes the frontend
reachable at all, nothing else about the API's behavior changes.

## Data Flow

1. User pastes IOCs into a textarea or drops a `.txt` file into `IocInput`.
2. `classifyIoc.ts` splits lines and classifies each into `ips`/`domains`/
   `urls`/`hashes` (IPv4 regex; MD5/SHA1/SHA256 by hex length; URL by scheme
   prefix; else domain) or flags it `unrecognized`.
3. `IocReviewTable` shows the classified list before submission — the user
   can fix a misclassification, remove a line, or see the "N lines skipped"
   count for unrecognized entries. Nothing is submitted from here directly;
   this is a review step.
4. On confirm, `useAnalyze` calls `POST /analyze` with the reviewed list and
   the API key from `localStorage` (read via `SettingsPage`'s storage, not
   re-entered per request).
5. The response is one result per item: `hit` (report attached, render
   immediately), `invalid` (error attached, render immediately), or
   `queued` (`job_id` attached).
6. Each `queued` item is tracked by `useJobPolling`, which polls
   `GET /jobs/{job_id}` via TanStack Query's `refetchInterval` until the
   job reaches `complete` or `failed`.
7. Once every item has a terminal state, `ResultsTable` and `KpiCards`
   render from the full set: `KpiCards` counts by status
   (malicious/suspect/clean/unknown, computed from `report.malicious_score`/
   `report.total_scans` using the hackathon PRs' thresholds); `ResultsTable`
   shows one row per IOC with a `StatusBadge` and a direct VT GUI link
   (`https://www.virustotal.com/gui/...`, mirroring `build_virustotal_link`'s
   URL shape).

## Error Handling

- Network/API-unreachable at submit time: inline banner, input preserved —
  the user never loses what they typed or uploaded.
- `ApiHealthIndicator` polls `/health` independently and shows a persistent
  online/offline state in the app header.
- A `failed` job status (e.g. bad API key, VT error) renders inline on that
  row with the actual error string from `/jobs/{id}`'s `error` field — not
  a generic toast that hides which IOC failed and why.
- File upload: reject non-`.txt` client-side; 5MB size cap, matching the
  hackathon PRs' defensive practice, with a clear rejection message rather
  than a silent failure.
- Unrecognized lines are excluded from submission by default (never guessed
  at) and their count is surfaced in the review step.

## Testing

- **Vitest unit tests** for `classifyIoc.ts` — the single highest-risk file,
  since it's the one piece of logic genuinely reimplemented (in a different
  language) from a server-side concept. Full coverage per value type plus
  edge cases (mixed-case hashes, IPv6 — explicitly out of scope, see below —
  URLs with ports/paths, near-miss domains).
- **Vitest component tests** for `ResultsTable`/`KpiCards` — badge
  assignment at each threshold boundary, count math.
- **Playwright e2e** (`e2e/analyze.spec.ts`) against a mocked API (MSW or
  route interception) covering the submit → review → poll → results flow.
  Deliberately does not stand up a real backend — `deployment/scripts/
  ci-smoke.sh` already proves the real API/worker/Redis chain works; this
  suite only needs to prove the UI drives that chain correctly.

## Out of Scope

- MISP push and analysis history (v2 sub-project, needs new backend
  endpoints — see Decisions above).
- IPv6 classification/support — `DataValidator` itself doesn't support it
  today either; not this sub-project's job to add.
- Any change to `/analyze`'s or `/jobs/{id}`'s request/response shape.
- A reverse proxy / TLS termination in front of the whole stack (already an
  explicitly deferred item from B5; CORS is this sub-project's answer for
  now).
- Authentication/authorization on the frontend or API — out of scope for
  both this and the existing B4 API; the API key IS the only credential in
  play, exactly as today.
- Company branding/theming config (`VITE_COMPANY_*` style vars in
  `suspicious-ui`'s runtime env) — v1 only needs `VITE_API_BASE`.
