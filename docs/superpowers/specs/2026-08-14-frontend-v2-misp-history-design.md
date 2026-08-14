# vt_tool Frontend v2 — MISP Push & Analysis History — Design

## Goal

Give `vt-tool-ui` the two capabilities v1 explicitly deferred: pushing
analyzed IOCs to MISP, and viewing past analyses. Both were named as a
follow-up sub-project in v1's design spec (`2026-08-12-frontend-design.md`)
because neither was a backend capability at the time, and building MISP
push into the browser directly would mean exposing the MISP API key
client-side — not acceptable then, still not acceptable now. This spec
keeps that constraint: MISP credentials never leave the server.

## Background

v1 shipped a React SPA over the existing FastAPI/arq backend: paste/upload
IOCs, classify, review, submit, poll job status, see KPI cards and a
results table with VT links. `MISPURL`/`MISPKEY` already exist as
server-side environment variables — the CLI (`app/MISP/vt_tools2misp.py`)
already builds `MISPObject`s from analyzed data (`MispService`) and submits
them via `ExpandedPyMISP`, but only from a CSV file the CLI itself wrote,
identifying the MISP object type by regex-matching the CSV *filename*
(`identify_object_type`). There is no "list past analyses" capability
anywhere in the tool today — the SQLite cache (`vttools.sqlite`) caches
individual IOC lookups by value, not analysis batches, and has no
audit-trail concept.

## Decisions made during brainstorming (binding, not open for re-litigation during implementation)

- **MISP push and history ship together as one sub-project**, not split
  into two. They share backend plumbing (the same stored analysis record
  is what gets listed in history and what gets pushed to MISP).
- **History is local, not MISP-sourced.** Every submitted batch is
  recorded in a new local table the moment its results all resolve,
  regardless of whether it's ever pushed to MISP — not a read-back of past
  MISP events (which was one of the two abandoned hackathon PRs' approach,
  and was explicitly not carried forward: MISP stays a push-only,
  optional destination, never a source of truth this frontend depends on
  for its own display).
- **Push happens from the results view, right after analyzing** (and
  identically from a past, not-yet-pushed history entry) — not
  history-only. Matches v1's "MISP push is optional/toggleable, not
  forced" carryover from the hackathon PRs.
- **Save-to-history is client-driven, not server-tracked.** The frontend
  already knows when a batch is fully resolved (`AnalyzePage`'s
  `allResolved`); at that moment it calls `POST /analyses` itself. This
  was chosen over having the server track batch completion from
  submission time (which would require the arq worker to report
  completion back into a batch record) because it's a much smaller diff,
  touches none of the existing job/worker pipeline, and the accepted
  trade-off — a batch is never saved if the browser tab closes before
  every item resolves — is minor for an internal triage tool.
- **The case ID is one field, not two.** vt_tool's CLI already uses a
  single case_id that doubles as the MISP event ID (reuse if it matches an
  existing event, create otherwise). The web UI carries this forward
  exactly: one optional text field, shown at push time, that both
  identifies/creates the MISP event AND becomes that analysis's
  `case_label` in history. Before a push happens, an auto-saved history
  entry has no label — just its timestamp.
- **MISP push reuses the CLI's existing functions, not a rewrite.**
  `get_misp_event()` and `submit_misp_objects()` in
  `app/MISP/vt_tools2misp.py` already take an `ExpandedPyMISP` instance as
  a parameter — only their *callers* are CLI-specific (interactive
  `Prompt.ask` calls). The API path constructs its own `ExpandedPyMISP`
  from the existing `MISPURL`/`MISPKEY` env vars and calls the same
  functions directly. Two small extractions make this possible: the
  ~80-line `attribute_type_mapping` dict (currently a local variable
  inside a CLI-only function) is promoted to a shared constant on
  `MispService`; a new small `value_type → MISP object name` mapping
  (`ips→ip-port`, `domains→domain-ip`, `urls→url`, `hashes→file`) is added
  alongside it, replacing filename-regex detection for this path — the API
  already knows the value type directly, no need to sniff a filename that
  doesn't exist in this flow.
- **A partial push is not a failed push.** If `MispService.create_object`
  can't build an object from a stored item (bad/missing data), that item
  is skipped and counted in the response (`skipped_count`), not treated as
  a hard failure of the whole push — matches `MispService`'s own existing
  per-row defensive behavior (it already returns `None` and logs on a
  per-row failure, never raises).
- **No auth, no per-user scoping.** Same stance as v1: this tool has no
  user identity today, so history is one shared list, exactly like MISP
  events are already shared across whoever uses a given MISP instance.
- **No retention/expiry policy for this sub-project.** History rows are
  kept indefinitely, same as the cache's TTL was its own separate, later
  concern in the original architecture — not bundled into this work.
- **No edit/delete on history entries**, beyond the push flow's own
  side effect of setting `case_label`/`misp_event_id` on push (that's part
  of the push action itself, not a general-purpose edit capability — there
  is no separate "rename this entry" or "delete this entry" UI/endpoint).
  Audit-trail semantics: what was analyzed and what happened to it, not a
  working document a user modifies after the fact.
- **Re-running a past analysis against VT again is out of scope.** History
  shows what was true at save/push time; refreshing it against a live VT
  lookup is a different feature, not this one.

## Architecture

```
Browser (vt-tool-ui)
   │
   ├─ existing: POST /analyze, GET /jobs/{id}, GET /health
   │
   ├─ POST /analyses              (save a finished batch)
   ├─ GET  /analyses               (paginated history list)
   ├─ GET  /analyses/{id}          (one batch's full detail)
   └─ POST /analyses/{id}/misp-push (push that batch to MISP)
        │
        ▼
   vt-tool-api (FastAPI)
        │
        ├─ HistoryService ── vttools.sqlite: new `analyses` table
        │
        └─ MISP push path ── ExpandedPyMISP(MISPURL, MISPKEY, ...)
                              (constructed the same way the CLI already
                               does today — no new connection config)
                              ── get_misp_event() / submit_misp_objects()
                                 (existing, from app/MISP/vt_tools2misp.py)
                              ── MispService.create_object() per item
                                 (existing, object-shaping only)
```

No changes to the arq worker or the existing `/analyze`/`/jobs/{id}`
contract. `MISPURL`/`MISPKEY` stay exactly where they are today
(server-side env vars) — this sub-project adds no new credential handling.

## Backend

**New:** `app/services/history_service.py` (`HistoryService`) — raw
`sqlite3` against the existing `vttools.sqlite`, following the same
one-class-per-concern convention as `DBHandler`/`VTReporter`/`MispService`.
New table `analyses`:

```sql
CREATE TABLE analyses (
    id TEXT PRIMARY KEY,          -- uuid4
    case_label TEXT,              -- nullable until pushed with a case ID
    created_at TEXT NOT NULL,     -- ISO 8601
    items TEXT NOT NULL,          -- JSON: [{value, value_type, report, error}]
    misp_event_id TEXT            -- nullable until pushed
);
```

`HistoryService` methods: `save(items, case_label=None) -> str` (returns
new id), `list(limit, offset) -> list[summary]`, `get(id) -> detail | None`,
`set_misp_event_id(id, event_id, case_label)`.

**Modified:** `MispService` (`app/services/misp_service.py`) gains the
promoted `ATTRIBUTE_TYPE_MAPPING` constant (moved from its current home
inside `process_and_submit_to_misp`'s local scope in
`app/MISP/vt_tools2misp.py`, that function updated to reference the
shared constant instead of redefining it) and a new
`OBJECT_NAME_BY_VALUE_TYPE` mapping (`{"ips": "ip-port", "domains":
"domain-ip", "urls": "url", "hashes": "file"}`).

**New endpoints** (`app/api/main.py`):

- `POST /analyses` — body `{case_label?: str, items: [{value, value_type,
  report, error?}]}` → `{id, created_at}`.
- `GET /analyses?limit=&offset=` — `limit` capped server-side (max 100,
  default 20) → `[{id, case_label, created_at, item_count,
  misp_event_id}]`.
- `GET /analyses/{id}` → full detail (`items` included) or 404.
- `POST /analyses/{id}/misp-push` — body `{case_id?: str}` →
  `{event_id, pushed_count, skipped_count}`, or 502/503 with a clear
  message if `MISPURL`/`MISPKEY` are unset or MISP is unreachable, or 404
  if the analysis id doesn't exist.

## Frontend

- **New route `/history`** → `HistoryPage.tsx`: paginated table of past
  analyses (case label or "—", timestamp, item count, MISP status —
  "Not pushed" or "Pushed as event #NNN"), each row linking to detail.
- **New route `/history/:id`** → `AnalysisDetailPage.tsx`: fetches
  `GET /analyses/{id}`, renders it read-only through the *same*
  `KpiCards`/`ResultsTable` components the Analyze flow already uses. If
  not yet pushed, shows the same case-ID field + "Push to MISP" control as
  the live results page.
- **`AnalyzePage.tsx`**: once `allResolved` is true, silently fires
  `useSaveAnalysis()` (`POST /analyses`) — no user action. The results
  view then shows an optional case-ID text field + "Push to MISP" button
  (`useMispPush(analysisId)` → `POST /analyses/{id}/misp-push`).
- **Nav bar** (`router.tsx`): "History" link alongside "Analyze"/
  "Settings".
- **`src/api/endpoints.ts`**: `saveAnalysis()`, `listAnalyses()`,
  `getAnalysis()`, `pushToMisp()`, and their types (`AnalysisSummary`,
  `AnalysisDetail`, `MispPushResult`).
- **New hooks** (matching `useAnalyze`/`useJobPolling`'s existing style):
  `useSaveAnalysis()`, `useAnalysisHistory()` (paginated query),
  `useAnalysis(id)`, `useMispPush(id)`.

## Data Flow

1. User submits IOCs on `/` — identical to v1 (paste/drop → classify →
   review → `POST /analyze` → poll).
2. Once every item resolves, `AnalyzePage` fires `useSaveAnalysis()` in
   the background. The batch is now in history, unlabeled, un-pushed.
3. The results view shows a case-ID field (optional) and "Push to MISP"
   button. On click, `useMispPush(analysisId)` sends the typed case ID (or
   none) to `POST /analyses/{id}/misp-push`.
4. Backend builds MISP objects from the *stored* batch (not re-fetched
   from VT), gets-or-creates the MISP event via `get_misp_event`, submits
   via `submit_misp_objects`, records `misp_event_id` (and `case_label` if
   a case ID was given) on the analysis row, returns push/skip counts.
5. Frontend shows "Pushed as event #NNN (8/10 items — 2 skipped)" inline;
   the same info shows up later on `/history`.
6. From `/history`, clicking a past unpushed analysis lands on
   `/history/:id`, which supports the identical push flow as steps 3–5,
   operating on stored data instead of a live batch.

## Error Handling

- `MISPURL`/`MISPKEY` unset or MISP unreachable at push time: the push
  endpoint returns a clear 502/503 with the underlying reason; shown
  inline on the push control's row. The batch stays in history untouched
  (already saved) so the user can retry once MISP is reachable.
- `POST /analyses` (the auto-save) failing is non-fatal to the analyze
  flow — the user still sees their results; a small inline note ("Couldn't
  save to history") appears rather than blocking anything, since results
  are the primary value and history is secondary.
- `GET /analyses/{id}` for a deleted/nonexistent id: 404 → `/history/:id`
  shows a "not found" state rather than crashing.
- `GET /analyses` pagination: `limit` capped server-side to avoid an
  accidental unbounded query.

## Testing

Same pattern as v1: pytest for `HistoryService` (save/list/get against a
real SQLite connection) and the new endpoints in `tests/test_api.py`
(including a mocked-MISP-unreachable case for the push endpoint); Vitest
for the new hooks/components (`useSaveAnalysis`, `useAnalysisHistory`,
`useAnalysis`, `useMispPush`, `HistoryPage`, `AnalysisDetailPage`); one
additional Playwright e2e spec covering submit → auto-save → push → visit
history → see it there, against a mocked API — no real MISP in e2e,
matching v1's "mock the API, don't stand up the real chain" testing
decision.

## Out of Scope

- Editing or deleting history entries.
- Any history retention/expiry policy.
- Per-user history scoping (no auth exists in this tool today).
- Re-running/refreshing a past analysis against VT again.
- Any change to `/analyze`'s or `/jobs/{id}`'s existing request/response
  shape.
- MISP event *reading* beyond what a push's response returns (no
  "browse existing MISP events" UI — history is this tool's own local
  record, not a MISP browser).
