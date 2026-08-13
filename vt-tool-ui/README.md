# vt-tool-ui

React SPA frontend for `vt_tool`'s HTTP API/worker service (see the root
[`README.md`](../README.md#running-as-a-service) and
[`deployment/README.md`](../deployment/README.md)). Submits IOCs to
`POST /analyze`, polls `GET /jobs/{id}`, and renders KPI cards + a results
table. See `docs/superpowers/specs/2026-08-12-frontend-design.md` for the
full design.

## Requirements

Node `^20.19.0 || >=22.12.0`, `pnpm@9.15.0`. If your host Node is older, run
everything through Docker instead (see below).

## Local development

```bash
pnpm install
pnpm dev
```

By default this talks to `http://localhost:8080` (the API's default local
port). Override it at build time with a `.env` file (`VITE_API_BASE=...`) —
see `vite-env.d.ts` for the typed env keys.

## Configuring the API base URL

- **Local dev**: build-time, via Vite's `VITE_API_BASE` env var.
- **Docker**: runtime, via `window.__ENV__`. `docker/docker-entrypoint.sh`
  regenerates a served `env-config.js` from the container's environment
  (`VITE_API_BASE`) at startup, so one built image can be reconfigured per
  deployment without a rebuild — `src/shared/lib/runtimeEnv.ts` reads
  `window.__ENV__` first and falls back to the build-time value for local
  dev.

## API key

Entered on the Settings page (`/settings`) and stored only in the browser's
`localStorage` — never sent anywhere except as the `api_key` field on each
`/analyze` request, and never defaulted server-side.

## Testing

```bash
pnpm test          # vitest
pnpm run build      # tsc -b && vite build
pnpm run lint
```

e2e (`pnpm run test:e2e`, Playwright) needs a real browser install, which
does not work on `node:alpine` — run it via Playwright's official Docker
image (`mcr.microsoft.com/playwright:v1.60.0-noble`) instead, e.g.:

```bash
docker run --rm -v "$(pwd)":/app -w /app mcr.microsoft.com/playwright:v1.60.0-noble sh -c "
  npm install -g pnpm@9.15.0 && pnpm install && pnpm run build && pnpm run test:e2e
"
```
