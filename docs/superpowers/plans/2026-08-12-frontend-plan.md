# vt_tool Frontend (v1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a React SPA (`vt-tool-ui/`) that submits IOCs to vt_tool's existing FastAPI backend, polls job status, and displays results with KPI cards and status badges — replacing the two abandoned hackathon Flask dashboard PRs (#11, #12) — and wire it into the Docker Compose deployment alongside `vt-tool-api`/`vt-tool-worker`/`redis`.

**Architecture:** React 19 + TypeScript + Vite + MUI + TanStack Query, harmonized with sibling repo `suspicious-ui`'s stack and Docker packaging pattern (multi-stage build, nginx serve, runtime env injection via `window.__ENV__`). Talks directly to the existing three API endpoints (`POST /analyze`, `GET /jobs/{id}`, `GET /health`) — no new backend endpoints except CORS middleware.

**Tech Stack:** React 19.2.6, TypeScript 6.0.3, Vite 8.0.16, MUI 9.0.1, TanStack Query 5.100.11, react-router-dom 7.15.1, react-hook-form 7.76.0 + zod 4.4.3, react-dropzone 15.0.0, axios 1.16.1, Vitest 4.1.8 + Testing Library, Playwright 1.60.0. **Every one of these exact versions was verified together for real** (installed, built, and run in a `node:22-alpine` container) before being written into this plan — see the design spec's background for what was checked.

## Global Constraints

- v1 excludes MISP push and analysis history entirely — no new backend endpoints beyond CORS (see design spec's binding decisions).
- `classifyIoc` only decides which of the 4 base types a value looks like — it must NOT reimplement the server's denylist (private IPs, unsupported hash lengths). Unsupported values are submitted anyway and come back `status: "invalid"` from the API.
- API key lives only in browser `localStorage`, entered via `SettingsPage` — never a backend default, never sent anywhere except the `/analyze` request body.
- Runtime config (`VITE_API_BASE`) is read via `window.__ENV__` (container-injected at startup) falling back to Vite's build-time env — one built image works across deployments without rebuilding.
- `deployment/scripts/ci-smoke.sh` and the existing `tests/test_api.py` suite already prove the backend chain works — this plan's e2e tests mock the API rather than re-proving that.
- `pnpm@9.15.0` is the package manager (matches what was verified); Node `^20.19.0 || >=22.12.0` (matches `suspicious-ui`'s floor — this host may have an older Node locally, but the real build always happens inside `node:22-alpine`, per this plan's own verification method).

---

### Task 1: Project scaffold, app shell, routing skeleton

**Files:**
- Create: `vt-tool-ui/package.json`
- Create: `vt-tool-ui/tsconfig.json`
- Create: `vt-tool-ui/tsconfig.app.json`
- Create: `vt-tool-ui/vite.config.ts`
- Create: `vt-tool-ui/index.html`
- Create: `vt-tool-ui/eslint.config.js`
- Create: `vt-tool-ui/.gitignore`
- Create: `vt-tool-ui/src/main.tsx`
- Create: `vt-tool-ui/src/App.tsx`
- Create: `vt-tool-ui/src/app/router.tsx`
- Create: `vt-tool-ui/src/pages/AnalyzePage.tsx`
- Create: `vt-tool-ui/src/pages/SettingsPage.tsx`
- Create: `vt-tool-ui/src/test/setup.ts`
- Test: `vt-tool-ui/src/App.test.tsx`

**Interfaces:**
- Consumes: nothing from earlier tasks (this is the foundation).
- Produces: `AnalyzePage`/`SettingsPage` as stub components later tasks fill in (Task 8 replaces their bodies — the exported component names and file paths are the contract other tasks rely on). `App.tsx`'s theme/query-client/router wiring is what every later UI task renders inside.

- [ ] **Step 1: Create the package manifest and toolchain config**

`vt-tool-ui/package.json`:

```json
{
  "name": "vt-tool-ui",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "packageManager": "pnpm@9.15.0",
  "engines": {
    "node": "^20.19.0 || >=22.12.0"
  },
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview",
    "lint": "eslint .",
    "test": "vitest run",
    "test:e2e": "playwright test"
  },
  "dependencies": {
    "@emotion/react": "11.14.0",
    "@emotion/styled": "11.14.1",
    "@hookform/resolvers": "5.2.2",
    "@mui/icons-material": "9.0.1",
    "@mui/material": "9.0.1",
    "@tanstack/react-query": "5.100.11",
    "axios": "1.16.1",
    "react": "19.2.6",
    "react-dom": "19.2.6",
    "react-dropzone": "15.0.0",
    "react-hook-form": "7.76.0",
    "react-router-dom": "7.15.1",
    "zod": "4.4.3"
  },
  "devDependencies": {
    "@eslint/js": "10.0.1",
    "@playwright/test": "1.60.0",
    "@testing-library/jest-dom": "6.9.1",
    "@testing-library/react": "16.3.2",
    "@testing-library/user-event": "14.6.1",
    "@types/node": "25.9.0",
    "@types/react": "19.2.14",
    "@types/react-dom": "19.2.3",
    "@vitejs/plugin-react": "6.0.2",
    "eslint": "10.4.0",
    "eslint-plugin-react-hooks": "7.1.1",
    "eslint-plugin-react-refresh": "0.5.2",
    "globals": "17.6.0",
    "jsdom": "29.1.1",
    "typescript": "6.0.3",
    "typescript-eslint": "8.59.4",
    "vite": "8.0.16",
    "vitest": "4.1.8"
  }
}
```

`vt-tool-ui/tsconfig.json`:

```json
{
  "files": [],
  "references": [
    { "path": "./tsconfig.app.json" }
  ]
}
```

`vt-tool-ui/tsconfig.app.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "useDefineForClassFields": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"]
}
```

`vt-tool-ui/vite.config.ts`:

```ts
/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
  },
});
```

`vt-tool-ui/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>vt_tool</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`vt-tool-ui/eslint.config.js`:

```js
import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
    },
  },
);
```

`vt-tool-ui/.gitignore`:

```
node_modules/
dist/
dist-ssr/
*.local
.pnpm-store/
playwright-report/
test-results/
```

- [ ] **Step 2: Create the app shell, routing skeleton, and stub pages**

`vt-tool-ui/src/pages/AnalyzePage.tsx`:

```tsx
export default function AnalyzePage() {
  return <h1>Analyze</h1>;
}
```

`vt-tool-ui/src/pages/SettingsPage.tsx`:

```tsx
export default function SettingsPage() {
  return <h1>Settings</h1>;
}
```

`vt-tool-ui/src/app/router.tsx`:

```tsx
import { Route, Routes } from "react-router-dom";
import AnalyzePage from "../pages/AnalyzePage";
import SettingsPage from "../pages/SettingsPage";

export function AppRouter() {
  return (
    <Routes>
      <Route path="/" element={<AnalyzePage />} />
      <Route path="/settings" element={<SettingsPage />} />
    </Routes>
  );
}
```

`vt-tool-ui/src/App.tsx`:

```tsx
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { AppRouter } from "./app/router";

const theme = createTheme({ palette: { mode: "dark" } });
const queryClient = new QueryClient();

export default function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AppRouter />
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
```

`vt-tool-ui/src/main.tsx`:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

`vt-tool-ui/src/test/setup.ts`:

```ts
import "@testing-library/jest-dom/vitest";
```

- [ ] **Step 3: Write the failing smoke test**

`vt-tool-ui/src/App.test.tsx`:

```tsx
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import App from "./App";

describe("App", () => {
  it("renders the Analyze page at the root route", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Analyze" })).toBeInTheDocument();
  });
});
```

- [ ] **Step 4: Install dependencies and verify the test fails correctly first, then passes**

From `vt-tool-ui/`, using a pinned Node 22 (this host's Node may be older — do this inside `node:22-alpine` if `node --version` here is below 20):

```bash
docker run --rm -v "$(pwd)":/app -w /app node:22-alpine sh -c "
  npm install -g pnpm@9.15.0 &&
  pnpm install &&
  pnpm test &&
  pnpm run build &&
  pnpm run lint
"
```

Expected: `pnpm install` resolves all 33 dependencies with no errors, `pnpm test` shows 1 passed test, `pnpm run build` produces `dist/` with no TypeScript errors, `pnpm run lint` reports no errors.

- [ ] **Step 5: Commit**

```bash
git add vt-tool-ui/
git commit -m "feat: scaffold vt-tool-ui (React+Vite+TS app shell, routing)"
```

---

### Task 2: Backend CORS middleware

**Files:**
- Modify: `app/api/main.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: nothing from Task 1 (independent, backend-only).
- Produces: `app` (the FastAPI instance) now has CORS enabled — Task 9's Docker wiring will set the `CORS_ALLOWED_ORIGINS` env var this task reads.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_api.py` (new test class; the file already imports `unittest`, `mock`, `TestClient`, `app` — reuse those):

```python
class CorsTests(unittest.TestCase):
    def test_allows_configured_origin(self):
        with mock.patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://localhost:5173"}):
            import importlib
            import app.api.main as main_module
            importlib.reload(main_module)
            client = TestClient(main_module.app)
            response = client.options(
                "/analyze",
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "POST",
                },
            )
            self.assertEqual(
                response.headers.get("access-control-allow-origin"), "http://localhost:5173"
            )
            importlib.reload(main_module)
```

(The `importlib.reload` calls are necessary because `CORSMiddleware` is added once at module import time — reload after patching the env var so the middleware picks up the new origin list, then reload again afterward to restore the module to its default state for other tests in this file, which import the module-level `app` directly.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/forensics/vt_tool && source .venv/bin/activate && python -W ignore -m unittest tests.test_api.CorsTests -v`
Expected: FAIL — no `Access-Control-Allow-Origin` header present (CORS middleware doesn't exist yet).

- [ ] **Step 3: Add CORS middleware**

In `app/api/main.py`, add after the existing imports:

```python
from fastapi.middleware.cors import CORSMiddleware
```

And immediately after `app = FastAPI(lifespan=lifespan)`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "*").split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

(`os` is already imported at the top of this file. Default `"*"` — no origin restriction — matches this API having no cookie/credential-based auth to protect; `CORS_ALLOWED_ORIGINS` is unset by default for zero-config local dev, and set explicitly in `deployment/compose_apps.yaml` in Task 9.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -W ignore -m unittest tests.test_api.CorsTests -v`
Expected: PASS.

Then run the full suite to confirm nothing broke: `python -W ignore -m unittest discover -s tests -t . -v`
Expected: all tests pass (198 previously + 1 new = 199).

- [ ] **Step 5: Commit**

```bash
git add app/api/main.py tests/test_api.py
git commit -m "feat: add configurable CORS middleware to the API"
```

---

### Task 3: Runtime env config + typed API client

**Files:**
- Create: `vt-tool-ui/src/shared/lib/runtimeEnv.ts`
- Create: `vt-tool-ui/src/api/client.ts`
- Create: `vt-tool-ui/src/api/endpoints.ts`
- Test: `vt-tool-ui/src/api/__tests__/endpoints.test.ts`
- Test: `vt-tool-ui/src/shared/lib/__tests__/runtimeEnv.test.ts`

**Interfaces:**
- Consumes: Task 1's scaffold (builds/tests run in this project).
- Produces: `IocType`, `AnalyzeItem`, `AnalyzeRequest`, `Report`, `AnalyzeResult`, `JobStatus`, `JobResponse` types and `analyze()`, `getJob()`, `health()` functions from `src/api/endpoints.ts` — every later task that talks to the backend imports from here, using these exact names.

- [ ] **Step 1: Write the failing tests**

`vt-tool-ui/src/shared/lib/__tests__/runtimeEnv.test.ts`:

```ts
import { afterEach, describe, expect, it } from "vitest";
import { env } from "../runtimeEnv";

describe("env", () => {
  afterEach(() => {
    delete (window as unknown as { __ENV__?: unknown }).__ENV__;
  });

  it("reads from window.__ENV__ when present", () => {
    window.__ENV__ = { VITE_API_BASE: "http://runtime:9000" };
    expect(env("VITE_API_BASE")).toBe("http://runtime:9000");
  });

  it("falls back to undefined when nothing is set and no build-time default exists", () => {
    expect(env("VITE_NONEXISTENT_KEY")).toBeUndefined();
  });

  it("ignores an empty string in window.__ENV__ and falls through", () => {
    window.__ENV__ = { VITE_API_BASE: "" };
    expect(env("VITE_API_BASE")).toBeUndefined();
  });
});
```

`vt-tool-ui/src/api/__tests__/endpoints.test.ts`:

```ts
import { describe, expect, it, vi } from "vitest";
import { client } from "../client";
import { analyze, getJob, health } from "../endpoints";

describe("analyze", () => {
  it("posts the request and returns the response data", async () => {
    const items = [{ value: "example.com", value_type: "domains" as const }];
    const spy = vi.spyOn(client, "post").mockResolvedValue({
      data: [{ status: "queued", job_id: "abc123" }],
    });

    const result = await analyze({ values: items, api_key: "fake-key" });

    expect(spy).toHaveBeenCalledWith("/analyze", { values: items, api_key: "fake-key" });
    expect(result).toEqual([{ status: "queued", job_id: "abc123" }]);
  });
});

describe("getJob", () => {
  it("gets the job by id and returns the response data", async () => {
    const spy = vi.spyOn(client, "get").mockResolvedValue({
      data: { status: "complete", report: { domain: "example.com" }, error: null },
    });

    const result = await getJob("abc123");

    expect(spy).toHaveBeenCalledWith("/jobs/abc123");
    expect(result).toEqual({ status: "complete", report: { domain: "example.com" }, error: null });
  });
});

describe("health", () => {
  it("gets /health and returns the response data", async () => {
    const spy = vi.spyOn(client, "get").mockResolvedValue({ data: { status: "ok" } });

    const result = await health();

    expect(spy).toHaveBeenCalledWith("/health");
    expect(result).toEqual({ status: "ok" });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test` (inside `node:22-alpine` as in Task 1, from `vt-tool-ui/`)
Expected: FAIL — `../runtimeEnv`, `../client`, `../endpoints` modules don't exist yet.

- [ ] **Step 3: Implement `runtimeEnv.ts`**

`vt-tool-ui/src/shared/lib/runtimeEnv.ts`:

```ts
declare global {
  interface Window {
    __ENV__?: Record<string, string>;
  }
}

export function env(key: string): string | undefined {
  const runtime = typeof window !== "undefined" ? window.__ENV__ : undefined;
  const fromRuntime = runtime?.[key];
  if (fromRuntime !== undefined && fromRuntime !== "") {
    return fromRuntime;
  }
  const fromBuild = (import.meta.env as Record<string, string | undefined>)[key];
  return fromBuild !== undefined && fromBuild !== "" ? fromBuild : undefined;
}
```

(This is harmonized verbatim from `suspicious-ui`'s `src/lib/runtimeEnv.ts` — same pattern, same precedence: runtime-injected `window.__ENV__` wins, falls back to Vite's build-time `import.meta.env` for local `pnpm dev`.)

- [ ] **Step 4: Implement `client.ts` and `endpoints.ts`**

`vt-tool-ui/src/api/client.ts`:

```ts
import axios from "axios";
import { env } from "../shared/lib/runtimeEnv";

export const client = axios.create({
  baseURL: env("VITE_API_BASE") ?? "http://localhost:8080",
});
```

`vt-tool-ui/src/api/endpoints.ts`:

```ts
import { client } from "./client";

export type IocType = "ips" | "domains" | "urls" | "hashes";

export interface AnalyzeItem {
  value: string;
  value_type: IocType;
}

export interface AnalyzeRequest {
  values: AnalyzeItem[];
  api_key: string;
  proxy?: string;
}

export interface Report {
  [key: string]: unknown;
  malicious_score?: number | string;
  total_scans?: number | string;
}

export type AnalyzeResult =
  | { status: "hit"; report: Report }
  | { status: "invalid"; error: string }
  | { status: "queued"; job_id: string };

export type JobStatusValue = "queued" | "in_progress" | "complete" | "failed";

export interface JobResponse {
  status: JobStatusValue;
  report: Report | null;
  error: string | null;
}

export async function analyze(request: AnalyzeRequest): Promise<AnalyzeResult[]> {
  const response = await client.post<AnalyzeResult[]>("/analyze", request);
  return response.data;
}

export async function getJob(jobId: string): Promise<JobResponse> {
  const response = await client.get<JobResponse>(`/jobs/${jobId}`);
  return response.data;
}

export async function health(): Promise<{ status: string }> {
  const response = await client.get<{ status: string }>("/health");
  return response.data;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (1 previous + 6 new = 7).

- [ ] **Step 6: Commit**

```bash
git add vt-tool-ui/src/shared/lib/runtimeEnv.ts vt-tool-ui/src/api/ vt-tool-ui/src/shared/lib/__tests__/
git commit -m "feat: add runtime env config and typed API client"
```

---

### Task 4: IOC classifier

**Files:**
- Create: `vt-tool-ui/src/features/analyze/lib/classifyIoc.ts`
- Test: `vt-tool-ui/src/features/analyze/lib/__tests__/classifyIoc.test.ts`

**Interfaces:**
- Consumes: nothing (pure function, no dependencies on earlier tasks beyond the project existing).
- Produces: `ClassifiedType`, `ClassifiedIoc`, `classifyIoc(value: string): ClassifiedType`, `classifyLines(text: string): ClassifiedIoc[]` — Task 5's `IocInput`/`IocReviewTable` call `classifyLines` directly.

- [ ] **Step 1: Write the failing tests**

`vt-tool-ui/src/features/analyze/lib/__tests__/classifyIoc.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { classifyIoc, classifyLines } from "../classifyIoc";

describe("classifyIoc", () => {
  it("classifies a plain IPv4 address", () => {
    expect(classifyIoc("8.8.8.8")).toBe("ips");
  });

  it("classifies an MD5 hash (32 hex chars)", () => {
    expect(classifyIoc("44d88612fea8a8f36de82e1278abb02f")).toBe("hashes");
  });

  it("classifies a SHA-1 hash (40 hex chars)", () => {
    expect(classifyIoc("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")).toBe("hashes");
  });

  it("classifies a SHA-256 hash (64 hex chars)", () => {
    expect(
      classifyIoc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ).toBe("hashes");
  });

  it("classifies a hash regardless of case", () => {
    expect(classifyIoc("44D88612FEA8A8F36DE82E1278ABB02F")).toBe("hashes");
  });

  it("classifies an http(s) URL", () => {
    expect(classifyIoc("https://example.com/a/b?c=1")).toBe("urls");
  });

  it("classifies a bare domain", () => {
    expect(classifyIoc("example.com")).toBe("domains");
  });

  it("classifies a subdomain as a domain", () => {
    expect(classifyIoc("mail.example.co.uk")).toBe("domains");
  });

  it("flags a value that matches nothing as unrecognized", () => {
    expect(classifyIoc("not an ioc at all!!")).toBe("unrecognized");
  });

  it("flags a hash-length string with non-hex characters as unrecognized", () => {
    expect(classifyIoc("gggggggggggggggggggggggggggggggg")).toBe("unrecognized");
  });
});

describe("classifyLines", () => {
  it("classifies each non-empty line", () => {
    const result = classifyLines("8.8.8.8\nexample.com\n");
    expect(result).toEqual([
      { value: "8.8.8.8", type: "ips" },
      { value: "example.com", type: "domains" },
    ]);
  });

  it("trims whitespace and skips blank lines", () => {
    const result = classifyLines("  8.8.8.8  \n\n\n  example.com\n");
    expect(result).toEqual([
      { value: "8.8.8.8", type: "ips" },
      { value: "example.com", type: "domains" },
    ]);
  });

  it("returns an empty array for empty input", () => {
    expect(classifyLines("")).toEqual([]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test`
Expected: FAIL — `../classifyIoc` doesn't exist.

- [ ] **Step 3: Implement `classifyIoc.ts`**

`vt-tool-ui/src/features/analyze/lib/classifyIoc.ts`:

```ts
export type ClassifiedType = "ips" | "domains" | "urls" | "hashes" | "unrecognized";

export interface ClassifiedIoc {
  value: string;
  type: ClassifiedType;
}

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const URL_RE = /^https?:\/\//i;
const DOMAIN_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export function classifyIoc(value: string): ClassifiedType {
  if (IPV4_RE.test(value)) {
    return "ips";
  }
  if (HASH_RE.test(value)) {
    return "hashes";
  }
  if (URL_RE.test(value)) {
    return "urls";
  }
  if (DOMAIN_RE.test(value)) {
    return "domains";
  }
  return "unrecognized";
}

export function classifyLines(text: string): ClassifiedIoc[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((value) => ({ value, type: classifyIoc(value) }));
}
```

(Order matters: IPv4 and hash-length checks run before the domain regex, since a bare numeric string could otherwise be ambiguous, and hashes are checked before the domain pattern since a 32/40/64-char hex string would not match `DOMAIN_RE` anyway but explicit ordering keeps the intent clear. This mirrors — loosely, not by shared code — the checks `DataValidator` runs server-side, but stays deliberately shallow per the Global Constraints: no denylist logic here.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (7 previous + 13 new = 20).

- [ ] **Step 5: Commit**

```bash
git add vt-tool-ui/src/features/analyze/lib/
git commit -m "feat: add client-side IOC type classifier"
```

---

### Task 5: IOC input and pre-submit review table

**Files:**
- Create: `vt-tool-ui/src/features/analyze/components/IocInput.tsx`
- Create: `vt-tool-ui/src/features/analyze/components/IocReviewTable.tsx`
- Test: `vt-tool-ui/src/features/analyze/components/__tests__/IocInput.test.tsx`
- Test: `vt-tool-ui/src/features/analyze/components/__tests__/IocReviewTable.test.tsx`

**Interfaces:**
- Consumes: `classifyLines`, `ClassifiedIoc`, `ClassifiedType` from Task 4's `../lib/classifyIoc`.
- Produces: `IocInput` (props: `onParsed: (items: ClassifiedIoc[]) => void`), `IocReviewTable` (props: `items: ClassifiedIoc[]`, `onChange: (items: ClassifiedIoc[]) => void`, `onSubmit: (items: ClassifiedIoc[]) => void`) — Task 8's `AnalyzePage` renders both and wires them together.

- [ ] **Step 1: Write the failing tests**

`vt-tool-ui/src/features/analyze/components/__tests__/IocInput.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import IocInput from "../IocInput";

describe("IocInput", () => {
  it("classifies pasted text and calls onParsed", async () => {
    const onParsed = vi.fn();
    render(<IocInput onParsed={onParsed} />);

    const textarea = screen.getByRole("textbox", { name: /paste iocs/i });
    await userEvent.type(textarea, "8.8.8.8{enter}example.com");
    await userEvent.click(screen.getByRole("button", { name: /review/i }));

    expect(onParsed).toHaveBeenCalledWith([
      { value: "8.8.8.8", type: "ips" },
      { value: "example.com", type: "domains" },
    ]);
  });

  it("does nothing when the textarea is empty", async () => {
    const onParsed = vi.fn();
    render(<IocInput onParsed={onParsed} />);

    await userEvent.click(screen.getByRole("button", { name: /review/i }));

    expect(onParsed).not.toHaveBeenCalled();
  });
});
```

`vt-tool-ui/src/features/analyze/components/__tests__/IocReviewTable.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import IocReviewTable from "../IocReviewTable";

const items = [
  { value: "8.8.8.8", type: "ips" as const },
  { value: "weird value", type: "unrecognized" as const },
];

describe("IocReviewTable", () => {
  it("renders one row per item and flags unrecognized entries", () => {
    render(<IocReviewTable items={items} onChange={vi.fn()} onSubmit={vi.fn()} />);

    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("weird value")).toBeInTheDocument();
    expect(screen.getByText(/1 line skipped/i)).toBeInTheDocument();
  });

  it("removes a row and calls onChange when its remove button is clicked", async () => {
    const onChange = vi.fn();
    render(<IocReviewTable items={items} onChange={onChange} onSubmit={vi.fn()} />);

    await userEvent.click(screen.getAllByRole("button", { name: /remove/i })[0]);

    expect(onChange).toHaveBeenCalledWith([items[1]]);
  });

  it("submits only the classified (non-unrecognized) items", async () => {
    const onSubmit = vi.fn();
    render(<IocReviewTable items={items} onChange={vi.fn()} onSubmit={onSubmit} />);

    await userEvent.click(screen.getByRole("button", { name: /^analyze$/i }));

    expect(onSubmit).toHaveBeenCalledWith([items[0]]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test`
Expected: FAIL — `../IocInput`, `../IocReviewTable` don't exist.

- [ ] **Step 3: Implement `IocInput.tsx`**

`vt-tool-ui/src/features/analyze/components/IocInput.tsx`:

```tsx
import { useCallback, useState } from "react";
import { Box, Button, Stack, TextField, Typography } from "@mui/material";
import { useDropzone } from "react-dropzone";
import { classifyLines, type ClassifiedIoc } from "../lib/classifyIoc";

interface IocInputProps {
  onParsed: (items: ClassifiedIoc[]) => void;
}

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024;

export default function IocInput({ onParsed }: IocInputProps) {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const onDrop = useCallback((accepted: File[], rejected: { file: File }[]) => {
    setError(null);
    if (rejected.length > 0) {
      setError("Only .txt files up to 5MB are accepted.");
      return;
    }
    const file = accepted[0];
    if (!file) return;
    file.text().then((content) => setText((prev) => (prev ? `${prev}\n${content}` : content)));
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "text/plain": [".txt"] },
    maxSize: MAX_FILE_SIZE_BYTES,
    multiple: false,
  });

  const handleReview = () => {
    const items = classifyLines(text);
    if (items.length > 0) {
      onParsed(items);
    }
  };

  return (
    <Stack spacing={2}>
      <TextField
        label="Paste IOCs"
        multiline
        minRows={6}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={"8.8.8.8\nexample.com\nhttps://example.com/a"}
      />
      <Box
        {...getRootProps()}
        sx={{
          border: "2px dashed",
          borderColor: isDragActive ? "primary.main" : "divider",
          borderRadius: 1,
          p: 3,
          textAlign: "center",
          cursor: "pointer",
        }}
      >
        <input {...getInputProps()} />
        <Typography>Drop a .txt file here, or click to browse</Typography>
      </Box>
      {error && <Typography color="error">{error}</Typography>}
      <Button variant="contained" onClick={handleReview}>
        Review
      </Button>
    </Stack>
  );
}
```

- [ ] **Step 4: Implement `IocReviewTable.tsx`**

`vt-tool-ui/src/features/analyze/components/IocReviewTable.tsx`:

```tsx
import {
  Button,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import DeleteIcon from "@mui/icons-material/Delete";
import type { ClassifiedIoc } from "../lib/classifyIoc";

interface IocReviewTableProps {
  items: ClassifiedIoc[];
  onChange: (items: ClassifiedIoc[]) => void;
  onSubmit: (items: ClassifiedIoc[]) => void;
}

export default function IocReviewTable({ items, onChange, onSubmit }: IocReviewTableProps) {
  const unrecognizedCount = items.filter((item) => item.type === "unrecognized").length;
  const submittable = items.filter((item) => item.type !== "unrecognized");

  const handleRemove = (index: number) => {
    onChange(items.filter((_, i) => i !== index));
  };

  return (
    <>
      {unrecognizedCount > 0 && (
        <Typography color="warning.main">
          {unrecognizedCount} line{unrecognizedCount === 1 ? "" : "s"} skipped — unrecognized format
        </Typography>
      )}
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Value</TableCell>
            <TableCell>Type</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {items.map((item, index) => (
            <TableRow key={`${item.value}-${index}`}>
              <TableCell>{item.value}</TableCell>
              <TableCell>{item.type}</TableCell>
              <TableCell>
                <IconButton aria-label="Remove" onClick={() => handleRemove(index)}>
                  <DeleteIcon />
                </IconButton>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Button variant="contained" disabled={submittable.length === 0} onClick={() => onSubmit(submittable)}>
        Analyze
      </Button>
    </>
  );
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (20 previous + 5 new = 25).

- [ ] **Step 6: Commit**

```bash
git add vt-tool-ui/src/features/analyze/components/IocInput.tsx vt-tool-ui/src/features/analyze/components/IocReviewTable.tsx vt-tool-ui/src/features/analyze/components/__tests__/
git commit -m "feat: add IOC input and pre-submit review table"
```

---

### Task 6: Analyze mutation and job-polling hooks

**Files:**
- Create: `vt-tool-ui/src/shared/lib/apiKeyStorage.ts`
- Create: `vt-tool-ui/src/features/analyze/hooks/useAnalyze.ts`
- Create: `vt-tool-ui/src/features/analyze/hooks/useJobPolling.ts`
- Test: `vt-tool-ui/src/shared/lib/__tests__/apiKeyStorage.test.ts`
- Test: `vt-tool-ui/src/features/analyze/hooks/__tests__/useAnalyze.test.tsx`
- Test: `vt-tool-ui/src/features/analyze/hooks/__tests__/useJobPolling.test.tsx`

**Interfaces:**
- Consumes: `analyze`, `getJob`, `AnalyzeItem`, `AnalyzeResult`, `JobResponse` from Task 3's `../../../api/endpoints`.
- Produces: `getApiKey()`/`setApiKey(key: string)` (Task 8's `SettingsPage` calls `setApiKey`; `useAnalyze` calls `getApiKey`), `useAnalyze()` (TanStack Query mutation, `mutate(items: AnalyzeItem[])` → `AnalyzeResult[]`), `useJobPolling(jobId: string | null)` (single-job query, `.data: JobResponse | undefined`), `useJobsPolling(jobIds: string[])` (TanStack Query's `useQueries` over a *dynamic-length* array of job ids — this is what Task 8's `AnalyzePage` actually calls, since React forbids calling a hook like `useJobPolling` inside a loop whose iteration count changes between renders; `useQueries` is TanStack's own supported answer to that exact constraint).

- [ ] **Step 1: Write the failing tests**

`vt-tool-ui/src/shared/lib/__tests__/apiKeyStorage.test.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";
import { getApiKey, setApiKey } from "../apiKeyStorage";

describe("apiKeyStorage", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("returns null when nothing is stored", () => {
    expect(getApiKey()).toBeNull();
  });

  it("stores and retrieves the key", () => {
    setApiKey("my-vt-key");
    expect(getApiKey()).toBe("my-vt-key");
  });
});
```

`vt-tool-ui/src/features/analyze/hooks/__tests__/useAnalyze.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useAnalyze } from "../useAnalyze";
import * as endpoints from "../../../../api/endpoints";
import { setApiKey } from "../../../../shared/lib/apiKeyStorage";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useAnalyze", () => {
  it("calls analyze() with the stored API key and the given items", async () => {
    setApiKey("stored-key");
    const spy = vi
      .spyOn(endpoints, "analyze")
      .mockResolvedValue([{ status: "queued", job_id: "job-1" }]);

    const { result } = renderHook(() => useAnalyze(), { wrapper });
    result.current.mutate([{ value: "8.8.8.8", value_type: "ips" }]);

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(spy).toHaveBeenCalledWith({
      values: [{ value: "8.8.8.8", value_type: "ips" }],
      api_key: "stored-key",
    });
    expect(result.current.data).toEqual([{ status: "queued", job_id: "job-1" }]);
  });
});
```

`vt-tool-ui/src/features/analyze/hooks/__tests__/useJobPolling.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useJobPolling, useJobsPolling } from "../useJobPolling";
import * as endpoints from "../../../../api/endpoints";

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useJobPolling", () => {
  it("is disabled when jobId is null", () => {
    const spy = vi.spyOn(endpoints, "getJob");
    const { result } = renderHook(() => useJobPolling(null), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(spy).not.toHaveBeenCalled();
  });

  it("fetches the job once it reaches a terminal state and stops polling", async () => {
    vi.spyOn(endpoints, "getJob").mockResolvedValue({
      status: "complete",
      report: { domain: "example.com" },
      error: null,
    });

    const { result } = renderHook(() => useJobPolling("job-1"), { wrapper });

    await waitFor(() => expect(result.current.data?.status).toBe("complete"));
  });
});

describe("useJobsPolling", () => {
  it("fetches each job id independently", async () => {
    vi.spyOn(endpoints, "getJob").mockImplementation((jobId: string) =>
      Promise.resolve({ status: "complete", report: { id: jobId }, error: null }),
    );

    const { result } = renderHook(() => useJobsPolling(["job-1", "job-2"]), { wrapper });

    await waitFor(() => expect(result.current.every((q) => q.data?.status === "complete")).toBe(true));
    expect(result.current.map((q) => q.data?.report)).toEqual([{ id: "job-1" }, { id: "job-2" }]);
  });

  it("returns an empty array for an empty list of job ids, without violating the Rules of Hooks", () => {
    // This is the reason useJobsPolling exists at all: AnalyzePage needs to poll
    // a set of jobs whose count changes between renders (0 before submit, N after).
    // Calling useJobPolling in a .map() loop would violate React's Rules of Hooks
    // (hook call count must be stable across renders) - useQueries is TanStack's
    // supported way to run a dynamic-length set of queries as a single hook call.
    const { result } = renderHook(() => useJobsPolling([]), { wrapper });
    expect(result.current).toEqual([]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test`
Expected: FAIL — `../apiKeyStorage`, `../useAnalyze`, `../useJobPolling` don't exist.

- [ ] **Step 3: Implement `apiKeyStorage.ts`**

`vt-tool-ui/src/shared/lib/apiKeyStorage.ts`:

```ts
const STORAGE_KEY = "vt-tool-ui:api-key";

export function getApiKey(): string | null {
  return localStorage.getItem(STORAGE_KEY);
}

export function setApiKey(key: string): void {
  localStorage.setItem(STORAGE_KEY, key);
}
```

- [ ] **Step 4: Implement `useAnalyze.ts` and `useJobPolling.ts`**

`vt-tool-ui/src/features/analyze/hooks/useAnalyze.ts`:

```ts
import { useMutation } from "@tanstack/react-query";
import { analyze, type AnalyzeItem } from "../../../api/endpoints";
import { getApiKey } from "../../../shared/lib/apiKeyStorage";

export function useAnalyze() {
  return useMutation({
    mutationFn: (items: AnalyzeItem[]) => analyze({ values: items, api_key: getApiKey() ?? "" }),
  });
}
```

`vt-tool-ui/src/features/analyze/hooks/useJobPolling.ts`:

```ts
import { useQueries, useQuery } from "@tanstack/react-query";
import { getJob, type JobResponse } from "../../../api/endpoints";

const TERMINAL_STATUSES: JobResponse["status"][] = ["complete", "failed"];

function shouldKeepPolling(status: JobResponse["status"] | undefined): number | false {
  return status && TERMINAL_STATUSES.includes(status) ? false : 2000;
}

export function useJobPolling(jobId: string | null) {
  return useQuery({
    queryKey: ["job", jobId],
    queryFn: () => getJob(jobId as string),
    enabled: jobId !== null,
    refetchInterval: (query) => shouldKeepPolling(query.state.data?.status),
  });
}

// AnalyzePage needs to poll a *set* of jobs whose size changes between renders
// (0 before submit, N after) - calling useJobPolling in a .map() loop would
// violate React's Rules of Hooks. useQueries is TanStack's supported way to
// run a dynamic-length set of queries as a single, stable hook call.
export function useJobsPolling(jobIds: string[]) {
  return useQueries({
    queries: jobIds.map((jobId) => ({
      queryKey: ["job", jobId],
      queryFn: () => getJob(jobId),
      refetchInterval: (query: { state: { data?: JobResponse } }) =>
        shouldKeepPolling(query.state.data?.status),
    })),
  });
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (25 previous + 7 new = 32).

- [ ] **Step 6: Commit**

```bash
git add vt-tool-ui/src/shared/lib/apiKeyStorage.ts vt-tool-ui/src/shared/lib/__tests__/apiKeyStorage.test.ts vt-tool-ui/src/features/analyze/hooks/
git commit -m "feat: add API key storage, analyze mutation, and job-polling hooks"
```

---

### Task 7: Results display — status badges, KPI cards, results table

**Files:**
- Create: `vt-tool-ui/src/features/analyze/lib/computeVerdict.ts`
- Create: `vt-tool-ui/src/features/analyze/components/StatusBadge.tsx`
- Create: `vt-tool-ui/src/features/analyze/components/KpiCards.tsx`
- Create: `vt-tool-ui/src/features/analyze/components/ResultsTable.tsx`
- Test: `vt-tool-ui/src/features/analyze/lib/__tests__/computeVerdict.test.ts`
- Test: `vt-tool-ui/src/features/analyze/components/__tests__/StatusBadge.test.tsx`
- Test: `vt-tool-ui/src/features/analyze/components/__tests__/KpiCards.test.tsx`
- Test: `vt-tool-ui/src/features/analyze/components/__tests__/ResultsTable.test.tsx`

**Interfaces:**
- Consumes: `Report` type from Task 3's `../../../api/endpoints`.
- Produces: `Verdict` type, `computeVerdict(report: Report | null | undefined): Verdict`, `StatusBadge` (props: `verdict: Verdict`), `KpiCards` (props: `reports: (Report | null)[]`), `ResultsTable` (props: `rows: { value: string; report: Report | null; error?: string }[]`) — Task 8's `AnalyzePage` renders `KpiCards` and `ResultsTable` once every job resolves.

- [ ] **Step 1: Write the failing tests**

`vt-tool-ui/src/features/analyze/lib/__tests__/computeVerdict.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { computeVerdict } from "../computeVerdict";

describe("computeVerdict", () => {
  it("is malicious when malicious_score is greater than 5", () => {
    expect(computeVerdict({ malicious_score: 6, total_scans: 90 })).toBe("malicious");
  });

  it("is suspect when malicious_score is between 1 and 5 inclusive", () => {
    expect(computeVerdict({ malicious_score: 1, total_scans: 90 })).toBe("suspect");
    expect(computeVerdict({ malicious_score: 5, total_scans: 90 })).toBe("suspect");
  });

  it("is clean when malicious_score is exactly 0", () => {
    expect(computeVerdict({ malicious_score: 0, total_scans: 90 })).toBe("clean");
  });

  it("is unknown when malicious_score is the not-found sentinel", () => {
    expect(computeVerdict({ malicious_score: "Not found", total_scans: "Not found" })).toBe("unknown");
  });

  it("is unknown when the report is null or undefined", () => {
    expect(computeVerdict(null)).toBe("unknown");
    expect(computeVerdict(undefined)).toBe("unknown");
  });
});
```

`vt-tool-ui/src/features/analyze/components/__tests__/StatusBadge.test.tsx`:

```tsx
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import StatusBadge from "../StatusBadge";

describe("StatusBadge", () => {
  it.each([
    ["malicious", "MALICIOUS"],
    ["suspect", "SUSPECT"],
    ["clean", "CLEAN"],
    ["unknown", "UNKNOWN"],
  ] as const)("renders %s as %s", (verdict, label) => {
    render(<StatusBadge verdict={verdict} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});
```

`vt-tool-ui/src/features/analyze/components/__tests__/KpiCards.test.tsx`:

```tsx
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import KpiCards from "../KpiCards";

describe("KpiCards", () => {
  it("counts each verdict correctly", () => {
    render(
      <KpiCards
        reports={[
          { malicious_score: 6, total_scans: 90 },
          { malicious_score: 6, total_scans: 90 },
          { malicious_score: 1, total_scans: 90 },
          { malicious_score: 0, total_scans: 90 },
          { malicious_score: "Not found", total_scans: "Not found" },
        ]}
      />,
    );

    // Query by each card's (unique) label, not by its number - three of the
    // five cards land on the same count ("1"), so screen.getByText("1") would
    // throw "found multiple elements". The label's actual DOM text is the
    // lowercase object key ("malicious", not "Malicious") - the component
    // only capitalizes it visually via CSS text-transform, which doesn't
    // change matchable text content - so match case-insensitively.
    expect(screen.getByText(/^total$/i).closest("div")).toHaveTextContent("5");
    expect(screen.getByText(/^malicious$/i).closest("div")).toHaveTextContent("2");
    expect(screen.getByText(/^suspect$/i).closest("div")).toHaveTextContent("1");
    expect(screen.getByText(/^clean$/i).closest("div")).toHaveTextContent("1");
    expect(screen.getByText(/^unknown$/i).closest("div")).toHaveTextContent("1");
  });
});
```

`vt-tool-ui/src/features/analyze/components/__tests__/ResultsTable.test.tsx`:

```tsx
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import ResultsTable from "../ResultsTable";

describe("ResultsTable", () => {
  it("renders one row per result with a VT GUI link", () => {
    render(
      <ResultsTable
        rows={[
          { value: "8.8.8.8", report: { malicious_score: 0, total_scans: 90 } },
          { value: "bad-key.example.com", report: null, error: "Wrong API key" },
        ]}
      />,
    );

    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText("Wrong API key")).toBeInTheDocument();
    // Both rows render a VT link, so a singular getByRole would throw "found
    // multiple elements" - use getAllByRole and index into the first row's.
    const links = screen.getAllByRole("link", { name: /view on virustotal/i });
    expect(links[0]).toHaveAttribute("href", "https://www.virustotal.com/gui/search/8.8.8.8");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test`
Expected: FAIL — none of the four new modules exist.

- [ ] **Step 3: Implement `computeVerdict.ts`**

`vt-tool-ui/src/features/analyze/lib/computeVerdict.ts`:

```ts
import type { Report } from "../../../api/endpoints";

export type Verdict = "malicious" | "suspect" | "clean" | "unknown";

export function computeVerdict(report: Report | null | undefined): Verdict {
  if (!report || typeof report.malicious_score !== "number") {
    return "unknown";
  }
  if (report.malicious_score > 5) {
    return "malicious";
  }
  if (report.malicious_score > 0) {
    return "suspect";
  }
  return "clean";
}
```

- [ ] **Step 4: Implement `StatusBadge.tsx`, `KpiCards.tsx`, `ResultsTable.tsx`**

`vt-tool-ui/src/features/analyze/components/StatusBadge.tsx`:

```tsx
import { Chip } from "@mui/material";
import type { Verdict } from "../lib/computeVerdict";

const COLOR_BY_VERDICT: Record<Verdict, "error" | "warning" | "success" | "default"> = {
  malicious: "error",
  suspect: "warning",
  clean: "success",
  unknown: "default",
};

const LABEL_BY_VERDICT: Record<Verdict, string> = {
  malicious: "MALICIOUS",
  suspect: "SUSPECT",
  clean: "CLEAN",
  unknown: "UNKNOWN",
};

export default function StatusBadge({ verdict }: { verdict: Verdict }) {
  return <Chip label={LABEL_BY_VERDICT[verdict]} color={COLOR_BY_VERDICT[verdict]} size="small" />;
}
```

`vt-tool-ui/src/features/analyze/components/KpiCards.tsx`:

```tsx
import { Card, CardContent, Stack, Typography } from "@mui/material";
import type { Report } from "../../../api/endpoints";
import { computeVerdict } from "../lib/computeVerdict";

interface KpiCardsProps {
  reports: (Report | null)[];
}

export default function KpiCards({ reports }: KpiCardsProps) {
  const verdicts = reports.map(computeVerdict);
  const counts = {
    total: reports.length,
    malicious: verdicts.filter((v) => v === "malicious").length,
    suspect: verdicts.filter((v) => v === "suspect").length,
    clean: verdicts.filter((v) => v === "clean").length,
    unknown: verdicts.filter((v) => v === "unknown").length,
  };

  return (
    <Stack direction="row" spacing={2}>
      {(Object.keys(counts) as (keyof typeof counts)[]).map((key) => (
        <Card key={key}>
          <CardContent>
            <Typography variant="h4">{counts[key]}</Typography>
            <Typography variant="body2" sx={{ textTransform: "capitalize" }}>
              {key}
            </Typography>
          </CardContent>
        </Card>
      ))}
    </Stack>
  );
}
```

`vt-tool-ui/src/features/analyze/components/ResultsTable.tsx`:

```tsx
import {
  Link,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import type { Report } from "../../../api/endpoints";
import { computeVerdict } from "../lib/computeVerdict";
import StatusBadge from "./StatusBadge";

interface ResultRow {
  value: string;
  report: Report | null;
  error?: string;
}

function vtLink(value: string): string {
  return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
}

export default function ResultsTable({ rows }: { rows: ResultRow[] }) {
  return (
    <Table>
      <TableHead>
        <TableRow>
          <TableCell>Value</TableCell>
          <TableCell>Status</TableCell>
          <TableCell>Detail</TableCell>
          <TableCell>VirusTotal</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={row.value}>
            <TableCell>{row.value}</TableCell>
            <TableCell>
              <StatusBadge verdict={computeVerdict(row.report)} />
            </TableCell>
            <TableCell>
              {row.error ? (
                <Typography color="error">{row.error}</Typography>
              ) : (
                `${row.report?.malicious_score ?? "-"}/${row.report?.total_scans ?? "-"}`
              )}
            </TableCell>
            <TableCell>
              <Link href={vtLink(row.value)} target="_blank" rel="noreferrer">
                View on VirusTotal
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pnpm test`
Expected: all pass (32 previous + 11 new = 43).

- [ ] **Step 6: Commit**

```bash
git add vt-tool-ui/src/features/analyze/lib/computeVerdict.ts vt-tool-ui/src/features/analyze/lib/__tests__/computeVerdict.test.ts vt-tool-ui/src/features/analyze/components/StatusBadge.tsx vt-tool-ui/src/features/analyze/components/KpiCards.tsx vt-tool-ui/src/features/analyze/components/ResultsTable.tsx vt-tool-ui/src/features/analyze/components/__tests__/StatusBadge.test.tsx vt-tool-ui/src/features/analyze/components/__tests__/KpiCards.test.tsx vt-tool-ui/src/features/analyze/components/__tests__/ResultsTable.test.tsx
git commit -m "feat: add status badges, KPI cards, and results table"
```

---

### Task 8: Wire up AnalyzePage, SettingsPage, and the health indicator

**Files:**
- Modify: `vt-tool-ui/src/pages/AnalyzePage.tsx`
- Modify: `vt-tool-ui/src/pages/SettingsPage.tsx`
- Create: `vt-tool-ui/src/shared/components/ApiHealthIndicator.tsx`
- Modify: `vt-tool-ui/src/app/router.tsx`
- Test: `vt-tool-ui/src/pages/__tests__/AnalyzePage.test.tsx`
- Test: `vt-tool-ui/src/pages/__tests__/SettingsPage.test.tsx`
- Test: `vt-tool-ui/src/shared/components/__tests__/ApiHealthIndicator.test.tsx`

**Interfaces:**
- Consumes: everything from Tasks 3-7 (`classifyLines`, `IocInput`, `IocReviewTable`, `useAnalyze`, `useJobPolling`, `KpiCards`, `ResultsTable`, `getApiKey`/`setApiKey`, `health`).
- Produces: the complete, usable application — no later task depends on this one beyond Task 9 packaging it.

- [ ] **Step 1: Write the failing tests**

`vt-tool-ui/src/shared/components/__tests__/ApiHealthIndicator.test.tsx`:

```tsx
import { describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import ApiHealthIndicator from "../ApiHealthIndicator";
import * as endpoints from "../../../api/endpoints";

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient();
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("ApiHealthIndicator", () => {
  it("shows online when /health succeeds", async () => {
    vi.spyOn(endpoints, "health").mockResolvedValue({ status: "ok" });
    renderWithClient(<ApiHealthIndicator />);
    await waitFor(() => expect(screen.getByText(/online/i)).toBeInTheDocument());
  });

  it("shows offline when /health fails", async () => {
    vi.spyOn(endpoints, "health").mockRejectedValue(new Error("network error"));
    renderWithClient(<ApiHealthIndicator />);
    await waitFor(() => expect(screen.getByText(/offline/i)).toBeInTheDocument());
  });
});
```

`vt-tool-ui/src/pages/__tests__/SettingsPage.test.tsx`:

```tsx
import { describe, expect, it, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import SettingsPage from "../SettingsPage";
import { getApiKey } from "../../shared/lib/apiKeyStorage";

describe("SettingsPage", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("saves the entered API key to storage", async () => {
    render(<SettingsPage />);
    await userEvent.type(screen.getByLabelText(/virustotal api key/i), "my-real-key");
    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    expect(getApiKey()).toBe("my-real-key");
  });

  it("pre-fills the field when a key is already stored", () => {
    localStorage.setItem("vt-tool-ui:api-key", "already-stored");
    render(<SettingsPage />);
    expect(screen.getByLabelText(/virustotal api key/i)).toHaveValue("already-stored");
  });
});
```

`vt-tool-ui/src/pages/__tests__/AnalyzePage.test.tsx`:

```tsx
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import AnalyzePage from "../AnalyzePage";
import * as endpoints from "../../api/endpoints";
import { setApiKey } from "../../shared/lib/apiKeyStorage";

function renderPage() {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <AnalyzePage />
    </QueryClientProvider>,
  );
}

describe("AnalyzePage", () => {
  beforeEach(() => {
    setApiKey("fake-key");
    vi.spyOn(endpoints, "health").mockResolvedValue({ status: "ok" });
  });

  it("takes a user from paste through review to a rendered hit result", async () => {
    vi.spyOn(endpoints, "analyze").mockResolvedValue([
      { status: "hit", report: { domain: "example.com", malicious_score: 0, total_scans: 90 } },
    ]);

    renderPage();

    await userEvent.type(screen.getByRole("textbox", { name: /paste iocs/i }), "example.com");
    await userEvent.click(screen.getByRole("button", { name: /review/i }));
    await userEvent.click(screen.getByRole("button", { name: /^analyze$/i }));

    await waitFor(() => expect(screen.getByText("CLEAN")).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm test`
Expected: FAIL — `ApiHealthIndicator` doesn't exist; `AnalyzePage`/`SettingsPage` are still Task 1's stubs (no form/textarea present).

- [ ] **Step 3: Implement `ApiHealthIndicator.tsx`**

`vt-tool-ui/src/shared/components/ApiHealthIndicator.tsx`:

```tsx
import { useQuery } from "@tanstack/react-query";
import { Chip } from "@mui/material";
import { health } from "../../api/endpoints";

export default function ApiHealthIndicator() {
  const { isSuccess } = useQuery({
    queryKey: ["health"],
    queryFn: health,
    retry: false,
    refetchInterval: 15000,
  });

  return (
    <Chip
      label={isSuccess ? "API: online" : "API: offline"}
      color={isSuccess ? "success" : "error"}
      size="small"
    />
  );
}
```

- [ ] **Step 4: Implement `SettingsPage.tsx`**

`vt-tool-ui/src/pages/SettingsPage.tsx`:

```tsx
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button, Stack, TextField, Typography } from "@mui/material";
import { getApiKey, setApiKey } from "../shared/lib/apiKeyStorage";

const schema = z.object({ apiKey: z.string().min(1, "API key is required") });
type FormValues = z.infer<typeof schema>;

export default function SettingsPage() {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { apiKey: getApiKey() ?? "" },
  });

  const onSubmit = (values: FormValues) => {
    setApiKey(values.apiKey);
  };

  return (
    <Stack spacing={2} sx={{ maxWidth: 400 }}>
      <Typography variant="h4">Settings</Typography>
      <form onSubmit={handleSubmit(onSubmit)}>
        <Stack spacing={2}>
          <TextField
            label="VirusTotal API key"
            type="password"
            error={!!errors.apiKey}
            helperText={errors.apiKey?.message}
            {...register("apiKey")}
          />
          <Button type="submit" variant="contained">
            Save
          </Button>
        </Stack>
      </form>
    </Stack>
  );
}
```

- [ ] **Step 5: Implement `AnalyzePage.tsx`**

`vt-tool-ui/src/pages/AnalyzePage.tsx`:

```tsx
import { useState } from "react";
import { Stack, Typography } from "@mui/material";
import IocInput from "../features/analyze/components/IocInput";
import IocReviewTable from "../features/analyze/components/IocReviewTable";
import KpiCards from "../features/analyze/components/KpiCards";
import ResultsTable from "../features/analyze/components/ResultsTable";
import { useAnalyze } from "../features/analyze/hooks/useAnalyze";
import { useJobsPolling } from "../features/analyze/hooks/useJobPolling";
import type { ClassifiedIoc } from "../features/analyze/lib/classifyIoc";
import type { AnalyzeResult, Report } from "../api/endpoints";

interface ResolvedRow {
  value: string;
  report: Report | null;
  error?: string;
}

export default function AnalyzePage() {
  const [reviewItems, setReviewItems] = useState<ClassifiedIoc[] | null>(null);
  const [submittedItems, setSubmittedItems] = useState<ClassifiedIoc[] | null>(null);
  const { mutate, data: results } = useAnalyze();

  // Job ids for whichever results came back "queued" - this array's length
  // changes between renders (0 before submit, N after), which is exactly why
  // useJobsPolling (TanStack's useQueries under the hood) is used here rather
  // than calling useJobPolling once per item in a loop - React forbids a
  // hook's call count varying across renders.
  const queuedJobIds = (results ?? [])
    .filter((result): result is Extract<AnalyzeResult, { status: "queued" }> => result.status === "queued")
    .map((result) => result.job_id);
  const jobQueries = useJobsPolling(queuedJobIds);

  const rows: ResolvedRow[] = (results ?? []).map((result, index) => {
    const item = submittedItems![index];
    if (result.status === "hit") {
      return { value: item.value, report: result.report };
    }
    if (result.status === "invalid") {
      return { value: item.value, report: null, error: result.error };
    }
    const jobIndex = queuedJobIds.indexOf(result.job_id);
    const jobData = jobQueries[jobIndex]?.data;
    return {
      value: item.value,
      report: jobData?.report ?? null,
      error: jobData?.error ?? undefined,
    };
  });

  const allResolved =
    submittedItems !== null &&
    results !== undefined &&
    rows.every((row) => row.report !== null || row.error !== undefined);

  const handleSubmit = (items: ClassifiedIoc[]) => {
    setSubmittedItems(items);
    mutate(items.map((item) => ({ value: item.value, value_type: item.type as "ips" | "domains" | "urls" | "hashes" })));
  };

  return (
    <Stack spacing={3}>
      <Typography variant="h4">Analyze</Typography>
      {!reviewItems && <IocInput onParsed={setReviewItems} />}
      {reviewItems && !submittedItems && (
        <IocReviewTable items={reviewItems} onChange={setReviewItems} onSubmit={handleSubmit} />
      )}
      {submittedItems && (
        <>
          <KpiCards reports={rows.map((row) => row.report)} />
          <ResultsTable rows={rows} />
          {!allResolved && <Typography>Waiting for results…</Typography>}
        </>
      )}
    </Stack>
  );
}
```

(`items.type as "ips" | "domains" | "urls" | "hashes"` is a safe assertion, not a workaround: `IocReviewTable.onSubmit` — Task 5 — only ever passes its already-filtered `submittable` array, which excludes `"unrecognized"` by construction, so `ClassifiedIoc["type"]` narrows to exactly `AnalyzeItem["value_type"]`'s 4 members at this call site even though TypeScript's structural typing can't prove that across the component boundary on its own.)

- [ ] **Step 6: Add the health indicator to the router/layout**

`vt-tool-ui/src/app/router.tsx`:

```tsx
import { Link as RouterLink, Route, Routes } from "react-router-dom";
import { AppBar, Box, Link, Toolbar, Typography } from "@mui/material";
import AnalyzePage from "../pages/AnalyzePage";
import SettingsPage from "../pages/SettingsPage";
import ApiHealthIndicator from "../shared/components/ApiHealthIndicator";

export function AppRouter() {
  return (
    <>
      <AppBar position="static">
        <Toolbar sx={{ gap: 2 }}>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            vt_tool
          </Typography>
          <Link component={RouterLink} to="/" color="inherit">
            Analyze
          </Link>
          <Link component={RouterLink} to="/settings" color="inherit">
            Settings
          </Link>
          <ApiHealthIndicator />
        </Toolbar>
      </AppBar>
      <Box sx={{ p: 3 }}>
        <Routes>
          <Route path="/" element={<AnalyzePage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </Box>
    </>
  );
}
```

- [ ] **Step 7: Run tests, type-check, and lint**

Run: `pnpm test`
Expected: all pass (43 previous + 5 new = 48). Then `pnpm run build` (TypeScript project build + Vite build) and `pnpm run lint` both clean.

- [ ] **Step 8: Commit**

```bash
git add vt-tool-ui/src/pages/ vt-tool-ui/src/shared/components/ vt-tool-ui/src/app/router.tsx
git commit -m "feat: wire AnalyzePage, SettingsPage, and API health indicator"
```

---

### Task 9: Docker packaging and deployment wiring

**Files:**
- Create: `vt-tool-ui/Dockerfile`
- Create: `vt-tool-ui/docker/nginx.conf`
- Create: `vt-tool-ui/docker/docker-entrypoint.sh`
- Modify: `deployment/compose_apps.yaml`
- Modify: `deployment/docker-compose.yml`
- Modify: `deployment/.env.example`

**Interfaces:**
- Consumes: the built `vt-tool-ui` app from Tasks 1-8 (`pnpm run build` output, `dist/`).
- Produces: a `vt-tool-ui` container runnable via `docker compose up`, reachable at `${VT_TOOL_UI_PORT}`, configured to reach `vt-tool-api` via `CORS_ALLOWED_ORIGINS` (backend side, Task 2) and `VITE_API_BASE` (frontend side, this task).

- [ ] **Step 1: Write the Dockerfile**

`vt-tool-ui/Dockerfile` (this exact multi-stage pattern — `node:22-alpine` build, `nginx:alpine` serve — was verified for real against these exact dependency versions before being written here):

```dockerfile
FROM node:22-alpine AS build
WORKDIR /app
RUN npm install -g pnpm@9.15.0

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm run build

FROM nginx:alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
COPY docker/docker-entrypoint.sh /docker-entrypoint.d/40-env-config.sh
RUN chmod +x /docker-entrypoint.d/40-env-config.sh
EXPOSE 80
```

`vt-tool-ui/docker/nginx.conf`:

```nginx
server {
    listen 80;
    server_name _;

    root /usr/share/nginx/html;
    index index.html;

    location ~* \.(js|css|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|ico|webp)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
        try_files $uri =404;
    }

    location / {
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        try_files $uri $uri/ /index.html;
    }

    location = /healthz {
        access_log off;
        return 200 "ok\n";
        add_header Content-Type text/plain;
    }
}
```

`vt-tool-ui/docker/docker-entrypoint.sh` (regenerates the runtime config `runtimeEnv.ts` reads, from the container's own environment, every time the container starts — this is what lets one built image work across deployments without a rebuild):

```sh
#!/bin/sh
set -eu

CONFIG="/usr/share/nginx/html/env-config.js"

esc() {
  printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

{
  printf 'window.__ENV__ = {\n'
  printf '  "VITE_API_BASE": "%s"\n' "$(esc "${VITE_API_BASE:-}")"
  printf '};\n'
} > "$CONFIG"
```

Also add a `<script src="/env-config.js"></script>` line to `vt-tool-ui/index.html`, right before the existing `<script type="module" src="/src/main.tsx">` line, so the runtime config is loaded before the app's own bundle:

```html
    <script src="/env-config.js"></script>
    <script type="module" src="/src/main.tsx"></script>
```

(For local `pnpm dev`, `/env-config.js` won't exist — the browser will 404 on it harmlessly, and `runtimeEnv.ts`'s fallback to `import.meta.env` covers local dev instead.)

- [ ] **Step 2: Add the `vt-tool-ui` service to `deployment/compose_apps.yaml`**

Add this service block (after the existing `vt-tool-worker` block, before the trailing `networks:`/`volumes:` sections):

```yaml
  vt-tool-ui:
    init: true
    restart: always
    ports:
      - "127.0.0.1:${VT_TOOL_UI_PORT:-5173}:80"
    environment:
      VITE_API_BASE: "http://127.0.0.1:${VT_TOOL_API_PORT:-8080}"
    networks:
      - vt_tool_network
```

(`VITE_API_BASE` points at the API's *published host port* — `127.0.0.1:${VT_TOOL_API_PORT}` — not the internal Docker service name, since this URL is used by the *browser*, which runs outside the Docker network entirely and can only reach the API via its published port on the host, exactly like `vt-tool-api`'s own healthcheck reasoning about `localhost:8080` inside its own container is a *different* network context. Verify this reasoning holds during Step 5's real end-to-end check — do not skip that check because this looks obviously correct on paper.)

- [ ] **Step 3: Add the `vt-tool-ui` service to `deployment/docker-compose.yml`**

Add this service block (alongside `vt-tool-api`/`vt-tool-worker`/`redis`, using the same `extends`/`image`/`build` pattern):

```yaml
  vt-tool-ui:
    extends:
      file: compose_apps.yaml
      service: vt-tool-ui
    image: ${REGISTRY_MIRROR_URL:-}ghcr.io/thalesgroup-cert/vt-tool-ui:${VT_TOOL_UI_VERSION:-latest}
    build:
      context: ../vt-tool-ui
      dockerfile: Dockerfile
    pull_policy: build
    container_name: vt-tool-ui
    depends_on:
      vt-tool-api:
        condition: service_healthy
```

(`pull_policy: build` matches `vt-tool-api`/`vt-tool-worker`'s own entries — this image isn't published anywhere either, so `docker compose pull` must skip it and build locally, the exact fix Task 2's counterpart applied during B5's final review for the other two services.)

Also update `app.state.analysis`'s CORS origin default for this stack: add to `deployment/compose_apps.yaml`'s `vt-tool-api` service's `environment:` block (alongside the existing `REDIS_URL`/`VT_CACHE_DB_URL`/`VT_CACHE_TTL_HOURS` lines):

```yaml
      CORS_ALLOWED_ORIGINS: "http://localhost:${VT_TOOL_UI_PORT:-5173}"
```

- [ ] **Step 4: Add `.env.example` entries**

In `deployment/.env.example`, add under the `# --- Application ports ---` section:

```
VT_TOOL_UI_PORT=5173
```

And add `VT_TOOL_UI_VERSION=latest` under `# --- Application versions ---`.

- [ ] **Step 5: Build and run the real stack, verify the frontend reaches the real backend**

```bash
cd deployment
cp .env.example .env
docker network inspect vt_tool_net >/dev/null 2>&1 || \
  docker network create --subnet=172.30.0.0/16 --gateway=172.30.0.1 --ip-range=172.30.0.0/24 vt_tool_net
docker compose --env-file .env up -d --build
```

Wait for all four containers (`redis`, `vt-tool-api`, `vt-tool-worker`, `vt-tool-ui`) to report healthy or running (the UI container has no explicit healthcheck yet — that's fine, confirm it's `Up` via `docker compose ps`), then:

```bash
curl -sf http://127.0.0.1:5173/healthz
curl -s http://127.0.0.1:5173/env-config.js
```

Expected: `healthz` returns `ok`, and `env-config.js` shows `VITE_API_BASE` pointing at `http://127.0.0.1:8080` (or whatever `VT_TOOL_API_PORT` resolved to). Then confirm the SPA itself is served and can actually reach the API — from a shell with `curl`, simulate what the browser's JS would do:

```bash
curl -s http://127.0.0.1:8080/health
```

Expected: `{"status":"ok"}` — proving the API is reachable at the exact URL the frontend's `env-config.js` points to. (A full browser-based check is out of this task's reach without a browser automation tool; Task 10's Playwright e2e suite is what actually drives the UI in a real browser, against a mocked API — this step's job is only to prove the Docker wiring and runtime config are correct, which it does.)

Tear down:

```bash
docker compose --env-file .env down --remove-orphans
rm -f .env
```

- [ ] **Step 6: Commit**

```bash
git add vt-tool-ui/Dockerfile vt-tool-ui/docker/ vt-tool-ui/index.html deployment/compose_apps.yaml deployment/docker-compose.yml deployment/.env.example
git commit -m "feat: package vt-tool-ui for Docker, wire into the deployment stack"
```

---

### Task 10: Playwright e2e test and full verification pass

**Files:**
- Create: `vt-tool-ui/playwright.config.ts`
- Create: `vt-tool-ui/e2e/analyze.spec.ts`

**Interfaces:**
- Consumes: the complete app from Tasks 1-9.
- Produces: nothing consumed by a later task — this is the plan's final task.

- [ ] **Step 1: Write `playwright.config.ts`**

`vt-tool-ui/playwright.config.ts`:

```ts
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  webServer: {
    command: "pnpm run preview -- --port 4173",
    port: 4173,
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: "http://localhost:4173",
  },
});
```

- [ ] **Step 2: Write the e2e test**

`vt-tool-ui/e2e/analyze.spec.ts` (mocks the API via Playwright's route interception — deliberately does not require a real backend, per the design spec's testing decision):

```ts
import { test, expect } from "@playwright/test";

test("submit -> review -> results, against a mocked API", async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("vt-tool-ui:api-key", "fake-key");
  });

  await page.route("**/health", (route) =>
    route.fulfill({ json: { status: "ok" } }),
  );
  await page.route("**/analyze", (route) =>
    route.fulfill({
      json: [
        {
          status: "hit",
          report: { domain: "example.com", malicious_score: 0, total_scans: 90 },
        },
      ],
    }),
  );

  await page.goto("/");
  await page.getByRole("textbox", { name: /paste iocs/i }).fill("example.com");
  await page.getByRole("button", { name: /review/i }).click();
  await page.getByRole("button", { name: /^analyze$/i }).click();

  await expect(page.getByText("CLEAN")).toBeVisible();
  await expect(page.getByRole("link", { name: /view on virustotal/i })).toHaveAttribute(
    "href",
    "https://www.virustotal.com/gui/search/example.com",
  );
});
```

- [ ] **Step 3: Install Playwright's browser binaries and run the e2e suite**

```bash
docker run --rm -v "$(pwd)":/app -w /app node:22-alpine sh -c "
  npm install -g pnpm@9.15.0 &&
  pnpm install &&
  npx playwright install --with-deps chromium &&
  pnpm run build &&
  pnpm run test:e2e
"
```

Expected: the e2e test passes (Playwright starts the preview server itself per `playwright.config.ts`'s `webServer` block, runs the browser test against it, and tears the server down).

- [ ] **Step 4: Full verification pass — everything, one more time, from a clean state**

```bash
cd vt-tool-ui
docker run --rm -v "$(pwd)":/app -w /app node:22-alpine sh -c "
  npm install -g pnpm@9.15.0 &&
  pnpm install &&
  pnpm run lint &&
  pnpm test &&
  pnpm run build
"
cd ../deployment
python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml')); yaml.safe_load(open('compose_apps.yaml')); print('valid YAML')"
cd ..
source .venv/bin/activate
ruff check .
python -W ignore -m unittest discover -s tests -t . -v
```

Expected: frontend lint clean, 48/48 vitest tests passing, frontend build clean; both compose YAML files parse; backend ruff clean, 199/199 unittest tests passing (198 + Task 2's new CORS test).

- [ ] **Step 5: Commit**

```bash
git add vt-tool-ui/playwright.config.ts vt-tool-ui/e2e/
git commit -m "test: add Playwright e2e coverage for the analyze flow"
```

- [ ] **Step 6: Report to the user**

No commit for this step. Summarize: final test counts (frontend 48 vitest + 1 e2e; backend 199 unittest), confirmation the real Docker stack (now 4 services) was verified end to end, and that MISP push + history remain explicitly out of scope for a future sub-project (see the design spec's "Out of Scope" section).

---

## Self-Review

**Spec coverage:** paste/upload input, both client-parsed (Task 5) ✅. Client-side classification deliberately shallow, no denylist duplication (Task 4, Global Constraints) ✅. API key in localStorage via Settings (Task 6 storage + Task 8 page) ✅. Docker deployment in scope (Task 9) ✅. React 19 + TS + Vite + MUI + TanStack Query, exact versions verified together for real before this plan was written ✅. CORS via middleware, not a reverse proxy (Task 2) ✅. Runtime env config harmonized from `suspicious-ui` (Task 3, Task 9) ✅. KPI cards, status badges, thresholds matching the hackathon PRs (Task 7) ✅. Direct VT GUI links (Task 7) ✅. Review-before-submit step (Task 5) ✅. `ApiHealthIndicator` using `/health` (Task 8) ✅. Playwright e2e against a mocked API, not re-proving the backend (Task 10) ✅.

**Placeholder scan:** no TBD/TODO; every step has complete, real code. The one place the plan explicitly flags its own draft as "deliberately rough" (Task 8, Step 7's `value_type` cast) is followed immediately by the exact replacement code, not a hand-wave — this is a known TypeScript narrowing limitation (a filtered array doesn't propagate a narrowed type back through the type system) being resolved with an explicit assertion, not an unresolved question.

**Type/signature consistency:** `ClassifiedIoc`/`ClassifiedType` (Task 4) match Task 5's `IocInput`/`IocReviewTable` props exactly. `AnalyzeItem`/`AnalyzeResult`/`JobResponse`/`Report` (Task 3) are used identically by Task 6's hooks, Task 7's `computeVerdict`/`ResultsTable`, and Task 8's `AnalyzePage`. `getApiKey`/`setApiKey` (Task 6) match Task 8's `SettingsPage` usage and `useAnalyze`'s internal call. `useJobsPolling(jobIds: string[])`'s return shape (an array of query results, each with `.data: JobResponse | undefined`, in the same order as the input array) matches how Task 8's `AnalyzePage` indexes `jobQueries[jobIndex]?.data`.

**A real bug was caught and fixed during this plan's own self-review, not left for the implementer to discover**: the first draft of Task 8's `AnalyzePage` called `useJobPolling` once per queued item inside a `.map()` callback — a React Rules-of-Hooks violation, since the number of queued items (and therefore hook calls) changes between the pre-submit and post-submit render. Fixed by adding `useJobsPolling` (Task 6, using TanStack Query's `useQueries`) as the one stable hook call that itself takes a dynamic-length array. Two other bugs were caught the same way in Task 7's tests: `KpiCards`' test used `screen.getByText("1")` where three different cards all show "1", which throws on multiple matches — fixed by querying each card's unique label instead; `ResultsTable`'s test used a singular `getByRole("link", ...)` where both rendered rows have a VT link — fixed with `getAllByRole` indexed to the first row. All cumulative test-count arithmetic through Tasks 3-10 was recomputed from the actual `it(...)` blocks after these fixes (final count: 48 vitest tests, not the 51 an earlier arithmetic pass claimed).

**Every risky, novel piece of this plan was verified against reality before being written down, not just reasoned about.** The exact dependency version set (React 19.2.6, Vite 8.0.16, MUI 9.0.1, TanStack Query 5.100.11, TypeScript 6.0.3, and everything else in Task 1's `package.json`) was installed and built together inside a real `node:22-alpine` container — this combination is proven to work, not assumed compatible from each package's own changelog. The Docker packaging pattern (multi-stage build → nginx → runtime `env-config.js` injection) was built and run for real: a container was started with `VITE_API_BASE` set, and `curl` confirmed `env-config.js` correctly reflected it. Vitest's jsdom + Testing Library setup was smoke-tested for real. The one thing NOT independently verified end-to-end during planning (browser-driven UI interaction against the real running app) is exactly what Task 10's Playwright suite exists to cover — deferred to implementation time rather than planning time because it needs the actual component code Tasks 1-8 produce, not a throwaway scratch app.

**Scope discipline:** MISP push and history are named explicitly as out of scope in the Global Constraints and never referenced by any task's implementation — only by the final report's summary (Task 10, Step 6), which is prose, not code. No task touches `/analyze`'s or `/jobs/{id}`'s request/response shape. No task adds authentication. `boneyard-js`, `zustand`, `notistack`, `framer-motion`, `react-grid-layout`, `react-joyride`, `recharts`, `@dicebear/*` — all present in `suspicious-ui`'s own `package.json` but absent from Task 1's — are deliberately not carried over, since none of them serve anything in this plan's actual scope; harmonization means matching the pattern and the core stack, not importing every dependency a much larger, more mature sibling app happens to have accumulated.
