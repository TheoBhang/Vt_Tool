# Governance/CI Harmonization with `suspicious` — Design

**Date:** 2026-08-06
**Status:** Approved by user, ready for implementation plan.

## Goal

vt_tool and [`thalesgroup-cert/suspicious`](https://github.com/thalesgroup-cert/suspicious) are built and maintained by the same person/org, but vt_tool currently has no `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, linting, or CI. This project brings vt_tool's governance and contribution process in line with `suspicious`'s conventions — same *process and tooling philosophy*, not a wholesale content copy, since `suspicious` is a ~10-service platform (Django/React/Celery/Elasticsearch/Cortex/ChromaDB) and vt_tool is a single-process Python CLI. Every piece below is adapted to what vt_tool actually is.

This is sub-project **A** of a larger two-part ask (the user's other thread — turning vt_tool into a long-running containerized API service, project **B** — is explicitly deferred to its own separate brainstorming pass).

## Decisions made during brainstorming (binding, not open for re-litigation during implementation)

- **License: MIT → Apache 2.0.** Explicit user decision after being told this is a real legal change, not a cosmetic one. `LICENSE.md` → `LICENSE` (matches `suspicious`'s filename).
- **Scope: "Docs + CI"** — governance docs AND real enforcement (ruff in CI, test suite in CI, commit-msg hook), not docs-only paperwork.
- **SECURITY.md: in scope**, written fresh for vt_tool's actual threat model — not copied from `suspicious` (whose version is ~90 lines about Cortex webhooks, Vault, and sandboxed malware detonation, none of which exists in vt_tool).
- **CI scope is intentionally narrower than `suspicious`'s six workflows.** Only a lint+test workflow. No CodeQL, dependency/secret scanning, docs-site build, release/image-publishing, or e2e-deploy workflows — `suspicious` has those because it publishes GHCR images and hosts a docs site; vt_tool does neither today. Revisit if/when project B (containerized service) makes image publishing real.

## Component 1: Governance docs

### `LICENSE` (replaces `LICENSE.md`)

The standard, unmodified Apache License 2.0 text (from apache.org) — unlike MIT, the Apache 2.0 license body itself has no `[year] [fullname]` copyright line to fill in; attribution is conventionally handled via a per-file header or a separate `NOTICE` file, not inside `LICENSE`. Adding a `NOTICE` file is not in scope here (`suspicious` doesn't carry one either) — just the plain `LICENSE` text, byte-for-byte standard, since it's a legal document and not something to improvise wording on. `README.md`'s license badge and Installation section get updated to reference the new file/license type.

### `CODE_OF_CONDUCT.md`

Adopt `suspicious`'s Contributor Covenant 2.1 text directly (it's the unmodified standard). Adjust only the **Enforcement** section's reporting path to point at vt_tool's own `.github/SECURITY.md` for sensitive reports (see Component 1's SECURITY.md below) and/or a GitHub issue for non-sensitive ones — same structure as `suspicious`'s, different link target within *this* repo.

### `CONTRIBUTING.md`

Same **shape** as `suspicious`'s (fork → feature branch → wire the commit-msg hook → PR), rewritten dev-setup section for what's actually true here:

```bash
git clone <your-fork>
cd vt_tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
git config core.hooksPath .githooks   # Conventional Commits validator
python -m unittest discover -s tests -t . -v
```

Document the Conventional Commits format (types: `feat, fix, chore, docs, refactor, perf, test, ci, build, style, revert` — matching what this session's commits have already been using) and the expectation that `python -m unittest discover -s tests -t .` and `ruff check` both pass before opening a PR. No mention of Docker Compose dev workflows — vt_tool's `deployment/` stack is for running the *deployed* tool (VT tool + MISP + guard), not a dev inner-loop, and that distinction should be called out explicitly so contributors aren't confused about which one they need.

### `.github/SECURITY.md`

Written fresh, same section structure as `suspicious`'s (Reporting a Vulnerability / Responsible Disclosure / Supported Versions / Threat Model / In scope / Out of scope) but with vt_tool-real content:

- **Reporting:** same Thales PSIRT contact (`psirt@thalesgroup.com`) and PGP key `suspicious` uses — reasonable to reuse since it's an org-wide security contact, not project-specific. Implementer should verify this contact is actually intended to be shared across both repos before publishing (flag to user if uncertain at implementation time — this is a case where copying an org-wide security contact is very different from copying a whole threat model).
- **Threat model, in scope:** API-key handling (env var / `--api_key` / `--api_key_file`), the local SQLite cache (`vttools.sqlite`), outbound calls to the VirusTotal and MISP APIs, template/CSV file parsing (arbitrary user-supplied files), proxy configuration.
- **Threat model, out of scope:** the `deployment/` Docker stack's TLS/network setup (operator-trusted, same "operator host is trusted" assumption `suspicious` makes), VirusTotal/MISP's own security (third-party, out of vt_tool's control), and — until project B exists — anything about a long-running service, since vt_tool is a one-shot CLI today.
- **Supported versions:** latest release + `main`, matching `suspicious`'s policy.

## Component 2: Enforcement tooling

### `ruff.toml`

```toml
target-version = "py311"
line-length = 120

[lint]
select = ["E4", "E7", "E9", "F"]
```

Same rationale comment `suspicious`'s carries: explicit `select` rather than ruff's implicit default, because an unset/implicit select rides whatever rule set a given ruff release defaults to and can silently fail CI on hundreds of pre-existing, PR-unrelated findings on a version bump. `target-version = "py311"` matches the README's stated `Python 3.11+` support (vs. `suspicious`'s `py312`, since vt_tool's stated floor is lower).

**Pre-existing findings to fix in the same PR that adds `ruff.toml`** (12 total, confirmed by trial run during brainstorming — 10 auto-fixable via `ruff check --fix`), so the CI gate is blocking from the day it's added, not immediately red:

| File | Line | Rule | Fix |
|---|---|---|---|
| `app/DataHandler/validator.py` | 1 | F401 | Remove unused `import os` |
| `app/DataHandler/validator.py` | 15, 23 | F841 | `except Exception as e:` → `except Exception:` (both `get_service_name`/`get_port_from_service_name`) |
| `app/DBHandler/db_handler.py` | 180, 426 | F841 | Unused `except ... as e:` bindings — drop `as e` |
| `app/FileHandler/output_to_file.py` | 6 | F401 | Remove unused `Markdown` import |
| `app/FileHandler/output_to_file.py` | 83 | F841 | Unused `except ... as e:` binding |
| `app/FileHandler/read_file.py` | 4 | F401 | Remove unused `import csv` |
| `app/FileHandler/read_file.py` | 7 | F401 | Remove unused `Callable` from the `typing` import |
| `app/FileHandler/read_file.py` | 314 | F841 | Unused `csv_values = defaultdict(list)` inside the (separately known-broken, out of this project's scope) `read_from_csv_file` stub — just remove the dead assignment, do not touch the `exit(...)` bug itself |
| `app/MISP/vt_tools2misp.py` | 224 | E713 | `not (x in [...])` → `x not in [...]` |
| `app/VirusTotal/vt_reporter.py` | 169 | E722 | Bare `except:` → `except Exception:` |

All ten are behavior-preserving mechanical fixes (unused-binding/import removal, one De Morgan-style rewrite, one bare-except tightening) — same "cheap safe win" category as the earlier audit cleanup, verified against the 122-test suite, no new tests needed since nothing currently exercises the removed dead bindings.

### `.githooks/commit-msg`

Near-verbatim copy of `suspicious`'s validator (already reproduced in full during brainstorming research) — same allowed-type list, same `<type>(scope)?!?: <subject>` pattern, same 72-char cap, same Merge/Revert/fixup/squash bypass. Wire it via the `git config core.hooksPath .githooks` line in `CONTRIBUTING.md`; no `make install-hooks` target needed since vt_tool has no `Makefile` at the repo root (unlike `suspicious`) — document the manual `git config` command instead.

## Component 3: CI

One new file, `.github/workflows/ci.yml`:

- Triggers: `pull_request` and `push` to `master`.
- Matrix: Python 3.11 and 3.12.
- Steps: checkout → set up Python → `pip install -r requirements.txt` → `pip install ruff` → `ruff check .` → `python -m unittest discover -s tests -t . -v`.
- Single job (no separate lint/test jobs to start — the whole thing runs in well under a minute per the local timings seen during this session, splitting it doesn't buy anything yet).

No CodeQL, no dependency/secret scanning, no Dependabot config, no issue/PR templates, no `CODEOWNERS` in this pass — these are reasonable follow-ups but weren't in the agreed "Docs + CI" scope and don't have the same forcing-function urgency (nothing currently depends on them the way `CODE_OF_CONDUCT.md`'s enforcement section depends on `SECURITY.md` existing).

## Testing

Nothing here changes `app/`/`vt_tools.py`/`init.py` behavior except the 10 ruff-driven cleanups, all mechanical and covered by re-running the existing 122-test suite (no new test cases needed for those). The CI workflow's own correctness is verified by it actually running (green) once pushed — not something unit-tested in the traditional sense.

## Out of scope (explicitly deferred)

- Project B: long-running containerized API service — separate brainstorming pass.
- CodeQL, Dependabot, secret scanning, issue/PR templates, `CODEOWNERS`, release/image-publishing automation, docs-site build.
- Any further ruff rule categories beyond `E4/E7/E9/F` (e.g. import sorting, complexity checks) — `suspicious`'s own history shows expanding this scope casually breaks CI on unrelated findings; a deliberate future decision, not a default.
