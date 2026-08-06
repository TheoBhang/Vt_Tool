# Governance/CI Harmonization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring vt_tool's governance/contribution docs and CI in line with `thalesgroup-cert/suspicious`'s conventions (same process/tooling philosophy, content adapted to what vt_tool actually is), per the approved design at `docs/superpowers/specs/2026-08-06-governance-ci-harmonization-design.md`.

**Architecture:** Nine mostly-independent file-creation/edit tasks — four governance docs, one dependency-free tooling config, one 12-finding mechanical code cleanup, one git hook, one CI workflow, plus a final full-repo verification pass. Ordered so nothing references a file that doesn't exist yet in git history (`SECURITY.md` before `CODE_OF_CONDUCT.md`, which links to it).

**Tech Stack:** No new Python dependencies. `ruff` (dev-only, not added to `requirements.txt` — it's a lint tool, not a runtime dependency; CI installs it directly). GitHub Actions for CI.

## Global Constraints

- Do not modify `app/`, `vt_tools.py`, or `init.py` behavior except the 12 mechanical, behavior-preserving ruff-driven fixes named explicitly in Task 6 — no other refactoring bundled in.
- Every governance doc's content is specified verbatim in this plan — transcribe it exactly, do not paraphrase or "improve" wording, especially `LICENSE` (a legal document).
- Keep the 122-test suite green throughout; re-run after every task that touches `app/`.
- Activate the venv for every command: `source .venv/bin/activate`.
- All new files use LF line endings and end with a single trailing newline, matching the rest of the repo.

---

### Task 1: `.github/SECURITY.md`

**Files:**
- Create: `.github/SECURITY.md`

**Interfaces:**
- Produces: the file `CODE_OF_CONDUCT.md` (Task 2) links to from its Enforcement section (`.github/SECURITY.md`, relative to repo root).

- [ ] **Step 1: Create the directory and file**

Write `.github/SECURITY.md` with exactly this content:

```markdown
# Security Policy

vt_tool is a VirusTotal analysis CLI, maintained by **Thales Group CERT**, that
queries the VirusTotal and MISP APIs on behalf of an analyst, caches results
locally, and can push results into MISP. It handles API keys and analyst-
supplied indicators (IPs, hashes, URLs, domains), so its security posture
matters even though it has a much smaller footprint than a full platform.

## Reporting a Vulnerability

Please report potential security issues to the **Thales Product Security
Incident Response Team (PSIRT)**:

* **Email:** `psirt(at)thalesgroup[.]com`
* **PGP (recommended for sensitive details):** [Thales PSIRT PGP Key](https://pgp.circl.lu/pks/lookup?op=get&search=0xfc3c4520576ec756ae730030536949c48448ae39)
  * **ID:** `0x8448AE39`
  * **Fingerprint:** `FC3C 4520 576E C756 AE73 0030 5369 49C4 8448 AE39`

Encrypt any report that contains sensitive information (proof-of-concept,
affected data, exploit details) with the PGP key above.

Please do **not** open a public GitHub issue for security reports, and do not
include exploit details in pull requests.

## Responsible Disclosure

Thales follows a Responsible Disclosure model. Reported issues are qualified
and impact-assessed; once a report is confirmed, the reporter is informed of
the investigation and an **embargo period is agreed** so risks can be
mitigated before any public disclosure.

By submitting a report, each reporter commits to the following:

* Do not take advantage of the security issue - for example, do not
  exfiltrate more data than necessary to demonstrate the vulnerability, and
  do not delete or modify data.
* Do not disclose the issue until it has been resolved and without Thales's
  consent.
* Do not perform attacks such as social engineering, denial of service, or
  attacks against third-party infrastructure (VirusTotal, MISP instances)
  the tool happens to talk to.

## Supported Versions

Security fixes are provided for the **latest released version** and the
current `master` branch. Older versions are addressed on a best-effort basis
only. Always reproduce against the latest `master` before reporting.

## Threat Model

Our threat model makes the following assumptions. A reported issue that
requires breaking one of these assumptions will be treated as a regular bug
or a non-issue rather than a security vulnerability.

* **The operator's machine and filesystem are trusted.** vt_tool runs as a
  local CLI under the analyst's own account. Anyone with local code
  execution as that user already has access to whatever vt_tool can access
  (API keys, the local SQLite cache, environment variables). Local privilege
  escalation is out of scope for this project.
* **API keys are the operator's responsibility to protect.** vt_tool accepts
  a VirusTotal API key via `--api_key`, `--api_key_file`, or the `VTAPIKEY`
  environment variable, and a MISP key/URL via environment variables or an
  interactive prompt. Keeping those values out of shell history, world-
  readable files, or version control is the operator's responsibility;
  vt_tool does not log API keys, but cannot prevent misuse of a key an
  operator chooses to expose.
* **VirusTotal and MISP are trusted within their own boundary.** vt_tool
  trusts the responses it gets back from the configured VirusTotal API and
  MISP instance. A vulnerability in VirusTotal or MISP themselves should be
  reported to their respective maintainers, not here.
* **The `deployment/` Docker stack's operator is trusted.** The Docker host,
  container runtime, and network are administered by a trusted operator.
  TLS/certificate configuration in that stack is the operator's
  responsibility to set up correctly.

### In scope

Subject to the assumptions above, we consider the following security-relevant:

* Injection through analyst-supplied input (IOC values, template/CSV file
  contents, MISP event data) into a shell command, SQL query, or file path.
* API keys or MISP credentials being logged, printed, or written to output
  files (CSV/TXT reports) in plaintext where they shouldn't be.
* Path traversal or arbitrary file write/read via `--input_file`,
  `--template_file`, `--output_dir`, or `--api_key_file`.
* Server-side request forgery reachable through IOC values submitted for
  analysis, beyond what's already an accepted property of querying
  VirusTotal/MISP about attacker-controlled observables.
* Local SQLite cache (`vttools.sqlite`) contents being corrupted or
  manipulated in a way that causes vt_tool to misreport results to an
  analyst (separate from ordinary data-quality bugs - this is about an
  adversarial actor tampering with the cache file itself).

### Out of scope

* Anything requiring a broken assumption from the list above (compromised
  operator machine, intercepted TLS, a key the operator chose to expose).
* Denial of service against vt_tool itself or against VirusTotal/MISP.
* Findings from automated scanners without a demonstrated, realistic impact.
* Vulnerabilities in VirusTotal, MISP, or other third-party dependencies
  that are not exploitable through vt_tool as configured by default.
```

- [ ] **Step 2: Commit**

```bash
git add .github/SECURITY.md
git commit -m "docs: add SECURITY.md"
```

---

### Task 2: `CODE_OF_CONDUCT.md`

**Files:**
- Create: `CODE_OF_CONDUCT.md`

**Interfaces:**
- Consumes: `.github/SECURITY.md` (Task 1) — this file links to it.

- [ ] **Step 1: Create the file**

Write `CODE_OF_CONDUCT.md` with exactly this content:

```markdown
# Contributor Covenant Code of Conduct

## Our Pledge

We as members, contributors, and leaders pledge to make participation in our
community a harassment-free experience for everyone, regardless of age, body
size, visible or invisible disability, ethnicity, sex characteristics, gender
identity and expression, level of experience, education, socio-economic
status, nationality, personal appearance, race, religion, or sexual identity
and orientation.

## Our Standards

Examples of behavior that contributes to a positive environment:

* Demonstrating empathy and kindness toward other people
* Being respectful of differing opinions, viewpoints, and experiences
* Giving and gracefully accepting constructive feedback
* Accepting responsibility and apologizing to those affected by our mistakes

Examples of unacceptable behavior:

* The use of sexualized language or imagery, and sexual attention or advances
* Trolling, insulting or derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information without explicit permission

## Enforcement Responsibilities

Project maintainers are responsible for clarifying and enforcing our
standards and will take appropriate and fair corrective action in response to
any behavior deemed inappropriate, threatening, offensive, or harmful.

## Scope

This Code of Conduct applies within all community spaces (issues, pull
requests, discussions) and when an individual is officially representing the
project in public spaces.

## Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported to the project maintainers via a GitHub issue, or, for sensitive
reports, to the Thales PSIRT contact listed in [SECURITY.md](.github/SECURITY.md).
All complaints will be reviewed and investigated promptly and fairly.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org),
version 2.1.
```

- [ ] **Step 2: Commit**

```bash
git add CODE_OF_CONDUCT.md
git commit -m "docs: add CODE_OF_CONDUCT.md"
```

---

### Task 3: License swap (MIT → Apache 2.0)

**Files:**
- Delete: `LICENSE.md`
- Create: `LICENSE`

**Interfaces:**
- Produces: `LICENSE`, which `README.md:7`'s `[![License](...)](LICENSE)` badge already links to by that exact filename — confirmed no other README changes are needed (the badge is a dynamic shields.io `github/license` badge that reads GitHub's detected license, and the "## License" section at `README.md:321-323` just says "See `LICENSE` file." — both are already license-agnostic).

- [ ] **Step 1: Remove the old license file and create the new one**

```bash
git rm LICENSE.md
```

Write `LICENSE` with exactly this content (the standard, unmodified Apache License 2.0 text — do not add a filled-in copyright line; the license body itself has none, only the APPENDIX at the end carries the `[yyyy] [name of copyright owner]` placeholder template, which is for per-file headers/a NOTICE file, not this file):

```

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

- [ ] **Step 2: Verify the README badge and License section need no changes**

```bash
grep -n -i "license" README.md
```

Expected: line 7 shows `[![License](https://img.shields.io/github/license/thalesgroup-cert/vt_tool)](LICENSE)` (already points to the bare `LICENSE` filename) and line ~321 shows `## License` / `See \`LICENSE\` file.` — both already correct, no edit needed. If either line still says `LICENSE.md` or mentions "MIT" explicitly, fix it to say `LICENSE` / remove the MIT mention.

- [ ] **Step 3: Commit**

```bash
git add LICENSE
git commit -m "chore: switch license from MIT to Apache 2.0"
```

---

### Task 4: `CONTRIBUTING.md`

**Files:**
- Create: `CONTRIBUTING.md`

**Interfaces:**
- Consumes: `.githooks/commit-msg` (Task 5, referenced by path but not required to exist yet for this task's commit to be valid — document the command, the hook file itself lands in the next task).

- [ ] **Step 1: Create the file**

Write `CONTRIBUTING.md` with exactly this content:

```markdown
# Contributing to vt_tool

We welcome contributions to improve **vt_tool**, whether through new features, bug fixes, documentation, or optimizations. This guide explains how to set up your development environment and submit changes via Pull Requests (PRs).

---

## Development Setup

Before contributing, ensure you have:

* [Git](https://git-scm.com/) installed
* Python 3.11+
* A GitHub account
* A fork of the [official vt_tool repository](https://github.com/thalesgroup-cert/vt_tool)

Clone your fork locally:

```bash
git clone <your_forked_repository.git>
cd vt_tool
```

Set up a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Switch to a feature branch:

```bash
git checkout -b feature/<short_feature_name>
```

Wire the repo's git hooks (Conventional Commits validator):

```bash
git config core.hooksPath .githooks
```

The `commit-msg` hook rejects any subject that does not match
`<type>(scope)?!?: <subject>` (max 72 chars). Allowed types: `feat`,
`fix`, `chore`, `docs`, `refactor`, `perf`, `test`, `ci`, `build`,
`style`, `revert`. Merge / revert / fixup / squash auto-subjects are
allowed through.

> **Note:** the `deployment/` directory is for *running* the deployed tool
> (vt_tool + MISP + guard, via Docker Compose) - it's not a development
> environment. For day-to-day development, use the `venv` setup above.

---

## Contribution Workflow

1. **Make changes** to the code or documentation.

2. **Stage files**:

   ```bash
   git add <files>
   ```

3. **Commit with a clear message**:

   ```bash
   git commit -m "feat: short title" -m "Optional longer description"
   ```

   Use Conventional Commits style:

   * `feat:` for a new feature
   * `fix:` for a bug fix
   * `docs:` for documentation changes
   * `refactor:` for code improvements without changing behavior
   * `test:` for test-only changes
   * `chore:` for maintenance (dependencies, tooling, config)

4. **Run tests and lint before pushing**:

   ```bash
   python -m unittest discover -s tests -t . -v
   ruff check .
   ```

5. **Push your branch**:

   ```bash
   git push origin feature/<short_feature_name>
   ```

6. **Open a Pull Request (PR)** from your fork on GitHub, describing what changed and why.

---

## Code Review Process

* All PRs are reviewed by project maintainers.
* Reviews may request changes for consistency, security, or clarity.
* Once approved, your PR is merged into `master`.
* CI (lint + full test suite) must pass before merge.

---

## Best Practices

* Keep commits small and focused.
* Write clear commit messages.
* Ensure code passes `ruff check .`.
* Add/update tests where relevant - new code should have test coverage;
  bug fixes should include a test that reproduces the bug.
* Update documentation when introducing changes.

---

✅ Following these steps helps us keep **vt_tool** reliable, maintainable, and secure.
```

- [ ] **Step 2: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: add CONTRIBUTING.md"
```

---

### Task 5: `.githooks/commit-msg`

**Files:**
- Create: `.githooks/commit-msg` (executable)

**Interfaces:**
- Produces: the hook `CONTRIBUTING.md` (Task 4) documents wiring via `git config core.hooksPath .githooks`.

- [ ] **Step 1: Create the file**

Write `.githooks/commit-msg` with exactly this content:

```bash
#!/usr/bin/env bash
#
# commit-msg — Conventional Commits validator.
#
# Enable per clone with:
#   git config core.hooksPath .githooks
#
# Allowed types match CONTRIBUTING.md:
#   feat, fix, chore, docs, refactor, perf, test, ci, build, style, revert
#
# Format: <type>(optional-scope)!?: <subject>
# Examples:
#   feat(cli): add --output-format json
#   fix(dbhandler)!: drop legacy column layout
#   chore: bump vt-py 0.21.0 -> 0.22.0

set -euo pipefail

msg_file="$1"
# Strip comments and leading blank lines, take only the first non-empty line.
subject=$(grep -v '^\s*#' "$msg_file" | sed '/^[[:space:]]*$/d' | head -n 1 || true)

# Skip Git's auto-generated subjects (merge / revert / fixup / squash).
case "$subject" in
    "Merge "*|"Revert "*|"fixup! "*|"squash! "*|"amend! "*)
        exit 0
        ;;
esac

pattern='^(feat|fix|chore|docs|refactor|perf|test|ci|build|style|revert)(\([a-zA-Z0-9_./-]+\))?!?: .+'

if [[ ! "$subject" =~ $pattern ]]; then
    cat >&2 <<EOF

[commit-msg] Rejecting commit — subject does not follow Conventional Commits.

Got:    $subject

Expected: <type>(optional-scope)!?: <subject>
Types:    feat, fix, chore, docs, refactor, perf, test, ci, build, style, revert

Examples:
  feat(cli): add --output-format json
  fix(dbhandler)!: drop legacy column layout
  chore: bump vt-py 0.21.0 -> 0.22.0

EOF
    exit 1
fi

# Reject overly long subjects (>72 chars). Conventional Commits suggests <=72.
if (( ${#subject} > 72 )); then
    cat >&2 <<EOF

[commit-msg] Subject is ${#subject} chars; cap is 72.
            Move detail to the body (separate by a blank line).
Got:        $subject

EOF
    exit 1
fi

exit 0
```

- [ ] **Step 2: Make it executable and verify it actually rejects/accepts correctly**

```bash
chmod +x .githooks/commit-msg
git config core.hooksPath .githooks

# Should be rejected (exit 1):
echo "not a conventional commit" > /tmp/bad-msg.txt
.githooks/commit-msg /tmp/bad-msg.txt; echo "exit: $?"

# Should be accepted (exit 0):
echo "docs: test the hook" > /tmp/good-msg.txt
.githooks/commit-msg /tmp/good-msg.txt; echo "exit: $?"
```

Expected: first command prints the rejection message and `exit: 1`; second prints nothing and `exit: 0`.

- [ ] **Step 3: Commit**

```bash
git add .githooks/commit-msg
git commit -m "ci: add Conventional Commits git hook"
```

(This commit's own message must itself pass the hook you just wired — if it doesn't, something is wrong with the hook, not an excuse to bypass it.)

---

### Task 6: `ruff.toml` + fix the 12 pre-existing findings

**Files:**
- Create: `ruff.toml`
- Modify: `app/DataHandler/validator.py`
- Modify: `app/DBHandler/db_handler.py`
- Modify: `app/FileHandler/output_to_file.py`
- Modify: `app/FileHandler/read_file.py`
- Modify: `app/MISP/vt_tools2misp.py`
- Modify: `app/VirusTotal/vt_reporter.py`

**Interfaces:**
- Produces: a clean `ruff check .` baseline that Task 7's CI workflow can gate on from day one.

- [ ] **Step 1: Create `ruff.toml`**

```toml
# Ruff configuration.
target-version = "py311"
line-length = 120

[lint]
# Explicit select, matching ruff's own documented default (E4, E7, E9, F).
# Spelled out rather than left implicit: an implicit/unset `select` rides
# whatever rule set a given ruff release's default happens to be, and can
# silently pull in far more rules on a version bump, failing CI on findings
# unrelated to whatever a given PR actually touched.
select = ["E4", "E7", "E9", "F"]
```

- [ ] **Step 2: Install ruff locally and confirm the 12 pre-existing findings match exactly**

```bash
source .venv/bin/activate
pip install ruff
ruff check .
```

Expected: exactly 12 findings, matching this list (confirmed during design):

| File | Line | Rule |
|---|---|---|
| `app/DataHandler/validator.py` | 1 | F401 (`os` unused) |
| `app/DataHandler/validator.py` | 15 | F841 (`except ... as e` unused, `get_service_name`) |
| `app/DataHandler/validator.py` | 23 | F841 (`except ... as e` unused, `get_port_from_service_name`) |
| `app/DBHandler/db_handler.py` | 180 | F841 (`except ... as e` unused) |
| `app/DBHandler/db_handler.py` | 426 | F841 (`except ... as e` unused) |
| `app/FileHandler/output_to_file.py` | 6 | F401 (`Markdown` unused) |
| `app/FileHandler/output_to_file.py` | 83 | F841 (`except ... as e` unused) |
| `app/FileHandler/read_file.py` | 4 | F401 (`csv` unused) |
| `app/FileHandler/read_file.py` | 7 | F401 (`Callable` unused) |
| `app/FileHandler/read_file.py` | 314 | F841 (`csv_values` unused) |
| `app/MISP/vt_tools2misp.py` | 224 | E713 (`not (x in y)` → `x not in y`) |
| `app/VirusTotal/vt_reporter.py` | 169 | E722 (bare `except:`) |

If the line numbers or count differ from this table (e.g. because an earlier task's edits shifted something), that's fine — trust `ruff check .`'s actual output over this table, but the *set* of underlying issues (which unused imports/bindings, which two style rules) should still match. If it finds meaningfully different issues, stop and report NEEDS_CONTEXT rather than fixing something not on this list.

- [ ] **Step 3: Fix the 10 auto-fixable findings**

```bash
ruff check --fix .
```

- [ ] **Step 4: Manually fix the 2 non-auto-fixable findings**

In `app/DataHandler/validator.py`, `get_service_name` and `get_port_from_service_name` currently end with:

```python
    except (socket.error, ValueError):
        return None
    except Exception as e:
        return None
```

Change `except Exception as e:` to `except Exception:` in both functions (the `as e` binding is unused — ruff's F841 flags it, but won't auto-remove it since it's not certain the binding has zero side-effect implications).

- [ ] **Step 5: Verify ruff is clean and the test suite still passes**

```bash
ruff check .
python -m unittest discover -s tests -t . -v
```

Expected: `ruff check .` reports no findings (`All checks passed!`); full suite still 122/122 passing (these are all dead-code/unused-binding removals plus a bare-except tightening — nothing any test exercises, so no test changes are needed and none should be made).

- [ ] **Step 6: Commit**

```bash
git add ruff.toml app/DataHandler/validator.py app/DBHandler/db_handler.py app/FileHandler/output_to_file.py app/FileHandler/read_file.py app/MISP/vt_tools2misp.py app/VirusTotal/vt_reporter.py
git commit -m "chore: add ruff config, fix 12 pre-existing lint findings"
```

---

### Task 7: `.github/workflows/ci.yml`

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `ruff.toml` (Task 6) and the `tests/` suite (already present) — this workflow runs both.

- [ ] **Step 1: Create the file**

```yaml
name: CI

on:
  pull_request:
    branches: [master]
  push:
    branches: [master]

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -r requirements.txt
      - run: pip install ruff
      - run: ruff check .
      - run: python -m unittest discover -s tests -t . -v
```

- [ ] **Step 2: Validate the YAML syntax locally**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('valid YAML')"
```

(If `pyyaml` isn't installed, `pip install pyyaml` first just for this check — it's a one-off syntax validation, not a project dependency.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions lint+test workflow"
```

(This is the first commit that will actually run once pushed — full remote verification happens after this plan's tasks are merged and pushed, not locally.)

---

### Task 8: Full verification pass

**Files:** none (verification only)

- [ ] **Step 1: Confirm every governance file exists and cross-references resolve**

```bash
ls LICENSE CODE_OF_CONDUCT.md CONTRIBUTING.md .github/SECURITY.md .githooks/commit-msg ruff.toml .github/workflows/ci.yml
test ! -e LICENSE.md && echo "LICENSE.md correctly removed"
grep -q "SECURITY.md" CODE_OF_CONDUCT.md && echo "CODE_OF_CONDUCT.md correctly links to SECURITY.md"
```

- [ ] **Step 2: Full lint + test run from a clean shell**

```bash
cd /home/forensics/vt_tool
source .venv/bin/activate
ruff check .
python -m unittest discover -s tests -t . -v
```

Expected: `ruff check .` clean, 122/122 tests passing.

- [ ] **Step 3: Confirm the git hook is wired and working**

```bash
git config core.hooksPath
```

Expected: `.githooks`.

- [ ] **Step 4: Confirm no stray files and working tree is clean**

```bash
git status --short
```

Expected: empty (everything committed).

- [ ] **Step 5: Report a short summary to the user**

No commit for this step — just confirm to the user: all 4 governance docs present and cross-referencing correctly, ruff clean (12 pre-existing findings fixed), 122 tests passing, commit-msg hook verified working, CI workflow committed (will run for real on the next push/PR). Remind the user this was sub-project A only — sub-project B (long-running containerized API service) is still fully unstarted.

---

## Self-Review

**Spec coverage:** all three design components covered — governance docs (Tasks 1-4), enforcement tooling (Tasks 5-6), CI (Task 7), plus a verification task (8). The design's explicit exclusions (CodeQL, Dependabot, issue/PR templates, CODEOWNERS, release automation, docs-site workflow, commitlint-in-CI) are deliberately absent from this plan — not an oversight.

**Placeholder scan:** no TBD/TODO; every file's content is given in full, not described. The one explicit judgment call in the design (whether the PSIRT contact is actually meant to be shared org-wide) is carried into Task 1 as literal content per the approved design, not left as an open question in this plan — the design spec already flagged it for the user's awareness, and the user approved the design as-is including that content, so it is not re-litigated here.

**Type/consistency check:** file paths and content are cross-checked against each other (`CODE_OF_CONDUCT.md`'s link target matches `SECURITY.md`'s actual path; `CONTRIBUTING.md`'s documented hook-wiring command matches the actual `.githooks/commit-msg` mechanism; `ci.yml`'s Python versions match `CONTRIBUTING.md`'s stated `Python 3.11+` floor). The README-update step in Task 3 was verified against the actual current `README.md` content during planning (both relevant lines already reference the bare `LICENSE` filename generically) rather than assumed from the design doc, which had guessed changes might be needed.
