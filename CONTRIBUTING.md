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
