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
