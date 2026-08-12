<p align="center">
    <img src="assets/VTTools Logo.webp" alt="VirusTotal Tool Logo" width="250" height="250">
</p>

# THA-CERT VT Tool

[![License](https://img.shields.io/github/license/thalesgroup-cert/vt_tool)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](#requirements)
[![Issues](https://img.shields.io/github/issues/thalesgroup-cert/vt_tool)](https://github.com/thalesgroup-cert/vt_tool/issues)
[![Stars](https://img.shields.io/github/stars/thalesgroup-cert/vt_tool?style=social)](https://github.com/thalesgroup-cert/vt_tool/stargazers)

Welcome to VT_Tool by THA-CERT!

> VirusTotal analysis tool with local caching and optional MISP integration.

`vt_tool` retrieves analysis information for IP addresses, hashes, URLs, and domains using the VirusTotal v3 API.
It supports interactive and non-interactive modes, local result caching with a configurable TTL, structured CSV/TXT export, and MISP integration.

This README covers the CLI, the tool's original and primary interface. vt_tool can also run as a long-running HTTP service for automation/SOAR integration — jump to [Running as a Service](#running-as-a-service), or go straight to [`deployment/README.md`](deployment/README.md) for the Docker Compose deployment of that service.

## Features

* Query VirusTotal for:

  * IPv4 addresses
  * File hashes (MD5, SHA-1, SHA-256)
  * URLs
  * Domains
* Automatic quota checking (hourly VT API quota)
* Local caching with configurable TTL — SQLite by default, or any SQLAlchemy-supported database
* CSV and TXT report generation
* Template-based input processing
* Optional MISP event creation/update
* Proxy support
* Interactive CLI (Rich UI)
* Fully non-interactive automation mode
* Optional HTTP API + background worker for programmatic/automated use (see [Running as a Service](#running-as-a-service))

## Architecture Overview

```txt
CLI (argparse)
   │
   ├── Input Handling (file / template / CLI args)
   ├── Validator (IP / hash / URL / domain)
   ├── Local SQLite cache
   ├── VirusTotal API v3 client
   ├── Report processing
   │     ├── CSV export
   │     └── TXT formatted report
   └── Optional MISP integration
```

## Requirements

* Python 3.11+
* VirusTotal API key
* Internet access
* Optional: MISP instance (for integration)

Dependencies are listed in `requirements.txt`.

## Installation

```bash
git clone https://github.com/thalesgroup-cert/vt_tool.git
cd vt_tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

### 1️⃣ VirusTotal API Key

You can provide the API key in one of three ways:

#### Option A — Environment variable (recommended)

```bash
export VTAPIKEY="your_api_key"
```

#### Option B — CLI argument

```bash
--api_key YOUR_KEY
```

#### Option C — API key file

```bash
--api_key_file path/to/keyfile.txt
```

> You cannot use both `--api_key` and `--api_key_file` at the same time.

### 2️⃣ Proxy (optional)

```bash
--proxy http://127.0.0.1:8080
```

## Usage

```bash
python vt_tools.py [OPTIONS] VALUES...
```

If no values or input file are provided, execution stops with error.

## CLI Arguments (Complete Reference)

| Option              | Short | Description                                                                            |
| ------------------- | ----- | -------------------------------------------------------------------------------------- |
| `--template_file`   | `-tf` | Template file to use for structured IOC input.                                         |
| `--input_file`      | `-f`  | File containing IOCs to analyze.                                                       |
| `--output_dir`      | `-o`  | Directory where output reports are saved.                                              |
| `--type`            | `-t`  | Type of values to analyze: `ips`, `hashes`, `urls`, `domains`, `all` (default: `all`). |
| `--non_interactive` | `-n`  | Disable interactive prompts. Required for automation.                                  |
| `--case_id`         | `-c`  | Case ID or MISP event UUID (zero-padded to 6 digits).                                  |
| `--api_key`         | `-a`  | VirusTotal API key.                                                                    |
| `--api_key_file`    | `-af` | Path to file containing API key.                                                       |
| `--proxy`           | `-p`  | Proxy URL for outbound requests.                                                       |
| `values`            | —     | One or more IPs, hashes, URLs, or domains.                                             |

## Supported Types

| Type         | CLI Value |
| ------------ | --------- |
| IP addresses | `ips`     |
| File hashes  | `hashes`  |
| URLs         | `urls`    |
| Domains      | `domains` |
| All types    | `all`     |

## Input Methods

### 1️⃣ Direct CLI values

```bash
python vt_tools.py -t ips 8.8.8.8 1.1.1.1
```

### 2️⃣ Input file

```bash
python vt_tools.py -f iocs.txt
```

File format:

```txt
8.8.8.8
example.com
44d88612fea8a8f36de82e1278abb02f
```

### 3️⃣ Template mode

```bash
python vt_tools.py -tf template.csv
```

Template options available:

| Option | Template Structure                           |
| ------ | -------------------------------------------- |
| 1      | value,comment                                |
| 2      | value,comment,source                         |
| 3      | value,category,type,comment,to_ids,tag1,tag2 |

Interactive selection will prompt template choice.

## Interactive vs Non-Interactive Mode

### Interactive (default)

* Prompts for analysis type
* Prompts for MISP integration
* Displays Rich UI panels

### Non-Interactive

```bash
python vt_tools.py -n -t ips -f iocs.txt
```

* No prompts
* No MISP interactive selection
* Logging output instead of Rich prompts

## Quota Handling

Before analysis begins:

* The tool queries VirusTotal hourly quota.
* If quota is exhausted, execution stops.
* If requested IOCs exceed remaining quota, a warning is shown.
* Already cached IOCs do **not consume quota**.

## Local Database

* SQLite database by default: `vttools.sqlite`, automatically created if not present
* Prevents re-querying existing values
* Skips:

  * Private IPs
  * Loopback IPs
  * Reserved IP ranges
  * Unsupported hash types (SHA-224, SHA-384, SHA-512, SSDEEP)

### Cache configuration

Two environment variables (see `.env.example`) control caching, with sensible defaults if unset:

* `VT_CACHE_TTL_HOURS` — how long a cached result stays valid before it's treated as stale and re-queried.
* `VT_CACHE_DB_URL` — the cache backend. Defaults to the local `vttools.sqlite` file; can point to any SQLAlchemy-supported database (e.g. Postgres, MySQL) for shared/multi-instance caching.

## Output

For each analysis type:

### 1️⃣ CSV Report

Generated automatically.
Contains structured VT results.

### 2️⃣ TXT Report

Formatted table version of results.

Files are saved in:

* Current directory (default)
* Or `--output_dir` if provided

## MISP Integration

If:

* Running in interactive mode
* Or using template mode

The tool can:

* Create new MISP event
* Update existing MISP event (via `--case_id`)

Non-interactive mode skips MISP integration.

## Example Commands

### Analyze single IP

```bash
python vt_tools.py -t ips 8.8.8.8
```

### Analyze hashes from file

```bash
python vt_tools.py -t hashes -f hashes.txt
```

### Full automation mode

```bash
python vt_tools.py -n -t all -f iocs.txt --api_key YOUR_KEY
```

### Using template mode

```bash
python vt_tools.py -tf template.csv -c 123456
```

## Error Handling

The tool handles:

* Invalid IOCs
* Unsupported value types
* Quota exhaustion
* API failures
* Network errors
* Duplicate DB entries

Errors are counted and reported at the end of execution.

## Exit Behavior

Execution ends with:

* Total time taken
* Remaining quota
* Number of skipped values
* Number of errors

## Logging

* INFO level logging enabled by default
* Errors logged to console
* In non-interactive mode, logs replace UI prompts

## Security Considerations

* API keys are never logged
* Proxy support for controlled outbound traffic
* Local DB prevents unnecessary API calls
* Invalid or sensitive IP ranges are filtered

## Running as a Service

vt_tool can also run as a long-running HTTP service instead of a one-shot CLI invocation — useful for automation, SOAR integration, or anything that wants to submit lookups programmatically rather than shelling out to the CLI.

* **API** (`app/api/main.py`, FastAPI) — `POST /analyze` queues a lookup, `GET /jobs/{job_id}` polls its status, `GET /health` reports readiness.
* **Worker** (`app/worker/`, [arq](https://arq-docs.helpmanual.io/)) — picks jobs off a Redis queue and performs the VirusTotal lookup, sharing the same cache and analysis logic as the CLI.

For a Docker Compose deployment of the API + worker + Redis, see [`deployment/README.md`](deployment/README.md).

## Development

### Run directly

```bash
python vt_tools.py --help
```

### Run tests / lint

```bash
python -m unittest discover -s tests -t . -v
ruff check .
```

See `CONTRIBUTING.md` for the full development workflow.

### Code structure highlights

CLI (`vt_tools.py`, `init.py`):

* `Initializator` → handles DB, validator, reporter
* `ValueReader` → parses input/template files
* `db_handler` → manages SQLite
* `reporter` → calls VT API
* `validator` → validates IOC format

Shared library / service layer, used by both the CLI and the API:

* `app/services/` → `AnalysisService` and related services: analysis, caching, and validation logic shared across the CLI and the API
* `app/cache_backends/` → pluggable cache storage (SQLite file, or any SQLAlchemy-supported database via `VT_CACHE_DB_URL`)
* `app/api/` → FastAPI HTTP service
* `app/worker/` → arq background worker

## License

See `LICENSE` file.
