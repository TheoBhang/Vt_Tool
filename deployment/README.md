# Modern Deployment Guide

This project provides a **modular, automated, Docker-based deployment system** designed for reliability, maintainability, and ease of use.
It relies on:

* **Docker Compose v2**
* **Environment configuration via `.env`**
* **Self-contained helper scripts** (`scripts/`)
* **Optional Makefile shortcuts** for convenience
* A comprehensive **checklist** that prepares all required files, directories, and certificates

## Requirements

Before running any commands, ensure you have:

* **Make**
* **Docker**
* **Docker Compose v2 (`docker compose` subcommand)**
* **curl**

The `scripts/init.sh` and `scripts/check-network.sh` utilities will verify and prepare the environment automatically.

## Initialization

Run the full initialization script:

```bash
make init
```

This performs:

* Creation of the `.env` file (or uses yours if present)
* Directory structure validation
* Download/creation of config files
* Certificate generation (if missing)
  …and other required system checks.

This step ensures the project is ready to run.

## Starting the Stack

### Start all services

```bash
make up
```

or manually:

```bash
docker compose --env-file .env up -d
```

### Stop all services

```bash
make down
```

## Deployment Workflow

To pull new images, rebuild if needed, and restart services safely:

```bash
make deploy
```

This command runs:

* Network checks
* TLS/hostname replacement
* Deployment script execution

## 🛠 Development & Maintenance Commands

### Build images

```bash
make build
```

### Pull latest images

```bash
make pull
```

### Regenerate certificates

```bash
make create-certs
```

## MISP Integration

This stack does not run a local MISP instance. vt_tool's MISP-submission feature (`vt_tools.py`'s template-file workflow, implemented in `app/MISP/vt_tools2misp.py`) is configured independently of this deployment: set `MISPURL`, `MISPKEY`, and `MISPSSLVERIFY` in the repository's root-level `.env` file (see the root `.env.example`), pointed at whichever MISP instance you actually run. This deployment stack has no opinion about where that instance lives.

## Project Structure

```txt
.
├── docker-compose.yml           # Main orchestration file
├── .env.example                 # Example configuration (safe to commit)
├── .env                         # Real configuration (never commit)
├── scripts/                     # Modular shell scripts
│   ├── init.sh                  # Main initializer (system checks + setup)
│   ├── check-network.sh
│   ├── deploy.sh
│   └── openssl-certificates-generator.sh
└── Makefile                     # User-friendly command shortcuts
```

## Security Notes

* `.env` **must never be committed** — it contains secrets.
* `.env` is already included in `.gitignore`.
* Secrets can also be provided through:

  * environment variables
  * CI/CD secret stores
  * Docker Compose overrides

## Summary

| Action                | Command             |
| --------------------- | ------------------- |
| Initialize everything | `make init`         |
| Start services        | `make up`           |
| Stop services         | `make down`         |
| Deploy updates        | `make deploy`       |
| Generate certificates | `make create-certs` |
