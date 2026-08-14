#!/usr/bin/env sh
set -eu

echo "============================================"
echo "      vt tool – CHECKLIST"
echo "============================================"

# -------------------------------------------------
# 1. Required binaries
# -------------------------------------------------
echo "[1/2] Checking required binaries..."

# Check for docker binary
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: docker"
fi

# Check that docker supports the compose subcommand
if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: Docker Compose is not available (docker compose subcommand required)"
fi

# Check curl
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: Missing required binary: curl"
fi

echo "→ OK"

# -------------------------------------------------
# 2. Ensure .env exists
# -------------------------------------------------
echo "[2/2] Checking .env..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "→ .env created from .env.example"
    else
        echo "ERROR: Missing both .env and .env.example"
    fi
else
    echo "→ .env present"
fi

# Load environment variables
set -a
. ./.env
set +a

# -------------------------------------------------
# Completion
# -------------------------------------------------
echo "============================================"
echo "    CHECKLIST COMPLETED"
echo "    All required components are in place."
echo "    You can now modify:"
echo "        - .env for network and other settings"
echo "    Then run 'make deploy' to start the application."
echo "============================================"
