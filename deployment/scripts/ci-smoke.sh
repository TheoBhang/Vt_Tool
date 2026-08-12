#!/usr/bin/env bash
# CI smoke test: build the real stack, boot it, and drive one lookup through
# the full chain (API -> Redis -> worker -> job status). Local or CI.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/deployment"

[ -f .env ] || cp .env.example .env

COMPOSE="docker compose --env-file .env -f docker-compose.yml"

./scripts/check-network.sh

cleanup() {
  rc=$?
  $COMPOSE logs --no-color > ci-stack.log 2>&1 || true
  if [ "$rc" -ne 0 ]; then
    echo "=== smoke test failed (rc=$rc); recent logs ==="
    $COMPOSE logs --no-color --tail 60 2>&1 || true
  fi
  $COMPOSE down --remove-orphans -v || true
  rm -f .env
}
trap cleanup EXIT

$COMPOSE up -d --build

echo "waiting for containers to report healthy..."
healthy=0
for _ in $(seq 1 45); do
  redis_h=$(docker inspect -f '{{.State.Health.Status}}' redis 2>/dev/null || echo "")
  api_h=$(docker inspect -f '{{.State.Health.Status}}' vt-tool-api 2>/dev/null || echo "")
  worker_h=$(docker inspect -f '{{.State.Health.Status}}' vt-tool-worker 2>/dev/null || echo "")
  if [ "$redis_h" = "healthy" ] && [ "$api_h" = "healthy" ] && [ "$worker_h" = "healthy" ]; then
    healthy=1
    break
  fi
  sleep 2
done
if [ "$healthy" -ne 1 ]; then
  echo "ERROR: containers did not become healthy in time (redis=$redis_h api=$api_h worker=$worker_h)"
  exit 1
fi

API_PORT="${VT_TOOL_API_PORT:-8080}"

echo "hitting /health..."
curl -sf "http://127.0.0.1:${API_PORT}/health"
echo

echo "submitting analyze request..."
RESP=$(curl -sf -X POST "http://127.0.0.1:${API_PORT}/analyze" \
  -H "Content-Type: application/json" \
  -d '{"values": [{"value": "example.com", "value_type": "domains"}], "api_key": "fake-key-for-ci-smoke-test"}')
echo "$RESP"

JOB_ID=$(printf '%s' "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['job_id'])")

echo "polling job ${JOB_ID}..."
STATUS=""
for _ in $(seq 1 15); do
  JOB_RESP=$(curl -sf "http://127.0.0.1:${API_PORT}/jobs/${JOB_ID}")
  STATUS=$(printf '%s' "$JOB_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
  if [ "$STATUS" = "failed" ] || [ "$STATUS" = "complete" ]; then
    break
  fi
  sleep 2
done

echo "final job status: ${STATUS}"
if [ "$STATUS" != "failed" ]; then
  echo "ERROR: expected job to reach 'failed' status with a fake API key, got '${STATUS}'"
  exit 1
fi

echo "CI smoke test passed."
