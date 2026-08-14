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
