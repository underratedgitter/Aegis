#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

# shellcheck source=scripts/ports.sh
source "$project_dir/scripts/ports.sh"

# Fault injection and remediation are disabled without a shared admin key.
# Generate a local key once so `make start` keeps the demo usable.
if [[ -z "${AEGIS_API_KEY:-}" ]]; then
  if [[ -f .env ]] && grep -q '^AEGIS_API_KEY=.' .env; then
    AEGIS_API_KEY="$(grep '^AEGIS_API_KEY=' .env | tail -1 | cut -d= -f2-)"
    export AEGIS_API_KEY
  else
    AEGIS_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    export AEGIS_API_KEY
    touch .env
    printf '\nAEGIS_API_KEY=%s\n' "$AEGIS_API_KEY" >> .env
    echo "Generated AEGIS_API_KEY in .env; admin/fault endpoints are key-protected."
  fi
fi

grafana_port="${GRAFANA_PORT:-3001}"
checkout_port="${CHECKOUT_PORT:-8080}"
open_browser="${OPEN_BROWSER:-1}"
auto_start_docker="${AUTO_START_DOCKER:-1}"

docker_server_ready() {
  local server_version
  server_version="$(docker info --format '{{.ServerVersion}}' 2>/dev/null || true)"
  [[ -n "$server_version" ]]
}

if ! docker_server_ready; then
  docker_context="$(docker context show 2>/dev/null || true)"

  if [[ "$auto_start_docker" == "1" && "$docker_context" == "colima" ]] && command -v colima >/dev/null 2>&1; then
    echo "Docker is not running; starting Colima..."
    colima start
  fi

  if ! docker_server_ready; then
    echo "Docker is not running. Start Docker Desktop or run 'colima start', then retry 'make start'." >&2
    echo "To disable automatic Docker startup, use AUTO_START_DOCKER=0 make start." >&2
    exit 1
  fi
fi

# Ports this stack publishes besides the two that can move; never auto-pick them.
fixed_ports=(8000 8081 9091 3100)

# The port a running stack already publishes, so a re-run keeps it instead of treating it as busy.
published_port() {
  docker compose port "$1" "$2" 2>/dev/null | tail -1 | sed 's/.*://' || true
}

# An explicit GRAFANA_PORT / CHECKOUT_PORT always wins. Otherwise reuse the port saved in the
# env file while it is free, else take the next free one and save it so that a later plain
# `docker compose up` publishes the same port.
if [[ -z "${GRAFANA_PORT:-}" ]]; then
  grafana_port="$(select_port GRAFANA_PORT 3001 "$(published_port grafana 3000)" "${fixed_ports[@]}" 8080)"
  export GRAFANA_PORT="$grafana_port"
  if [[ "$grafana_port" != "3001" ]]; then
    echo "Grafana port 3001 is busy; using ${grafana_port} (saved to .env)."
  fi
fi

if [[ -z "${CHECKOUT_PORT:-}" ]]; then
  checkout_port="$(select_port CHECKOUT_PORT 8080 "$(published_port checkout 8000)" "${fixed_ports[@]}" "$grafana_port")"
  export CHECKOUT_PORT="$checkout_port"
  if [[ "$checkout_port" != "8080" ]]; then
    echo "Checkout port 8080 is busy; using ${checkout_port} (saved to .env)."
  fi
fi

echo "Starting the Aegis stack..."
docker compose up --build -d

urls=(
  "http://localhost:8000"
  "http://localhost:${grafana_port}"
  "http://localhost:9091"
  "http://localhost:${checkout_port}"
  "http://localhost:8081"
)

echo "Waiting for the control room to become available..."
for attempt in {1..30}; do
  if curl --fail --silent --show-error --max-time 2 http://localhost:8000 >/dev/null; then
    break
  fi

  if [[ "$attempt" == "30" ]]; then
    echo "The stack started, but the control room did not respond in time." >&2
    echo "Check the service logs with: make logs" >&2
    exit 1
  fi

  sleep 2
done

echo "Aegis is running:"
printf '  %s\n' "${urls[@]}"

if [[ "$open_browser" == "1" ]]; then
  if command -v open >/dev/null 2>&1; then
    for url in "${urls[@]}"; do
      open "$url"
    done
  elif command -v xdg-open >/dev/null 2>&1; then
    for url in "${urls[@]}"; do
      xdg-open "$url" >/dev/null 2>&1 &
    done
  else
    echo "No supported browser opener found; use the URLs above."
  fi
fi
