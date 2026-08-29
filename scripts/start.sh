#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

grafana_port="${GRAFANA_PORT:-3001}"
open_browser="${OPEN_BROWSER:-1}"
auto_start_docker="${AUTO_START_DOCKER:-1}"

port_in_use() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "$1" >/dev/null 2>&1
  else
    return 1
  fi
}

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

if [[ -z "${GRAFANA_PORT:-}" ]]; then
  original_grafana_port="$grafana_port"
  while port_in_use "$grafana_port"; do
    grafana_port=$((grafana_port + 1))
  done

  if [[ "$grafana_port" != "$original_grafana_port" ]]; then
    export GRAFANA_PORT="$grafana_port"
    echo "Grafana port ${original_grafana_port} is busy; using ${grafana_port}."
  fi
fi

echo "Starting the Aegis stack..."
docker compose up --build -d

urls=(
  "http://localhost:8000"
  "http://localhost:${grafana_port}"
  "http://localhost:9091"
  "http://localhost:8080"
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
