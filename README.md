# Aegis

### An evidence-first AI SRE copilot for a toy production environment

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-control--plane-009688?logo=fastapi&logoColor=white)
![Docker Compose](https://img.shields.io/badge/Docker_Compose-ready-2496ED?logo=docker&logoColor=white)

Aegis watches a small checkout-and-inventory application, detects abnormal behavior, correlates related signals into incidents, investigates them using real telemetry and runbooks, and proposes a bounded remediation.

> Aegis is a local observability and incident-response demo. It does not replace production alerting, authentication, on-call infrastructure, or change-management controls.

It is deliberately runnable without an API key. Local fallback mode performs the complete telemetry and approval workflow deterministically; setting `OPENAI_API_KEY` enables the optional tool-calling investigator.

| Start here | Link |
|---|---|
| Control room | <http://localhost:8000> |
| API documentation | <http://localhost:8000/docs> |
| Grafana signals | <http://localhost:3001> or <http://localhost:3002> |
| Quick demo | [Run Aegis](#run-aegis) |
| Safety model | [Human-approved remediation](#safety-model-and-design-decisions) |

## Contents

- [What Aegis demonstrates](#what-aegis-demonstrates)
- [Run Aegis](#run-aegis)
- [Demo workflow](#demo-workflow-at-a-glance)
- [Architecture](#architecture)
- [Useful API calls](#useful-api-calls)
- [Local development](#local-development)
- [Safety and design decisions](#safety-model-and-design-decisions)
- [Troubleshooting](#troubleshooting)

## What Aegis demonstrates

- `checkout` calls `inventory`, exposes Prometheus metrics, and emits JSONL logs.
- Bounded chaos for latency, 5xx errors, dependency failure, and CPU stress.
- Prometheus, Grafana, Loki, and Promtail in Docker Compose.
- Threshold alerts plus a rolling z-score detector.
- Root-cause correlation: checkout error/latency signals merge into an inventory incident when the inventory dependency is the common signal.
- An evidence-citing investigator with four read-only tools: current metrics, recent logs, runbooks, and incident timeline.
- A safe remediation allowlist: clear an injected fault or change a demo replica-count gauge from 1–3. No shell, Docker socket, arbitrary URL, or arbitrary command execution.
- A small web control room showing incident state, evidence, timeline, metrics, and the approval gate.
- SQLite incident history and MTTR calculation.

## Run Aegis

Requirements: Docker Desktop or another Docker Engine with Compose, plus `python3` and `curl` on the host (`make start` uses them to generate a key and wait for the control room).

If your Docker context is Colima on macOS, `make start` automatically starts Colima when it is
stopped. You can disable that behavior with `AUTO_START_DOCKER=0 make start`.

```bash
cp .env.example .env
make start
```

`make start` builds and starts every container in the background, waits for the control room,
and opens the local pages automatically. Published ports bind to `127.0.0.1` by default; set
`AEGIS_BIND_ADDR` to change that.

- Aegis control room: <http://localhost:8000>
- Grafana: <http://localhost:3001> (or `3002` if 3001 is occupied; default credentials: `admin` / `admin`)
- Prometheus: <http://localhost:9091>
- Checkout: <http://localhost:8080>
- Inventory: <http://localhost:8081>

On macOS, you can also double-click [`start.command`](start.command) to run the same startup
flow. To start the stack without opening browser tabs, use `OPEN_BROWSER=0 make start`.

If host port 3001 is already in use, `make start` automatically selects the next available
Grafana port. You can also choose one explicitly without changing the other services:

```bash
GRAFANA_PORT=3002 make start
```

Fault injection, approval, and execution are protected by a shared `AEGIS_API_KEY`. If none is set,
`make start` generates one and appends it to `.env`. Paste it into the control room's **API key**
box before using the action buttons; the key is kept in the browser's session storage. Without a
key, `/api/chaos` and the service admin routes return 503.

The control room is the recommended demo surface. If you want traffic before injecting a fault:

```bash
python3 scripts/smoke.py --count 100
```

`scripts/smoke.py` defaults to `--checkout-url http://localhost:8080` and `--count 20`.

Or inject a failure from a terminal, passing the key from `.env`:

```bash
export AEGIS_API_KEY="$(grep '^AEGIS_API_KEY=' .env | tail -1 | cut -d= -f2-)"
python3 scripts/chaos.py --service inventory --fault dependency --duration 60
```

`chaos.py` reads `AEGIS_API_KEY` from the environment (or `--api-key`). Faults are `latency`, `errors`, `dependency`, and `cpu`; `--duration` is 1–900 seconds and `--intensity` is 0.1–10. Pass `--random` to keep injecting random bounded incidents. `make chaos` runs the single-fault example above (using the exported `AEGIS_API_KEY`).

Wait for the incident engine to detect the failure. The expected flow is:

1. `inventory_dependency_errors`, checkout 5xx rate, and possibly checkout p95 latency rise.
2. The engine correlates those signals under `dependency:inventory`.
3. Aegis collects Prometheus values, recent JSON logs, the inventory runbook, and its own timeline.
4. The incident moves to `recommendation_pending` with a proposed `clear_fault` action.
5. Click **Approve recommendation**, then **Execute approved fix** (with the API key entered).
6. The fault clears; after two healthy polling cycles the incident is marked resolved and contributes to MTTR.

To use a real LLM investigator, add a key to `.env` before starting Compose:

```dotenv
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4.1-mini
```

The key is only used by the control-plane investigator. The agent still has the same narrow read tools and the same remediation approval gate.

## Architecture

```text
                 ┌──────────────────────┐
 chaos.py/UI ───▶│ checkout ──────────── │──▶ inventory
                 │ metrics + JSON logs   │    metrics + JSON logs
                 └──────────┬───────────┘    └──────────┬──────────
                            │ Prometheus                 │
                            ▼                            ▼
                    ┌───────────────┐            ┌───────────────┐
                    │ Prometheus    │            │ Loki/Promtail │
                    └───────┬───────┘            └───────┬───────┘
                            └──────────────┬─────────────┘
                                           ▼
                         ┌────────────────────────────────┐
                         │ Aegis control plane             │
                         │ rules → correlation → agent     │
                         │ → approval → bounded executor   │
                         └────────────────┬───────────────┘
                                          ▼
                                  SQLite + web UI
```

The Compose topology is the reliable local demo. The service container boundaries and HTTP admin surface make it straightforward to move the demo services to Kubernetes later; the important safety boundary is that the executor talks only to explicit service endpoints and does not receive a cluster-admin credential.

## Demo workflow at a glance

```text
traffic → metrics/logs → detection → correlation → investigation
       → recommendation_pending → human approval → safe remediation → resolution
```

The dashboard is the best place to watch the workflow, while Grafana provides the underlying Prometheus and Loki data.

## Useful API calls

Read endpoints are open. State-changing endpoints (`POST` routes and `GET /api/audit`) require `Authorization: Bearer $AEGIS_API_KEY` whenever a key is configured; the examples below assume the key is exported as in [Run Aegis](#run-aegis). Interactive API docs are served at <http://localhost:8000/docs> (with ReDoc at <http://localhost:8000/redoc>).

### Control plane

```bash
# Liveness and current state
curl http://localhost:8000/healthz
curl http://localhost:8000/api/overview

# Force one engine evaluation
curl -X POST http://localhost:8000/api/engine/run-once \
  -H "Authorization: Bearer $AEGIS_API_KEY"

# Inspect incidents (filters: status, severity, search, page, limit)
curl http://localhost:8000/api/incidents
curl http://localhost:8000/api/incidents/<incident-id>
curl 'http://localhost:8000/api/incidents/export?format=csv'

# Trigger investigation manually
curl -X POST http://localhost:8000/api/incidents/<incident-id>/investigate \
  -H "Authorization: Bearer $AEGIS_API_KEY"

# The UI normally performs these two calls after investigation
curl -X POST http://localhost:8000/api/incidents/<incident-id>/approve \
  -H "Authorization: Bearer $AEGIS_API_KEY" \
  -H 'content-type: application/json' -d '{"approver":"demo-operator"}'
curl -X POST http://localhost:8000/api/incidents/<incident-id>/execute \
  -H "Authorization: Bearer $AEGIS_API_KEY" \
  -H 'content-type: application/json' -d '{"approver":"demo-operator"}'
```

Other control-plane routes:
- `POST /api/incidents/batch/approve` (requires key): Batch-approve all incidents in `recommendation_pending`.
- `POST /api/chaos` (requires key): Inject bounded faults into demo services (`service`, `fault`, `duration_seconds`, `intensity`).
- `GET /api/audit` (requires key): Recent audit trail entries (`?limit=50`).
- `GET /api/metrics`: Current Prometheus metric snapshot for checkout/inventory.
- `GET /api/logs`: Recent structured JSON logs (`?service=checkout|inventory&limit=40`).
- `GET /api/runbooks`: Available incident runbooks from `runbooks/`.

The control plane rate-limits each client (default 100 requests per 60 seconds; configurable via `AEGIS_RATE_LIMIT_MAX` and `AEGIS_RATE_LIMIT_WINDOW`).

### Demo services (Checkout & Inventory)

Each demo service also exposes its own application and admin endpoints:

- `GET /healthz` — Service liveness check.
- `GET /metrics` — Prometheus metrics scrape target.
- `GET /api/checkout` (Checkout: port 8080) — Process an order and call the inventory dependency.
- `GET /api/inventory` (Inventory: port 8081) — Check inventory availability for the demo SKU.
- `GET /admin/faults` (requires key) — View currently active faults on the service.
- `POST /admin/faults` (requires key) — Direct fault injection (`fault`, `duration_seconds`, `intensity`).
- `POST /admin/faults/clear` (requires key) — Clear active faults (`{"fault": "<fault_name>"}` or empty for all).
- `POST /admin/scale` (requires key) — Set simulated replica gauge (`{"replicas": 1..3}`).

## Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
ruff check aegis tests scripts
mypy aegis --ignore-missing-imports
```

`make test`, `make test-cov`, `make lint`, `make format`, and `make typecheck` wrap the same tools; CI (`.github/workflows/tests.yml`) runs lint, type-check, and the test suite across Python 3.11–3.13.

To run the services locally without Docker:

```bash
# Terminal 1: inventory service
SERVICE_NAME=inventory PORT=8081 python3 -m aegis.service_main

# Terminal 2: checkout service (points to inventory on 8081)
PORT=8080 DEPENDENCY_URL=http://localhost:8081 python3 -m aegis.service_main

# Terminal 3: control plane (listens on default PORT 8000)
python3 -m aegis.control_main
```

Each service and control-plane process listens on `PORT` (default 8000). The control plane reads `PROMETHEUS_URL` (default `http://localhost:9090`), `LOKI_URL` (default `http://localhost:3100`), `CHECKOUT_URL` (default `http://localhost:8080`), `INVENTORY_URL` (default `http://localhost:8081`), `AEGIS_DB_PATH` (default `./data/aegis.db`), `AEGIS_LOG_DIR` (default `./logs`), `AEGIS_RUNBOOK_DIR` (default `./runbooks`), `AEGIS_POLL_SECONDS` (default `5`), `AEGIS_RESOLUTION_CYCLES` (default `2`), `AEGIS_MAX_EVIDENCE` (default `100`), `OPENAI_MODEL` (default `gpt-4.1-mini`), and `AEGIS_API_KEY`; see `aegis/settings.py`. If you reuse the Compose Prometheus, it is published on host port 9091, so set `PROMETHEUS_URL=http://localhost:9091`.

## Safety model and design decisions

1. The agent is a copilot, not a captain. Recommendations are auditable proposals; execution requires a named approver and a second API call.
2. Correlation is explicit. Alert rules provide a root-cause key, and dependency evidence can rewrite checkout symptoms to `dependency:inventory`.
3. Evidence is first-class. Every investigation stores the metrics query/value, log observations, runbook excerpt, and tool names used.
4. The fallback investigator is intentional. A demo should work in a clean environment, while the LLM path is a replaceable reasoning layer rather than a hidden dependency.
5. The chaos surface is bounded. It can stress only this demo's own process and service state; there is no arbitrary command or infrastructure mutation API.

## Troubleshooting

### `python: command not found`

Activate the project environment:

```bash
source .venv/bin/activate
```

Or call its interpreter directly:

```bash
.venv/bin/python scripts/smoke.py --count 100
```

### Choose a Grafana port

```bash
GRAFANA_PORT=3002 make start
```

### Inspect or stop the stack

```bash
docker compose logs -f control checkout inventory
make down
```

## Current scope

This repository provides dashboard and API-based incident visibility. Email, Slack, PagerDuty, and mobile notifications are not included yet. The demo uses simulated faults and simulated scaling instead of changing real infrastructure.
