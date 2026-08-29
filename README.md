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

Requirements: Docker Desktop or another Docker Engine with Compose.

If your Docker context is Colima on macOS, `make start` automatically starts Colima when it is
stopped. You can disable that behavior with `AUTO_START_DOCKER=0 make start`.

```bash
cp .env.example .env
make start
```

`make start` builds and starts every container in the background, waits for the control room,
and opens the local pages automatically:

- Aegis control room: <http://localhost:8000>
- Grafana: <http://localhost:3001> (or `3002` if 3001 is occupied)
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

The control room is the recommended demo surface. If you want traffic before injecting a fault:

```bash
python3 scripts/smoke.py --count 100
```

Or inject a failure from a terminal:

```bash
python3 scripts/chaos.py --service inventory --fault dependency --duration 60
```

Wait for the incident engine to detect the failure. The expected flow is:

1. `inventory_dependency_errors`, checkout 5xx rate, and possibly checkout p95 latency rise.
2. The engine correlates those signals under `dependency:inventory`.
3. Aegis collects Prometheus values, recent JSON logs, the inventory runbook, and its own timeline.
4. The incident moves to `recommendation_pending` with a proposed `clear_fault` action.
5. Click **Approve recommendation**, then **Execute approved fix**.
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

```bash
# Health and current state
curl http://localhost:8000/api/overview

# Force one engine evaluation
curl -X POST http://localhost:8000/api/engine/run-once

# Inspect an incident
curl http://localhost:8000/api/incidents
curl http://localhost:8000/api/incidents/<incident-id>

# The UI normally performs these two calls after investigation
curl -X POST http://localhost:8000/api/incidents/<incident-id>/approve \
  -H 'content-type: application/json' -d '{"approver":"demo-operator"}'
curl -X POST http://localhost:8000/api/incidents/<incident-id>/execute \
  -H 'content-type: application/json' -d '{"approver":"demo-operator"}'
```

## Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
ruff check aegis tests scripts
```

Run a service locally with `SERVICE_NAME=inventory python3 -m aegis.service_main` or run the control plane with `python3 -m aegis.control_main`. For local Python processes, use `.env.example` values and make sure Prometheus is available at `localhost:9090`.

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
