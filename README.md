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
- [Remediation safety](#remediation-safety)
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
- Checkout: <http://localhost:8080> (or the next free port if 8080 is occupied)
- Inventory: <http://localhost:8081>

On macOS, you can also double-click [`start.command`](start.command) to run the same startup
flow. To start the stack without opening browser tabs, use `OPEN_BROWSER=0 make start`.

If host port 3001 is already in use, `make start` automatically selects the next available
Grafana port. You can also choose one explicitly without changing the other services:

```bash
GRAFANA_PORT=3002 make start
```

The checkout port (8080) is handled the same way: `make start` picks the next free port, or set
`CHECKOUT_PORT=8082 make start`.

A port that `make start` picks itself is saved to `.env` (as `CHECKOUT_PORT` / `GRAFANA_PORT`, next to
`AEGIS_API_KEY`), because `docker compose` reads that file too. A later plain `docker compose up`
therefore publishes the same ports instead of falling back to 8080 and failing while it is busy. Re-runs
are stable: the saved port is reused while it is free (or already published by this stack), otherwise
the next free port is chosen and the saved value is updated. Ports you pass explicitly are never
written. Ports used by the other services (8000, 8081, 9091, 3100) are never auto-picked.

Fault injection, approval, and execution are protected by a shared `AEGIS_API_KEY`. If none is set,
`make start` generates one and appends it to `.env`. Paste it into the control room's **API key**
box before using the action buttons; the key is kept in the browser's session storage. Without a
key, `/api/chaos` and the service admin routes return 503.

The control room is the recommended demo surface. If you want traffic before injecting a fault:

```bash
python3 scripts/smoke.py --count 100
```

`scripts/smoke.py` defaults to `--checkout-url http://localhost:$CHECKOUT_PORT` (8080 when unset) and `--count 20`.

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
# Liveness and readiness
curl http://localhost:8000/healthz
curl http://localhost:8000/readyz
# Current state
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

`execute` returns `status` `executed`, `already_executed` (this approval already ran; nothing was called) or `dry_run`, plus the `idempotency_key`, `attempts` and initial `verification` state. It answers HTTP 409 when refused (not approved, already executing, not permitted, target busy), 429 with `Retry-After` over the per-target limit, and 502 when the service did not accept the action.

`GET /readyz` returns HTTP 503 (`status: unavailable`) when the SQLite database cannot be queried, the incident-engine thread has stopped, or the engine is stalled (no successful cycle within the heartbeat limit; see [Engine supervision](#engine-supervision)). `checks.engine` says which (`ok`, `degraded`, `stalled`, `stopped`) and `checks.engine_reason` explains a non-ok state. Prometheus and Loki being down, or the engine failing cycles while its heartbeat is still fresh, only report `status: degraded` with HTTP 200, because Aegis can still serve and record incidents without them. Compose uses `/readyz` for the control plane and `/healthz` for the demo services.

Other control-plane routes:
- `POST /api/incidents/batch/approve` (requires key): Batch-approve all incidents in `recommendation_pending`.
- `POST /api/chaos` (requires key): Inject bounded faults into demo services (`service`, `fault`, `duration_seconds`, `intensity`).
- `GET /api/audit` (requires key): Recent audit trail entries (`?limit=50`).
- `GET /api/engine/status`: Engine heartbeat (last success, last error, consecutive failures, cycle counts) and the state of the Prometheus, Loki and LLM circuit breakers.
- `GET /metrics`: The control plane's own Prometheus metrics (not part of the OpenAPI schema; Compose Prometheus scrapes it as job `control`): `aegis_engine_cycle_seconds` (histogram), `aegis_engine_cycle_failures_total{reason}`, `aegis_engine_up`, `aegis_engine_consecutive_failures`, `aegis_engine_last_success_age_seconds`, `aegis_incidents_open`, `aegis_remediation_executions_total{result}`, `aegis_backend_errors_total{backend}` and `aegis_breaker_open{backend}`.
- `GET /api/metrics`: Current Prometheus metric snapshot for checkout/inventory.
- `GET /api/logs`: Recent structured JSON logs (`?service=checkout|inventory&limit=40`).
- `GET /api/runbooks`: Available incident runbooks from `runbooks/`.

The control plane rate-limits each client (default 100 requests per 60 seconds; configurable via `AEGIS_RATE_LIMIT_MAX` and `AEGIS_RATE_LIMIT_WINDOW`).

#### HTTP hardening

- **Failed-key lockout:** a client that presents a wrong bearer token `AEGIS_AUTH_FAIL_MAX` times (default 10) within `AEGIS_AUTH_FAIL_WINDOW` seconds (default 60) receives `429` with a `Retry-After` header on protected routes, even if it then sends the right key. Requests with no token are not counted. The counters are in memory and per process, keyed by the TCP peer address; behind a reverse proxy every client shares the proxy's address, so apply per-client limits at the proxy as well. The demo services' admin routes use the same lockout.
- **Request size:** bodies larger than `AEGIS_MAX_BODY_BYTES` (default 65536) are refused with `413`, whether declared by `Content-Length` or streamed. `approver` must be 2-80 plain characters (letters, digits, space, `. _ @ + -`), and request bodies reject unknown fields.
- **Security headers:** every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and a `Content-Security-Policy` (`default-src 'self'`, no external origins, inline handlers only via `script-src-attr`; `/docs` and `/redoc` get a relaxed policy so Swagger UI can load from jsDelivr; the demo services send `default-src 'none'`). `Strict-Transport-Security` is added when the request arrived over HTTPS, so terminate TLS in front of Aegis for anything beyond localhost.
- **CORS:** disabled by default, so browsers only allow same-origin use (the bundled control room needs nothing). To let another web origin call the API, set `AEGIS_CORS_ORIGINS` to a comma-separated list of origins such as `https://ops.example.com,http://localhost:3000`. Wildcards and paths are rejected, credentials are never allowed, and only `GET`/`POST` with the `Authorization`, `Content-Type` and `X-Request-Id` headers are permitted.
- **Startup checks:** invalid configuration (a non-integer or out-of-range number, a malformed URL or port, a bad CORS origin) stops the process at startup with a message listing every problem, instead of silently falling back to a default. When `AEGIS_API_KEY` is unset the demo still runs, but a `SECURITY WARNING` is logged on every start: approve, execute, investigate and audit routes are then open to anyone who can reach the port. Always set a key for a shared or production deployment.

### Demo services (Checkout & Inventory)

Each demo service also exposes its own application and admin endpoints:

- `GET /healthz` — Service liveness check (no dependencies, always cheap).
- `GET /readyz` — Readiness: `checks.dependency` reports whether the `DEPENDENCY_URL` service answers (`ok`/`unavailable`). A down dependency yields `status: degraded` but still HTTP 200.
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

Each service and control-plane process listens on `PORT` (default 8000) on `AEGIS_HOST` (default `0.0.0.0`; use `127.0.0.1` when running locally outside a container). The control plane reads `PROMETHEUS_URL` (default `http://localhost:9090`), `LOKI_URL` (default `http://localhost:3100`), `CHECKOUT_URL` (default `http://localhost:8080`), `INVENTORY_URL` (default `http://localhost:8081`), `AEGIS_DB_PATH` (default `./data/aegis.db`), `AEGIS_LOG_DIR` (default `./logs`), `AEGIS_RUNBOOK_DIR` (default `./runbooks`), `AEGIS_POLL_SECONDS` (default `5`), `AEGIS_RESOLUTION_CYCLES` (default `2`), `AEGIS_DETECTION_CYCLES` (default `2`), `AEGIS_BLIND_SECONDS` (default `300`, seconds; `0` disables the telemetry-blind incident), `AEGIS_REOPEN_COOLDOWN_SECONDS` (default `300`, seconds; `0` always opens a new incident), `AEGIS_MAX_EVIDENCE` (default `100`), `AEGIS_SIGNAL_EVENT_INTERVAL` (default `60`, seconds; `0` records every poll), `AEGIS_CYCLE_TIMEOUT_SECONDS` (default `60`), `AEGIS_ENGINE_STALE_INTERVALS` (default `3`), `AEGIS_ENGINE_MAX_BACKOFF_SECONDS` (default `60`), `AEGIS_SHUTDOWN_GRACE_SECONDS` (default `10`, at most `15`; see [Engine supervision](#engine-supervision)), `OPENAI_MODEL` (default `gpt-4.1-mini`), `AEGIS_API_KEY`, `AEGIS_RATE_LIMIT_MAX` (default `100`), `AEGIS_RATE_LIMIT_WINDOW` (default `60`), `AEGIS_AUTH_FAIL_MAX` (default `10`), `AEGIS_AUTH_FAIL_WINDOW` (default `60`), `AEGIS_MAX_BODY_BYTES` (default `65536`), `AEGIS_CORS_ORIGINS` (default empty, same-origin only), and the `AEGIS_REMEDIATION_*` settings (dry run, attempts, backoff, timeout, rate limit, verification window and allowlist) described under [Remediation safety](#remediation-safety); see `aegis/settings.py` and [HTTP hardening](#http-hardening). Malformed values abort startup with an error naming the variable. If you reuse the Compose Prometheus, it is published on host port 9091, so set `PROMETHEUS_URL=http://localhost:9091`.

## Reliability

The engine is built to keep running when its dependencies do not.

- **Timeouts and retries.** Prometheus queries use a 1 s connect and 3 s read timeout. They are idempotent reads, so transport errors and HTTP 429/502/503/504 are retried up to 3 attempts in total, with 0.25 s then 0.5 s backoff. After a query exhausts its retries, further Prometheus queries fail fast for 10 s instead of each waiting out the full retry budget. The services' admin API (remediation) uses a 2 s connect and a configurable read timeout (`AEGIS_REMEDIATION_TIMEOUT_SECONDS`, default 5) and is retried with exponential backoff; see [Remediation safety](#remediation-safety).
- **Circuit breakers.** Prometheus and Loki fail fast for 10 s after a failed call (Prometheus: after a query exhausts its retries), and the LLM is skipped for 60 s after 3 consecutive failures (local investigation is used meanwhile; `fallback_reason` says "circuit open"). After the cooldown one probe call decides whether the breaker closes. Breaker states are shown in `/api/engine/status`, the Settings view and `aegis_breaker_open`.
- **Outages do not close incidents.** If a rule's Prometheus query fails, the engine skips it: the anomaly baseline is not updated, no healthy cycle is counted, and the incident gets one `telemetry_unavailable` event. Incidents only auto-resolve after consecutive successful, below-threshold readings.
- **No flapping.** A rule must breach for `AEGIS_DETECTION_CYCLES` consecutive cycles (default 2) before an incident opens, and an open incident resolves only after `AEGIS_RESOLUTION_CYCLES` consecutive healthy cycles, so a value oscillating around its threshold neither opens nor closes anything. A cycle where the signal cannot be read breaks the breach streak.
- **Empty is not healthy.** An empty Prometheus result counts as healthy only while the checkout target answers scrapes (the `checkout_down` rule, which needs a scrape job named `checkout` as in `observability/prometheus.yml`); otherwise the signal is "unavailable" and, like an error, never resolves an incident. A checkout target that stops answering scrapes opens a `service:checkout` incident. If any signal stays unavailable for `AEGIS_BLIND_SECONDS` (default 300), one `telemetry:blind` incident lists the blind rules; it skips the investigator and resolves when the signals return. `IncidentEngine.signal_states` holds each rule's latest state (`ok`, `breaching`, `unavailable`).
- **One incident per root cause.** Evaluation cycles are serialised, so concurrent or manual runs cannot open duplicates, and correlation reads the database, so restarts cannot either. Checkout symptoms stay attached to an open `dependency:inventory` incident until the dependency errors fall to half the threshold. A root cause that returns within `AEGIS_REOPEN_COOLDOWN_SECONDS` (default 300) of resolving reopens that incident (a `reopened` event) instead of opening a new one; `closed` incidents are never reopened.
- **Anomaly scores stay sane.** The z-score detector needs at least 2 (default 5) samples, ignores NaN, infinite and absurdly large values, treats float noise on a flat baseline as no change, and stores an outlier at the threshold rather than its full size so one huge spike cannot mask the next real one.
- **One failure does not stop the loop.** Each rule is evaluated independently; engine errors are logged (with traceback) and the next cycle runs after `AEGIS_POLL_SECONDS` (minimum 1 s). A crashed investigation records an `agent_error` event and returns the incident to `open`. Incidents left in `investigating` by a restart are investigated again at startup.
- **Bounded LLM investigator.** With `OPENAI_API_KEY` set, each request times out after 20 s (one SDK retry), the whole investigation has a 60 s budget, at most 6 tool rounds with 8 tool calls each, tool results are cut to 8,000 characters and the whole prompt to 60,000. Any breach, malformed answer, or recommendation outside the remediation allowlist falls back to the local investigator, and the reason is stored as `fallback_reason`. Tool errors are returned to the model rather than aborting.
- **Quiet timelines.** The engine appends evidence on every poll, but an open incident's timeline gets a "Signal still active" event only when a rule starts firing for that incident or at most once per `AEGIS_SIGNAL_EVENT_INTERVAL` seconds (default 60) per rule, so a long incident does not add two events every 5 s poll. The evidence history (bounded by `AEGIS_MAX_EVIDENCE`) is unaffected.
- **No lost updates.** Investigation results, approvals and remediation results are merged into the incident under the store lock, so evidence appended while they run is kept, and two concurrent approvals cannot both succeed (the second gets HTTP 409).
- **Remediation failures are explicit.** A failed Execute records a `remediation_failed` event that says whether the target may have applied the request (for example after a read timeout), then returns the incident to `approved` so an operator can check and retry.

These limits are constants in `aegis/telemetry.py`, `aegis/agent.py` and `aegis/remediation.py`.

## Remediation safety

Executing a fix is the one place Aegis changes state, so it is guarded in layers. All settings below are read by the control plane, validated at startup, and passed through Compose with the same defaults.

- **At most once per approval.** Each approval has an idempotency key (a hash of the incident, the approval time and the approved recommendation). The key is stored in the `remediation_executions` table *before* the service is called, and its outcome is recorded afterwards. Pressing Execute twice, a client retry or two concurrent requests call the service once; a repeat after success returns HTTP 200 with `status: already_executed` and the recorded result. A new approval is a new key. The table is created with `CREATE TABLE IF NOT EXISTS`, so an existing database upgrades in place on the next start.
- **Restart mid-execution.** On startup an execution that was in flight becomes `unknown` and the incident returns to `approved`; one whose success was recorded but not applied to the incident is completed. Execute on an `unknown` attempt does not blindly repeat it: if the triggering signal has cleared it is recorded as applied, if the signal still fires one new attempt is made, and if Prometheus cannot be read the request is refused until it can.
- **Retries and timeouts.** The admin call is retried up to `AEGIS_REMEDIATION_MAX_ATTEMPTS` times (default 3, at most 10) with exponential backoff starting at `AEGIS_REMEDIATION_BACKOFF_MS` (default 500, capped at 10 s) for connection errors, timeouts and HTTP 5xx. A 4xx rejection is never retried. This is safe because both actions are declarative on the service (clear this fault, scale to N). The read timeout is `AEGIS_REMEDIATION_TIMEOUT_SECONDS` (default 5).
- **Two different failures.** If the service never accepted the action the response is HTTP 502, the incident returns to `approved`, and the audit entry (`execute_failed`) lists every attempt and whether the action may have been applied. If the action succeeded but the problem persists, the response was HTTP 200 and the verification below escalates it.
- **Verification.** After a successful action Aegis re-reads the alert rules that fired for the incident every `AEGIS_REMEDIATION_VERIFY_INTERVAL` seconds (default 5) for up to `AEGIS_REMEDIATION_VERIFY_SECONDS` (default 180, longer than the 2 m rate windows in the alert queries; `0` turns verification off). When every signal has been below its threshold for `AEGIS_RESOLUTION_CYCLES` consecutive checks the remediation is `verified` (`remediation_verified` event). If the window ends with the signal still firing (`failed`) or unreadable (`unverified`), the incident is raised to `critical` and gets a `remediation_escalated` event. The incident status stays `open` throughout, so it auto-resolves as usual when the signal clears and can be re-investigated; the outcome lives in `data.remediation.verification` and is shown as a badge in the UI. A restart resumes verifications that were still running.
- **Guardrails.** `AEGIS_REMEDIATION_ALLOWED_ACTIONS` (default all four of `checkout:clear_fault,checkout:scale_simulation,inventory:clear_fault,inventory:scale_simulation`) is a per-target action allowlist, enforced at approval and again at execution; faults are additionally limited per target and scale is an integer from 1 to 3 (booleans and fractions are rejected). At most one execution may be in flight per target, and at most `AEGIS_REMEDIATION_MAX_PER_WINDOW` (default 5) executions per target per `AEGIS_REMEDIATION_WINDOW_SECONDS` (default 300) are allowed; beyond that Execute returns HTTP 429 with `Retry-After`. Attempts known not to have been applied do not count towards the limit.
- **Dry run.** With `AEGIS_REMEDIATION_DRY_RUN=true` Execute runs every check, records a `remediation_dry_run` event and returns `status: dry_run` with the endpoint and payload it would have called; nothing is sent and the incident stays `approved`.
- **Audit trail.** Every Execute outcome is an entry in `GET /api/audit` with the incident, approver, action, target, idempotency key and attempts: `execute`, `execute_replayed`, `execute_failed`, `execute_refused` (with a `reason`), `execute_dry_run`, plus `remediation_verified` and `remediation_escalated`. The audit buffer is in memory (the last 1,000 entries); the durable record is the incident timeline and the `remediation_executions` table.

## Operations

### Containers

- The image runs as the unprivileged user `aegis` (uid 10001), installs runtime dependencies only, and has a built-in `HEALTHCHECK` on `/healthz`.
- Compose runs the Aegis containers with a read-only root filesystem (`/tmp` is a tmpfs), all Linux capabilities dropped, `no-new-privileges`, an init process, rotated container logs (10 MB x 3), and `restart: unless-stopped`. Checkout waits for a healthy inventory; the control plane waits for all of its dependencies.
- Compose passes `AEGIS_CORS_ORIGINS`, `AEGIS_AUTH_FAIL_MAX`, `AEGIS_AUTH_FAIL_WINDOW` and `AEGIS_MAX_BODY_BYTES` to all three Aegis containers and `AEGIS_SIGNAL_EVENT_INTERVAL`, `AEGIS_DETECTION_CYCLES`, `AEGIS_BLIND_SECONDS`, `AEGIS_REOPEN_COOLDOWN_SECONDS`, `AEGIS_CYCLE_TIMEOUT_SECONDS`, `AEGIS_ENGINE_STALE_INTERVALS`, `AEGIS_ENGINE_MAX_BACKOFF_SECONDS` and `AEGIS_SHUTDOWN_GRACE_SECONDS` plus the `AEGIS_REMEDIATION_*` settings to the control plane, each with the default from `aegis/settings.py`; set them in the shell or `.env`.
- Third-party images are pinned to explicit versions in `docker-compose.yml`; bump them deliberately.
- Upgrading an existing stack: volumes created by an earlier (root) image are not writable by uid 10001. Fix ownership once:

  ```bash
  docker compose run --rm --no-deps --user root --cap-add CHOWN control chown -R aegis:aegis /data /var/log/aegis
  ```

### Graceful shutdown

On `SIGTERM` (`docker compose stop`/`down`) uvicorn drains open requests for up to 10 s, then the control plane stops the incident engine: an in-flight evaluation cycle gets `AEGIS_SHUTDOWN_GRACE_SECONDS` (default 10) to finish and is then abandoned, in-flight investigations are awaited for the same window plus 5 s, and only then the database is closed (checkpointing the WAL). An incident left in `executing` by an abandoned or killed process is returned to `approved` at the next startup. Compose allows 30 s (`stop_grace_period`) before `SIGKILL`.

### Engine supervision

The engine loop cannot silently die or stall. Each evaluation cycle runs under a timeout (`AEGIS_CYCLE_TIMEOUT_SECONDS`, default 60); a cycle that raises or overruns is logged and counted as a failure, and the loop carries on. A cycle that overran is abandoned, and no new cycle starts until it ends, so two cycles never run at once. After consecutive failures the pause between cycles doubles each time, from `AEGIS_POLL_SECONDS` up to `AEGIS_ENGINE_MAX_BACKOFF_SECONDS` (default 60), and returns to the poll interval after one success.

The heartbeat is the time of the last successful cycle. The engine is `degraded` while cycles are failing, and `stalled` (readiness 503) when there has been no success for `AEGIS_ENGINE_STALE_INTERVALS` poll intervals plus one cycle timeout (default 3 x 5 s + 60 s = 75 s). The top-bar engine pill and the Settings view show the state, the reason, the last error and the breakers.

### Database and backups

Incident history lives in SQLite at `AEGIS_DB_PATH` (Compose: the `aegis-data` volume at `/data`). It runs in WAL mode with `synchronous=NORMAL` and a 10 s busy timeout, so reads do not block the engine and brief lock contention is retried instead of failing.

Back it up while the stack is running (do not copy the `.db` file by hand: with WAL it is incomplete without its `-wal` file):

```bash
make backup    # writes ./backups/aegis-<UTC timestamp>.db, integrity-checked
```

This uses SQLite's online backup API via `python -m aegis.backup_main [DEST]` (default destination: `backups/aegis-<timestamp>.db` next to `AEGIS_DB_PATH`; an existing file is never overwritten). Outside Docker, run the same command with `AEGIS_DB_PATH` set, or use `sqlite3 aegis.db ".backup 'copy.db'"`.

Restore by stopping the control plane, replacing the database, and starting it again:

```bash
docker compose stop control
docker compose run --rm --no-deps -v "$PWD/backups:/restore:ro" control sh -c \
  'rm -f /data/aegis.db-wal /data/aegis.db-shm && cp /restore/aegis-<timestamp>.db /data/aegis.db'
docker compose start control
```

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

An explicit port is used as given and is not saved to `.env`; automatically chosen ports are (see [Run Aegis](#run-aegis)).

### Inspect or stop the stack

```bash
docker compose logs -f control checkout inventory
make down
```

## Current scope

This repository provides dashboard and API-based incident visibility. Email, Slack, PagerDuty, and mobile notifications are not included yet. The demo uses simulated faults and simulated scaling instead of changing real infrastructure.
