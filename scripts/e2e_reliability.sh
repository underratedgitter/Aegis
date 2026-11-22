#!/usr/bin/env bash
# End-to-end fault-injection proof of Aegis' reliability behaviour.
#
# Builds a SEPARATE Docker Compose project from this checkout, injects real faults and checks
# what the control plane does about them. It never touches another Compose project: the
# project name must differ from "aegis", every host port is remapped, and teardown only
# targets that project.
#
# Usage:   scripts/e2e_reliability.sh            (or: make e2e-reliability)
# Env:     E2E_PROJECT        Compose project name            (default aegis-rel)
#          E2E_PORT_BASE      first of 6 consecutive host ports (default 8140)
#          E2E_API_KEY        admin key for the project; random when unset (never printed)
#          E2E_SCENARIOS      space separated subset of "1 2 3 4 5 6 7" (default all)
#          E2E_KEEP=1         leave the project running afterwards (default: down -v)
#          E2E_SKIP_UP=1      use an already running project instead of building one
#          E2E_POLL_SECONDS, E2E_DETECTION_CYCLES, E2E_RESOLUTION_CYCLES, E2E_BLIND_SECONDS,
#          E2E_VERIFY_SECONDS tune speed
# Needs:   docker compose v2.24+, curl, jq. Exits non-zero when any check fails.
set -uo pipefail
cd "$(dirname "$0")/.."

PROJECT="${E2E_PROJECT:-aegis-rel}"
BASE="${E2E_PORT_BASE:-8140}"
SCENARIOS="${E2E_SCENARIOS:-1 2 3 4 5 6 7}"
POLL="${E2E_POLL_SECONDS:-2}"
K="${E2E_DETECTION_CYCLES:-3}"
BLIND="${E2E_BLIND_SECONDS:-15}"
VERIFY="${E2E_VERIFY_SECONDS:-300}"
# Long enough that an incident whose signals just cleared has not yet resolved when Prometheus is stopped.
RESOLVE="${E2E_RESOLUTION_CYCLES:-8}"

if [[ "$PROJECT" == "aegis" || "$PROJECT" == societyos* ]]; then
  echo "refusing to run against project '$PROJECT': use a dedicated project name" >&2
  exit 2
fi
for tool in docker curl jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 2; }
done

CONTROL_PORT=$BASE
CHECKOUT_PORT=$((BASE + 1))
INVENTORY_PORT=$((BASE + 2))
PROM_PORT=$((BASE + 3))
LOKI_PORT=$((BASE + 4))
GRAFANA_PORT_E2E=$((BASE + 5))
CONTROL="http://127.0.0.1:$CONTROL_PORT"
CHECKOUT="http://127.0.0.1:$CHECKOUT_PORT"
INVENTORY="http://127.0.0.1:$INVENTORY_PORT"
KEY="${E2E_API_KEY:-$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 32)}"

WORK="$(mktemp -d)"
EMPTY_ENV="$WORK/empty.env"
OVERRIDE="$WORK/override.yml"
BASELINE="$WORK/baseline.json"
: >"$EMPTY_ENV"
echo '[]' >"$BASELINE"

# An explicit empty env file keeps Compose from reading a developer's .env.
# The shipped CPU quotas (0.25 for the demo services) throttle them enough on a busy Docker
# host that healthy checkout p95 latency crosses its 0.75 s threshold, which would drown the
# faults injected here in false incidents, so the test project gets one full CPU each.
cat >"$OVERRIDE" <<EOF
services:
  control:
    deploy:
      resources:
        limits:
          cpus: "1.0"
    ports: !override
      - "127.0.0.1:$CONTROL_PORT:8000"
    environment:
      AEGIS_POLL_SECONDS: "$POLL"
      AEGIS_DETECTION_CYCLES: "$K"
      AEGIS_RESOLUTION_CYCLES: "$RESOLVE"
      AEGIS_BLIND_SECONDS: "$BLIND"
      AEGIS_REOPEN_COOLDOWN_SECONDS: "0"
      AEGIS_SIGNAL_EVENT_INTERVAL: "5"
      AEGIS_REMEDIATION_VERIFY_SECONDS: "$VERIFY"
      AEGIS_REMEDIATION_VERIFY_INTERVAL: "3"
      AEGIS_RATE_LIMIT_MAX: "100000"
  checkout:
    deploy:
      resources:
        limits:
          cpus: "1.0"
    ports: !override
      - "127.0.0.1:$CHECKOUT_PORT:8000"
  inventory:
    deploy:
      resources:
        limits:
          cpus: "1.0"
    ports: !override
      - "127.0.0.1:$INVENTORY_PORT:8000"
  prometheus:
    deploy:
      resources:
        limits:
          cpus: "1.0"
    ports: !override
      - "127.0.0.1:$PROM_PORT:9090"
  loki:
    ports: !override
      - "127.0.0.1:$LOKI_PORT:3100"
  grafana:
    ports: !override
      - "127.0.0.1:$GRAFANA_PORT_E2E:3000"
EOF

dc() {
  AEGIS_API_KEY="$KEY" docker compose -p "$PROJECT" --env-file "$EMPTY_ENV" \
    -f docker-compose.yml -f "$OVERRIDE" "$@"
}

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
FAILED=0
RESULTS=()
pass() { RESULTS+=("PASS  $1"); log "PASS  $1${2:+  -- $2}"; }
fail() { RESULTS+=("FAIL  $1"); FAILED=1; log "FAIL  $1${2:+  -- $2}"; }
check() { if [[ "$3" == 0 ]]; then pass "$1" "$2"; else fail "$1" "$2"; fi; }
# ok CMD...: prints 0 when the command succeeds and 1 otherwise, for use as check's third argument.
ok() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }

wait_for() {
  local limit="$1" end
  shift
  end=$((SECONDS + limit))
  while ((SECONDS < end)); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

# --- API helpers -------------------------------------------------------------------------

api() { # METHOD PATH [JSON]  ->  API_BODY, API_CODE
  local out
  if [[ $# -ge 3 ]]; then
    out="$(curl -sS -m 40 -X "$1" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
      -d "$3" -w '\n%{http_code}' "$CONTROL$2" 2>/dev/null)"
  else
    out="$(curl -sS -m 40 -X "$1" -H "Authorization: Bearer $KEY" -w '\n%{http_code}' "$CONTROL$2" 2>/dev/null)"
  fi
  API_CODE="${out##*$'\n'}"
  API_BODY="${out%$'\n'*}"
}
get() { curl -sS -m 10 "$CONTROL$1" 2>/dev/null; }
inc() { get "/api/incidents/$1"; }
incf() { inc "$1" | jq -r "$2" 2>/dev/null; }
service_admin() { # URL PATH JSON
  curl -sS -m 10 -X POST -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "$3" "$1$2" >/dev/null 2>&1
}
clear_faults() {
  service_admin "$CHECKOUT" /admin/faults/clear '{}'
  service_admin "$INVENTORY" /admin/faults/clear '{}'
}
chaos() { api POST /api/chaos "{\"service\":\"$1\",\"fault\":\"$2\",\"duration_seconds\":900,\"intensity\":${3:-2}}"; }

engine_state() { get /api/engine/status | jq -r .state; }
engine_is() { [[ "$(engine_state)" == "$1" ]]; }
breaker_state() { get /api/engine/status | jq -r ".breakers.$1.state"; }
breaker_not_closed() { [[ "$(breaker_state "$1")" != closed ]]; }
breaker_closed() { [[ "$(breaker_state "$1")" == closed ]]; }
cycles() { get /api/engine/status | jq -r .cycles_total; }
control_ready() { [[ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$CONTROL/healthz")" == 200 ]]; }
all_signals_ok() { [[ "$(get /api/engine/status | jq '[.signals[] | select(. != "ok")] | length')" == 0 ]]; }
any_signal_unavailable() { [[ "$(get /api/engine/status | jq '[.signals[] | select(. == "unavailable")] | length')" -gt 0 ]]; }

snapshot() { get "/api/incidents?limit=200" | jq '[.incidents[].id]' >"$BASELINE"; }
new_ids() { # [ROOT] -> ids of incidents created since the snapshot, optionally with that root
  get "/api/incidents?limit=200" | jq -r --arg r "${1:-}" --slurpfile b "$BASELINE" \
    '.incidents[] | select($r == "" or .root_cause_key == $r) | select(.id as $i | ($b[0] | index($i)) | not) | .id'
}
first_new() { new_ids "${1:-}" | head -1; }
has_new() { [[ -n "$(new_ids "${1:-}")" ]]; }
count_new() { new_ids "${1:-}" | grep -c . || true; }
active_count() { get "/api/incidents?limit=200" | jq '[.incidents[] | select(.status != "resolved" and .status != "closed")] | length'; }
none_active() { [[ "$(active_count)" == 0 ]]; }
status_is() { [[ "$(incf "$1" .status)" == "$2" ]]; }
status_not() { [[ "$(incf "$1" .status)" != "$2" ]]; }
has_recommendation() { [[ "$(incf "$1" '.data.recommendation.action // "none"')" != none && "$(incf "$1" .status)" == recommendation_pending ]]; }
verification_state() { incf "$1" '.data.remediation.verification.state // "none"'; }
verification_is() { [[ "$(verification_state "$1")" == "$2" ]]; }
event_count() { incf "$1" "[.events[] | select(.kind == \"$2\")] | length"; }
cleared_count() { dc logs --no-log-prefix checkout inventory 2>&1 | grep -c faults_cleared || true; }
sql() { dc exec -T control python -c "import sqlite3,sys;c=sqlite3.connect('/data/aegis.db');print(c.execute(sys.argv[1]).fetchone()[0])" "$1" 2>/dev/null; }

# Gentle on purpose: the services run with small CPU quotas and heavy load alone would raise latency signals.
traffic() { while true; do curl -s -m 5 -o /dev/null "$CHECKOUT/api/checkout"; sleep 0.4; done; }
POLLERS=()
start_traffic() {
  local _
  for _ in 1 2; do
    traffic &
    POLLERS+=($!)
  done
}
stop_background() {
  local pid
  for pid in "${POLLERS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
  POLLERS=()
}

# Healthy, quiet and snapshotted: every scenario starts here.
quiesce() {
  dc start prometheus loki checkout inventory >/dev/null 2>&1
  dc unpause checkout inventory >/dev/null 2>&1
  control_ready || dc start control >/dev/null 2>&1
  wait_for 120 control_ready
  clear_faults
  wait_for 120 engine_is ok || log "engine not ok before scenario: $(get /api/engine/status | jq -c '{state,reason}')"
  if ! wait_for 480 none_active; then
    log "incidents still active before scenario: $(get '/api/incidents?limit=200' | jq -c '[.incidents[] | select(.status != "resolved") | {id,root_cause_key,status}]')"
  fi
  snapshot
}

# Approve and execute an incident's recommendation through the API; an incident left waiting for
# an operator is never auto-resolved, so this is how a scenario finishes its incident. Sets REM_CODE.
remediate() {
  api POST "/api/incidents/$1/approve" '{"approver":"e2e-operator"}'
  REM_CODE="$API_CODE"
  [[ "$API_CODE" == 200 ]] || return 1
  api POST "/api/incidents/$1/execute" '{"approver":"e2e-operator"}'
  REM_CODE="$REM_CODE/$API_CODE"
  [[ "$API_CODE" == 200 ]]
}

# --- scenarios ---------------------------------------------------------------------------

s1_latency() {
  log "== 1. latency fault on checkout: one incident, investigated, fixed, verified, resolved"
  quiesce
  local before after inc clears_before f1 f2 f3 statuses
  before="$(cycles)"
  chaos checkout latency 2
  check "1.inject latency fault" "HTTP $API_CODE" "$([[ $API_CODE == 200 ]] && echo 0 || echo 1)"
  wait_for 120 has_new service:checkout
  after="$(cycles)"
  inc="$(first_new service:checkout)"
  check "1.incident opened only after K cycles" "cycles $before -> $after, K=$K" "$([[ -n $inc && $((after - before)) -ge $K ]] && echo 0 || echo 1)"
  sleep $((POLL * 5))
  check "1.exactly one incident for the fault" "new incidents: $(count_new)" "$([[ $(count_new) == 1 ]] && echo 0 || echo 1)"
  wait_for 90 has_recommendation "$inc"
  check "1.investigation produced a recommendation" "$(incf "$inc" '.data.recommendation | "\(.action) \(.target) \(.parameters.fault)"')" "$(ok has_recommendation "$inc")"
  check "1.recommendation clears the injected latency fault" "fault=$(incf "$inc" .data.recommendation.parameters.fault)" "$([[ "$(incf "$inc" .data.recommendation.parameters.fault)" == latency ]] && echo 0 || echo 1)"

  clears_before="$(cleared_count)"
  api POST "/api/incidents/$inc/approve" '{"approver":"e2e-operator"}'
  check "1.approve" "HTTP $API_CODE" "$([[ $API_CODE == 200 ]] && echo 0 || echo 1)"
  f1="$WORK/exec1"
  f2="$WORK/exec2"
  local pids=()
  for f in "$f1" "$f2"; do
    (curl -sS -m 40 -X POST -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
      -d '{"approver":"e2e-operator"}' -w '\n%{http_code}' "$CONTROL/api/incidents/$inc/execute" >"$f" 2>&1) &
    pids+=($!)
  done
  wait "${pids[@]}" 2>/dev/null
  api POST "/api/incidents/$inc/execute" '{"approver":"e2e-operator"}'
  f3="$(echo "$API_BODY" | jq -r .status 2>/dev/null)"
  statuses="$(for f in "$f1" "$f2"; do sed '$d' "$f" | jq -r '.status // .detail' 2>/dev/null; done | tr '\n' ',')"
  check "1.concurrent double execute: exactly one runs, a later one replays" "responses: ${statuses}third=$f3/$API_CODE" \
    "$([[ $(echo "$statuses" | tr ',' '\n' | grep -c '^executed$') == 1 && $f3 == already_executed ]] && echo 0 || echo 1)"
  sleep 2
  check "1.service called exactly once" "faults_cleared log lines: $(($(cleared_count) - clears_before))" "$([[ $(($(cleared_count) - clears_before)) == 1 ]] && echo 0 || echo 1)"
  check "1.one remediation_executed event" "count=$(event_count "$inc" remediation_executed)" "$([[ $(event_count "$inc" remediation_executed) == 1 ]] && echo 0 || echo 1)"
  wait_for "$((VERIFY + 60))" verification_is "$inc" verified
  check "1.verification verified" "state=$(verification_state "$inc")" "$(ok verification_is "$inc" verified)"
  wait_for 300 status_is "$inc" resolved
  check "1.incident auto-resolved" "status=$(incf "$inc" .status)" "$(ok status_is "$inc" resolved)"
}

s2_dependency() {
  log "== 2. dependency fault on inventory: one dependency incident, no split checkout incident"
  quiesce
  local inc
  chaos inventory dependency
  check "2.inject dependency fault" "HTTP $API_CODE" "$([[ $API_CODE == 200 ]] && echo 0 || echo 1)"
  wait_for 120 has_new dependency:inventory
  sleep $((POLL * 8 + 10))
  check "2.dependency:inventory incident exists" "count=$(count_new dependency:inventory)" "$([[ $(count_new dependency:inventory) == 1 ]] && echo 0 || echo 1)"
  check "2.no split service:checkout incident" "checkout incidents=$(count_new service:checkout), total=$(count_new)" \
    "$([[ $(count_new service:checkout) == 0 && $(count_new) == 1 ]] && echo 0 || echo 1)"
  inc="$(first_new dependency:inventory)"
  wait_for 90 has_recommendation "$inc"
  check "2.recommendation clears the inventory dependency fault" "$(incf "$inc" '.data.recommendation | "\(.action) \(.target) \(.parameters.fault)"')" \
    "$([[ "$(incf "$inc" '.data.recommendation | "\(.action) \(.target) \(.parameters.fault)"')" == "clear_fault inventory dependency" ]] && echo 0 || echo 1)"
  remediate "$inc"
  check "2.approve and execute" "HTTP $REM_CODE" "$([[ $REM_CODE == 200/200 ]] && echo 0 || echo 1)"
  wait_for 300 status_is "$inc" resolved
  check "2.resolves after the fix, still a single incident" "status=$(incf "$inc" .status), total=$(count_new)" \
    "$([[ $(incf "$inc" .status) == resolved && $(count_new) == 1 ]] && echo 0 || echo 1)"
}

s3_prometheus() {
  log "== 3. prometheus down mid-incident: degraded, breaker open, no auto-resolve, blind incident, recovery"
  quiesce
  local inc blind ready
  chaos checkout errors 1
  wait_for 120 has_new service:checkout
  inc="$(first_new service:checkout)"
  wait_for 90 has_recommendation "$inc"
  remediate "$inc"
  check "3.fix executed (incident goes back to open and starts counting healthy cycles)" "HTTP $REM_CODE status=$(incf "$inc" .status)" "$([[ $REM_CODE == 200/200 ]] && echo 0 || echo 1)"
  # Rates are averaged over 2 minutes, so the signal needs a while to clear. Stop prometheus as
  # soon as it has: the incident is then moments from resolving on the strength of fresh readings.
  wait_for 300 all_signals_ok
  log "signals clear; incident $inc is $(incf "$inc" .status); stopping prometheus"
  dc stop prometheus >/dev/null 2>&1
  wait_for 60 engine_is degraded
  check "3.engine reports degraded" "$(get /api/engine/status | jq -c '{state,reason}')" "$(ok engine_is degraded)"
  wait_for 30 breaker_not_closed prometheus
  check "3.prometheus breaker not closed" "breaker=$(breaker_state prometheus)" "$(ok breaker_not_closed prometheus)"
  check "3.signals reported unavailable" "$(get /api/engine/status | jq -c '.signals')" "$(ok any_signal_unavailable)"
  sleep $((POLL * RESOLVE + 10)) # long enough to have resolved had the outage looked healthy
  check "3.incident not auto-resolved while blind" "status=$(incf "$inc" .status) after $((POLL * RESOLVE + 10))s without telemetry" "$(ok status_not "$inc" resolved)"
  wait_for $((BLIND + 40)) has_new telemetry:blind
  blind="$(first_new telemetry:blind)"
  check "3.telemetry:blind incident after AEGIS_BLIND_SECONDS=$BLIND" "incident=${blind:-none} rules=$(incf "${blind:-x}" '.data.latest_evidence.blind_rules | join(",")')" "$([[ -n $blind ]] && echo 0 || echo 1)"
  check "3.blind incident offers no remediation" "status=$(incf "${blind:-x}" .status), recommendation=$(incf "${blind:-x}" '.data.recommendation // "none"')" \
    "$([[ -n $blind && $(incf "$blind" '.data.recommendation // "none"') == none && $(incf "$blind" .status) == open ]] && echo 0 || echo 1)"
  if [[ -n "$blind" ]]; then
    api POST "/api/incidents/$blind/approve" '{"approver":"e2e-operator"}'
    check "3.blind incident cannot be approved" "HTTP $API_CODE" "$([[ $API_CODE == 409 ]] && echo 0 || echo 1)"
  fi
  ready="$(curl -s -m 10 -o "$WORK/ready.json" -w '%{http_code}' "$CONTROL/readyz")"
  check "3./readyz stays 200 but reports degraded" "HTTP $ready $(jq -c '{status,checks}' "$WORK/ready.json")" \
    "$([[ $ready == 200 && $(jq -r .status "$WORK/ready.json") == degraded ]] && echo 0 || echo 1)"
  log "starting prometheus"
  dc start prometheus >/dev/null 2>&1
  wait_for 120 engine_is ok
  check "3.engine ok again after prometheus returns" "$(get /api/engine/status | jq -c '{state,reason}')" "$(ok engine_is ok)"
  wait_for 60 breaker_closed prometheus
  check "3.breaker closed again" "breaker=$(breaker_state prometheus)" "$(ok breaker_closed prometheus)"
  wait_for $((VERIFY + 60)) verification_is "$inc" verified
  check "3.verification resumed once telemetry returned" "state=$(verification_state "$inc")" "$(ok verification_is "$inc" verified)"
  wait_for 300 status_is "$inc" resolved
  check "3.original incident resolves after recovery" "status=$(incf "$inc" .status)" "$(ok status_is "$inc" resolved)"
  if [[ -n "$blind" ]]; then wait_for 120 status_is "$blind" resolved; fi
  check "3.blind incident resolves after recovery" "status=$(incf "${blind:-x}" .status)" "$([[ -n $blind ]] && ok status_is "$blind" resolved || echo 1)"
}

s4_loki() {
  log "== 4. loki down: investigations still complete, engine stays up"
  quiesce
  local inc ready c1
  dc stop loki >/dev/null 2>&1
  chaos checkout cpu 1
  wait_for 120 has_new service:checkout:cpu
  inc="$(first_new service:checkout:cpu)"
  wait_for 120 has_recommendation "$inc"
  check "4.investigation completes without loki" "status=$(incf "$inc" .status), mode=$(incf "$inc" .data.investigation.mode)" "$(ok has_recommendation "$inc")"
  check "4.engine not stalled or stopped" "state=$(engine_state)" "$([[ $(engine_state) == ok || $(engine_state) == degraded ]] && echo 0 || echo 1)"
  c1="$(cycles)"
  sleep $((POLL * 3))
  check "4.engine loop still cycling" "cycles $c1 -> $(cycles)" "$([[ $(cycles) -gt $c1 ]] && echo 0 || echo 1)"
  ready="$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$CONTROL/readyz")"
  check "4./readyz 200 with loki down" "HTTP $ready" "$([[ $ready == 200 ]] && echo 0 || echo 1)"
  dc start loki >/dev/null 2>&1
  remediate "$inc"
  check "4.approve and execute" "HTTP $REM_CODE" "$([[ $REM_CODE == 200/200 ]] && echo 0 || echo 1)"
  wait_for 300 status_is "$inc" resolved
  check "4.incident resolves after the fix" "status=$(incf "$inc" .status)" "$(ok status_is "$inc" resolved)"
}

s5_restart() {
  log "== 5. control restarted mid-execution and mid-verification: no duplicate, verification resumes"
  quiesce
  local inc inflight
  chaos inventory dependency
  wait_for 120 has_new dependency:inventory
  inc="$(first_new dependency:inventory)"
  wait_for 90 has_recommendation "$inc"
  api POST "/api/incidents/$inc/approve" '{"approver":"e2e-operator"}'
  # Hold the admin call open so the restart lands while the execution is in flight.
  dc pause inventory >/dev/null 2>&1
  (curl -sS -m 60 -X POST -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d '{"approver":"e2e-operator"}' "$CONTROL/api/incidents/$inc/execute" >"$WORK/exec-inflight" 2>&1) &
  inflight=$!
  sleep 3
  log "in flight: status=$(incf "$inc" .status); restarting control"
  dc restart control >/dev/null 2>&1
  dc unpause inventory >/dev/null 2>&1
  wait "$inflight" 2>/dev/null
  wait_for 120 control_ready
  wait_for 60 status_not "$inc" executing
  check "5.nothing stuck executing after the restart" "status=$(incf "$inc" .status)" "$(ok status_not "$inc" executing)"
  check "5.no execution recorded twice" "remediation_executed events=$(event_count "$inc" remediation_executed)" "$([[ $(event_count "$inc" remediation_executed) -le 1 ]] && echo 0 || echo 1)"
  if [[ "$(incf "$inc" .status)" == approved ]]; then
    api POST "/api/incidents/$inc/execute" '{"approver":"e2e-operator"}'
    check "5.the interrupted execution can be completed" "HTTP $API_CODE status=$(echo "$API_BODY" | jq -r '.status // .detail')" "$([[ $API_CODE == 200 ]] && echo 0 || echo 1)"
  fi
  wait_for 30 verification_is "$inc" verifying
  log "verification: $(verification_state "$inc"); restarting control"
  dc restart control >/dev/null 2>&1
  wait_for 120 control_ready
  check "5.verification still running or concluded after restart" "state=$(verification_state "$inc")" "$([[ $(verification_state "$inc") =~ ^(verifying|verified)$ ]] && echo 0 || echo 1)"
  wait_for "$((VERIFY + 60))" verification_is "$inc" verified
  check "5.verification reaches verified after the restart" "state=$(verification_state "$inc")" "$(ok verification_is "$inc" verified)"
  check "5.still exactly one remediation_executed event" "count=$(event_count "$inc" remediation_executed)" "$([[ $(event_count "$inc" remediation_executed) == 1 ]] && echo 0 || echo 1)"
  wait_for 300 status_is "$inc" resolved
  check "5.incident resolves, nothing stuck executing" "status=$(incf "$inc" .status), executing rows=$(sql "select count(*) from incidents where status='executing'")" \
    "$([[ $(incf "$inc" .status) == resolved && $(sql "select count(*) from incidents where status='executing'") == 0 ]] && echo 0 || echo 1)"
}

s6_checkout_down() {
  log "== 6. checkout stopped: checkout_down incident, no unsafe remediation"
  quiesce
  local inc rule
  dc stop checkout >/dev/null 2>&1
  wait_for 120 has_new service:checkout
  inc="$(first_new service:checkout)"
  rule="$(incf "$inc" .data.latest_evidence.rule)"
  check "6.checkout_down incident opened" "incident=${inc:-none} rule=$rule" "$([[ $rule == checkout_down ]] && echo 0 || echo 1)"
  sleep $((BLIND + 10))
  wait_for 60 status_not "$inc" investigating
  check "6.no recommendation is offered" "status=$(incf "$inc" .status), recommendation=$(incf "$inc" '.data.recommendation // "none"')" \
    "$([[ $(incf "$inc" '.data.recommendation // "none"') == none && $(incf "$inc" .status) == open ]] && echo 0 || echo 1)"
  api POST "/api/incidents/$inc/approve" '{"approver":"e2e-operator"}'
  check "6.approve is refused" "HTTP $API_CODE" "$([[ $API_CODE == 409 ]] && echo 0 || echo 1)"
  check "6.no telemetry:blind incident just because checkout is down" "telemetry:blind incidents=$(count_new telemetry:blind)" "$([[ $(count_new telemetry:blind) == 0 ]] && echo 0 || echo 1)"
  dc start checkout >/dev/null 2>&1
  wait_for 300 status_is "$inc" resolved
  check "6.resolves when checkout returns" "status=$(incf "$inc" .status)" "$(ok status_is "$inc" resolved)"
}

s7_kill() {
  log "== 7. SIGKILL control during heavy polling: database intact, state consistent"
  quiesce
  local inc ids_before ids_after n path _
  chaos checkout errors 1
  wait_for 120 has_new service:checkout
  inc="$(first_new service:checkout)"
  wait_for 90 has_recommendation "$inc"
  ids_before="$(get "/api/incidents?limit=200" | jq -c '[.incidents[].id] | sort')"
  for path in /api/incidents /api/overview /readyz /metrics /api/engine/status "/api/incidents/$inc"; do
    for _ in 1 2; do
      (while true; do curl -s -m 5 -o /dev/null "$CONTROL$path"; done) &
      POLLERS+=($!)
    done
  done
  sleep 5
  log "killing control with SIGKILL under load"
  dc kill -s SIGKILL control >/dev/null 2>&1
  sleep 3
  dc start control >/dev/null 2>&1
  wait_for 120 control_ready
  stop_background
  start_traffic
  check "7.sqlite integrity_check ok" "$(sql 'pragma integrity_check')" "$([[ $(sql 'pragma integrity_check') == ok ]] && echo 0 || echo 1)"
  ids_after="$(get "/api/incidents?limit=200" | jq -c '[.incidents[].id] | sort')"
  check "7.no incident lost or duplicated by the crash" "$(echo "$ids_before" | jq length) -> $(echo "$ids_after" | jq length)" "$([[ $ids_before == "$ids_after" ]] && echo 0 || echo 1)"
  wait_for 60 engine_is ok
  check "7.engine healthy after restart" "$(get /api/engine/status | jq -c '{state,reason}')" "$(ok engine_is ok)"
  n="$(sql "select count(*) from incidents where status in ('executing')")"
  check "7.nothing stuck executing" "executing=$n" "$([[ $n == 0 ]] && echo 0 || echo 1)"
  sleep $((POLL * 6))
  check "7.still a single checkout incident (recovered engine did not duplicate it)" "count=$(count_new service:checkout)" "$([[ $(count_new service:checkout) == 1 ]] && echo 0 || echo 1)"
  remediate "$inc"
  check "7.the recommendation made before the crash can still be approved and executed" "HTTP $REM_CODE" "$([[ $REM_CODE == 200/200 ]] && echo 0 || echo 1)"
  wait_for 300 status_is "$inc" resolved
  check "7.incident resolves after the restart" "status=$(incf "$inc" .status)" "$(ok status_is "$inc" resolved)"
}

# --- run ---------------------------------------------------------------------------------

cleanup() {
  stop_background
  if [[ "${E2E_KEEP:-0}" != 1 && "${E2E_SKIP_UP:-0}" != 1 ]]; then
    log "tearing down project $PROJECT (and only that project)"
    dc down -v --remove-orphans >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ "${E2E_SKIP_UP:-0}" != 1 ]]; then
  log "building and starting project $PROJECT on ports $BASE-$((BASE + 5))"
  dc up -d --build control checkout inventory prometheus loki promtail || { log "stack failed to start"; exit 1; }
fi
wait_for 180 control_ready || { log "control plane did not become ready"; dc logs --tail 30 control; exit 1; }
start_traffic
sleep 15

for scenario in $SCENARIOS; do
  case "$scenario" in
    1) s1_latency ;;
    2) s2_dependency ;;
    3) s3_prometheus ;;
    4) s4_loki ;;
    5) s5_restart ;;
    6) s6_checkout_down ;;
    7) s7_kill ;;
    *) log "unknown scenario $scenario" ;;
  esac
done

echo
echo "==== results ===="
printf '%s\n' "${RESULTS[@]}"
if [[ "$FAILED" == 0 ]]; then
  echo "ALL CHECKS PASSED"
else
  echo "SOME CHECKS FAILED"
fi
exit "$FAILED"
