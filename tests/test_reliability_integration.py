"""The detection, supervision and remediation work compose: nothing one adds is bypassed by another."""

import dataclasses
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from aegis import control_plane
from aegis.agent import AgentInvestigator
from aegis.incidents import BLIND_ROOT, RULES
from aegis.remediation import RemediationError, RemediationExecutor, no_remediation_reason
from aegis.settings import Settings
from aegis.storage import Store
from aegis.supervisor import SupervisedEngine

QUERY = {rule.name: rule.query for rule in RULES}
ERRORS = "checkout_error_rate"
DOWN = "checkout_down"


class Telemetry:
    """Answers per rule name: a number, None (no series) or "error"."""

    def __init__(self, **answers):
        self.answers = answers

    def prometheus_query(self, query):
        name = next(name for name, text in QUERY.items() if text == query)
        reading = self.answers.get(name, 0.0)
        if reading == "error":
            return {"value": None, "error": "HTTP error: down"}
        return {"value": reading}

    def metric_snapshot(self):
        return []

    def recent_logs(self, service=None, limit=30):
        return []


def engine_for(tmp_path, telemetry, **overrides):
    options = {
        "detection_cycles": 2,
        "resolution_cycles": 2,
        "blind_seconds": 0,
        "reopen_cooldown_seconds": 0,
        **overrides,
    }
    settings = Settings(db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks", **options)
    store = Store(settings.db_path)
    engine = SupervisedEngine(settings, store, telemetry)
    engine._spawn_investigation = lambda incident_id: store.transition_status(  # type: ignore[method-assign]
        incident_id, "investigating", "open"
    )
    engine._thread = SimpleNamespace(is_alive=lambda: True)  # type: ignore[assignment]
    return engine, store


def test_supervised_cycles_apply_detection_hysteresis(tmp_path):
    engine, store = engine_for(tmp_path, Telemetry(**{ERRORS: 0.6}))

    engine._supervise_cycle()
    assert store.list_incidents(limit=10) == []

    engine._supervise_cycle()
    assert [i["root_cause_key"] for i in store.list_incidents(limit=10)] == ["service:checkout"]


def test_supervised_cycles_run_under_the_detection_cycle_lock(tmp_path):
    engine, _ = engine_for(tmp_path, Telemetry())
    held = []
    engine._run_cycle = lambda: held.append(engine._cycle_lock.locked()) or []  # type: ignore[method-assign]

    engine._supervise_cycle()

    assert held == [True]


def test_unreadable_telemetry_never_resolves_an_incident_in_the_supervised_loop(tmp_path):
    telemetry = Telemetry(**{ERRORS: 0.6})
    engine, store = engine_for(tmp_path, telemetry)
    engine._supervise_cycle()
    engine._supervise_cycle()
    telemetry.answers = dict.fromkeys(QUERY, "error")

    for _ in range(5):
        engine._supervise_cycle()

    assert [i["status"] for i in store.list_incidents(limit=10)] == ["open"]


def test_status_reports_signal_states_and_degrades_while_a_signal_is_unreadable(tmp_path):
    telemetry = Telemetry()
    engine, _ = engine_for(tmp_path, telemetry)
    engine._supervise_cycle()
    assert engine.status().state == "ok"
    assert set(engine.status().signals.values()) == {"ok"}

    telemetry.answers = dict.fromkeys(QUERY, "error")
    engine._supervise_cycle()

    status = engine.status()
    assert status.state == "degraded"
    assert status.reason is not None and "unavailable" in status.reason and DOWN in status.reason
    assert status.signals[DOWN] == "unavailable"
    assert status.consecutive_failures == 0  # the cycle itself succeeded


def test_status_is_ok_again_once_signals_return(tmp_path):
    telemetry = Telemetry(**dict.fromkeys(QUERY, "error"))
    engine, _ = engine_for(tmp_path, telemetry)
    engine._supervise_cycle()
    telemetry.answers = {}

    engine._supervise_cycle()

    assert engine.status().state == "ok"


# Incidents with no safe remediation -------------------------------------------------


def advisory_agent(tmp_path, root, rule):
    settings = Settings(db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks")
    store = Store(settings.db_path)
    store.upsert_incident("inc-1", "t", "high", root, {"rule": rule, "value": 1.0})
    return AgentInvestigator(settings, store, Telemetry()), store


@pytest.mark.parametrize(
    ("root", "rule"),
    [(BLIND_ROOT, "telemetry_blind"), ("service:checkout", DOWN)],
)
def test_incidents_without_a_safe_fix_get_no_recommendation(tmp_path, monkeypatch, root, rule):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    agent, store = advisory_agent(tmp_path, root, rule)
    store.transition_status("inc-1", "open", "investigating")

    result = agent.investigate("inc-1")

    incident = store.get_incident("inc-1")
    assert result["recommendation"] is None
    assert incident["data"]["recommendation"] is None
    assert incident["status"] == "open"  # nothing to approve


def test_the_llm_is_not_consulted_for_incidents_without_a_safe_fix(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    agent, _store = advisory_agent(tmp_path, BLIND_ROOT, "telemetry_blind")
    monkeypatch.setattr(agent, "_llm_investigation", lambda incident: pytest.fail("LLM was called"))

    assert agent.investigate("inc-1")["recommendation"] is None


def test_a_checkout_error_incident_still_gets_its_recommendation(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    agent, store = advisory_agent(tmp_path, "service:checkout", ERRORS)
    store.transition_status("inc-1", "open", "investigating")

    result = agent.investigate("inc-1")

    assert result["recommendation"]["action"] == "clear_fault"
    assert store.get_incident("inc-1")["status"] == "recommendation_pending"


def test_no_remediation_reason_covers_blind_and_down_incidents():
    blind = {"root_cause_key": BLIND_ROOT, "data": {}}
    down = {"root_cause_key": "service:checkout", "data": {"latest_evidence": {"rule": DOWN}}}
    erroring = {"root_cause_key": "service:checkout", "data": {"latest_evidence": {"rule": ERRORS}}}

    assert no_remediation_reason(blind)
    assert no_remediation_reason(down)
    assert no_remediation_reason(erroring) is None


@pytest.fixture
def client(monkeypatch):
    live = dataclasses.replace(
        control_plane.remediation.settings,
        api_key="test-key",
        remediation_verify_seconds=0,
        remediation_backoff_ms=0,
    )
    monkeypatch.setattr(control_plane.remediation, "settings", live)
    return TestClient(control_plane.app)


RECOMMENDATION = {"action": "clear_fault", "target": "checkout", "parameters": {"fault": "errors"}}


def stale_recommendation(incident_id, status):
    """An error incident whose recommendation predates checkout going down."""
    store = control_plane.store
    store.upsert_incident(incident_id, "t", "high", f"service:{incident_id}", {"rule": ERRORS})
    store.upsert_incident(incident_id, "t", "high", f"service:{incident_id}", {"rule": DOWN})
    data: dict = {"recommendation": RECOMMENDATION}
    if status == "approved":
        data["approval"] = {"approver": "op", "approved_at": "2026-01-01T00:00:00+00:00", "recommendation": RECOMMENDATION}
    store.merge_incident(incident_id, data, status=status)


def test_a_recommendation_is_not_approvable_once_checkout_is_down(client):
    stale_recommendation("inc-down-approve", "recommendation_pending")

    response = client.post("/api/incidents/inc-down-approve/approve", json={"approver": "op"})

    assert response.status_code == 409
    assert "not answering" in response.json()["detail"]


def test_an_approved_fix_is_not_executed_against_a_checkout_that_is_down(client, monkeypatch):
    stale_recommendation("inc-down-exec", "approved")
    monkeypatch.setattr(control_plane.remediation._client, "post", lambda *a, **k: pytest.fail("service was called"))

    response = client.post("/api/incidents/inc-down-exec/execute", json={"approver": "op"})

    assert response.status_code == 409
    assert control_plane.store.get_incident("inc-down-exec")["status"] == "approved"


# Verification honours detection's no-data semantics ----------------------------------


class Scripted:
    """Per-query answers: a number, None for an empty result, or "error"."""

    def __init__(self, by_query):
        self.by_query = by_query

    def prometheus_query(self, query):
        reading = self.by_query.get(query, "error")
        if reading == "error":
            return {"value": None, "error": "down"}
        return {"value": reading}


def verify_with(tmp_path, answers):
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"),
        remediation_verify_seconds=2,
        remediation_verify_interval=1,
        resolution_cycles=2,
    )
    store = Store(settings.db_path)
    executor = RemediationExecutor(settings, store, telemetry=Scripted(answers))
    executor._stop.wait = lambda seconds: False  # type: ignore[method-assign]
    store.upsert_incident("inc-1", "t", "high", "service:checkout", {"rule": ERRORS})
    record = {
        "action": "clear_fault", "target": "checkout", "approver": "op", "result": {},
        "idempotency_key": "k", "attempts": 1, "verification": {"state": "verifying"},
    }
    store.merge_incident("inc-1", {"remediation": record}, status="open")
    return executor, store


def test_an_empty_reading_is_cleared_only_while_checkout_still_answers_scrapes(tmp_path):
    executor, _ = verify_with(tmp_path, {QUERY[ERRORS]: None, QUERY[DOWN]: 0.0})

    assert executor.verify("inc-1") == "verified"


def test_an_empty_reading_is_not_cleared_when_checkout_liveness_is_unknown(tmp_path):
    executor, _ = verify_with(tmp_path, {QUERY[ERRORS]: None})  # liveness unreadable

    assert executor.verify("inc-1") == "unverified"


def test_an_empty_reading_is_not_cleared_when_checkout_is_down(tmp_path):
    executor, _ = verify_with(tmp_path, {QUERY[ERRORS]: None, QUERY[DOWN]: 1.0})

    assert executor.verify("inc-1") == "unverified"


# Metrics count every remediation outcome ---------------------------------------------


def sample(result):
    return REGISTRY.get_sample_value("aegis_remediation_executions_total", {"result": result}) or 0.0


def test_metrics_count_dry_runs_verifications_and_escalations():
    store = control_plane.store
    before = {r: sample(r) for r in ("dry_run", "verified", "escalated")}
    store.upsert_incident("inc-outcomes", "t", "high", "service:outcomes", {"n": 1})
    for kind in ("remediation_dry_run", "remediation_verified", "remediation_escalated", "remediation_escalated"):
        store.add_event("inc-outcomes", kind, "x")

    assert sample("dry_run") == before["dry_run"] + 1
    assert sample("verified") == before["verified"] + 1
    assert sample("escalated") == before["escalated"] + 2


def test_the_executor_refuses_a_down_checkout_directly(tmp_path):
    settings = Settings(db_path=str(tmp_path / "db.sqlite"), api_key="k")
    store = Store(settings.db_path)
    executor = RemediationExecutor(settings, store)
    store.upsert_incident("inc-1", "t", "high", "service:checkout", {"rule": DOWN})
    approval = {"approver": "op", "approved_at": "t", "recommendation": RECOMMENDATION}
    store.merge_incident("inc-1", {"recommendation": RECOMMENDATION, "approval": approval}, status="approved")

    with pytest.raises(RemediationError, match="not answering"):
        executor.execute("inc-1", "op")


# The local investigator proposes the fault that actually fired -------------------------


@pytest.mark.parametrize(
    ("rules", "fault"),
    [
        (["checkout_p95_latency"], "latency"),
        (["checkout_error_rate"], "errors"),
        (["checkout_p95_latency", "checkout_error_rate"], "errors"),
    ],
)
def test_the_local_recommendation_clears_the_fault_that_fired(tmp_path, monkeypatch, rules, fault):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    agent, store = advisory_agent(tmp_path, "service:checkout", rules[0])
    for rule in rules[1:]:
        store.upsert_incident("inc-1", "t", "high", "service:checkout", {"rule": rule})
    store.transition_status("inc-1", "open", "investigating")

    result = agent.investigate("inc-1")

    assert result["recommendation"]["parameters"] == {"fault": fault}


# A stopped checkout is not blindness ----------------------------------------------------


def blind_incidents(store):
    return [i for i in store.list_incidents(limit=50) if i["root_cause_key"] == BLIND_ROOT]


def run_for(engine, clock, seconds, step=5):
    for _ in range(seconds // step):
        clock[0] += step
        engine._supervise_cycle()


def test_a_down_checkout_opens_its_own_incident_but_not_a_blind_one(tmp_path):
    # Prometheus answers: checkout is down (1.0) and so has no other series.
    telemetry = Telemetry(**{**dict.fromkeys(QUERY), DOWN: 1.0})
    engine, store = engine_for(tmp_path, telemetry, blind_seconds=20)
    clock = [1000.0]
    engine._clock = lambda: clock[0]

    run_for(engine, clock, 60)

    roots = [i["root_cause_key"] for i in store.list_incidents(limit=50)]
    assert roots == ["service:checkout"]
    assert engine.status().state == "degraded"  # the other signals still cannot be judged


def test_unreadable_prometheus_still_opens_the_blind_incident(tmp_path):
    telemetry = Telemetry(**dict.fromkeys(QUERY, "error"))
    engine, store = engine_for(tmp_path, telemetry, blind_seconds=20)
    clock = [1000.0]
    engine._clock = lambda: clock[0]

    run_for(engine, clock, 60)

    assert len(blind_incidents(store)) == 1


def test_missing_liveness_series_is_still_blindness(tmp_path):
    # Prometheus has no checkout target at all: nothing can be judged, and nothing explains why.
    telemetry = Telemetry(**dict.fromkeys(QUERY))
    engine, store = engine_for(tmp_path, telemetry, blind_seconds=20)
    clock = [1000.0]
    engine._clock = lambda: clock[0]

    run_for(engine, clock, 60)

    assert len(blind_incidents(store)) == 1
