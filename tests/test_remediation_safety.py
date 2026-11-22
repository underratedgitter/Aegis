"""Remediation safety: idempotency, bounded retries, guardrails, dry run, and audit detail."""

import threading

import httpx
import pytest

from aegis.queries import CHECKOUT_CPU_BURN
from aegis.remediation import (
    RemediationActionFailed,
    RemediationError,
    RemediationExecutor,
    RemediationRateLimited,
)
from aegis.settings import Settings
from aegis.storage import Store

CLEAR_DEPENDENCY = {
    "action": "clear_fault",
    "target": "inventory",
    "parameters": {"fault": "dependency"},
}


class Ok:
    def __init__(self, body=None):
        self.body = body if body is not None else {"status": "cleared"}

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def status_error(code):
    request = httpx.Request("POST", "http://inventory/admin/faults/clear")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(str(code), request=request, response=response)


class FakeTelemetry:
    """Answers the cpu-burn query; `value` is what Prometheus would return."""

    def __init__(self, value):
        self.value = value
        self.queries = []

    def prometheus_query(self, query):
        self.queries.append(query)
        if self.value is None:
            return {"query": query, "value": None, "error": "prometheus down"}
        return {"query": query, "value": self.value}


def build(tmp_path, *, telemetry=None, audit=None, **overrides):
    defaults = {"remediation_verify_seconds": 0, "remediation_backoff_ms": 0}
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"),
        checkout_url="http://checkout",
        inventory_url="http://inventory",
        api_key="test-key",
        **{**defaults, **overrides},
    )
    store = Store(settings.db_path)
    executor = RemediationExecutor(settings, store, telemetry=telemetry, audit=audit)
    return executor, store


def approve(store, incident_id="inc-1", recommendation=CLEAR_DEPENDENCY, root="dependency:inventory",
            approved_at="2026-01-01T00:00:00+00:00", evidence=None):
    store.upsert_incident(incident_id, "t", "high", root, evidence or {"n": 0})
    approval = {"approver": "op", "approved_at": approved_at, "recommendation": recommendation}
    store.merge_incident(
        incident_id,
        {"recommendation": recommendation, "approval": approval},
        status="approved",
    )


def posts(executor, monkeypatch, responder=None):
    calls = []

    def fake_post(url, json, headers=None):
        calls.append((url, json))
        return responder(len(calls)) if responder else Ok()

    monkeypatch.setattr(executor._client, "post", fake_post)
    return calls


# ─── Idempotency ──────────────────────────────────────────────────────────────


def test_the_execution_is_recorded_under_an_idempotency_key(tmp_path, monkeypatch):
    executor, store = build(tmp_path)
    approve(store)
    posts(executor, monkeypatch)

    result = executor.execute("inc-1", "op")

    row = store.get_execution(result["idempotency_key"])
    assert row["state"] == "succeeded"
    assert (row["incident_id"], row["action"], row["target"], row["attempts"]) == (
        "inc-1", "clear_fault", "inventory", 1,
    )
    assert store.get_incident("inc-1")["data"]["remediation"]["idempotency_key"] == result["idempotency_key"]


def test_pressing_execute_again_replays_the_result_without_calling_the_service(tmp_path, monkeypatch):
    executor, store = build(tmp_path)
    approve(store)
    calls = posts(executor, monkeypatch)

    first = executor.execute("inc-1", "op")
    second = executor.execute("inc-1", "op")

    assert len(calls) == 1
    assert second["status"] == "already_executed"
    assert second["idempotency_key"] == first["idempotency_key"]
    assert second["result"] == first["result"]
    assert len(store.executions("inc-1")) == 1


def test_a_new_approval_is_a_new_execution(tmp_path, monkeypatch):
    executor, store = build(tmp_path, remediation_max_per_window=10)
    approve(store)
    calls = posts(executor, monkeypatch)
    first = executor.execute("inc-1", "op")

    store.merge_incident("inc-1", {}, status="recommendation_pending")
    approve(store, approved_at="2026-01-01T00:05:00+00:00")
    second = executor.execute("inc-1", "op")

    assert second["status"] == "executed"
    assert second["idempotency_key"] != first["idempotency_key"]
    assert len(calls) == 2


def test_a_stale_approval_is_not_replayed_for_a_new_recommendation(tmp_path, monkeypatch):
    executor, store = build(tmp_path)
    approve(store)
    posts(executor, monkeypatch)
    executor.execute("inc-1", "op")
    store.merge_incident("inc-1", {}, status="recommendation_pending")

    with pytest.raises(RemediationError, match="requires an approved"):
        executor.execute("inc-1", "op")


def test_an_interrupted_execution_is_not_repeated_blindly(tmp_path, monkeypatch):
    executor, store = build(tmp_path)  # no telemetry: it cannot tell whether the action applied
    approve(store)
    key = executor.idempotency_key("inc-1", store.get_incident("inc-1")["data"]["approval"])
    store.transition_status("inc-1", "approved", "executing")
    store.claim_execution(key, "inc-1", "clear_fault", "inventory", {}, "op", max_per_window=5, window_seconds=300)
    store.recover_interrupted_executions()
    calls = posts(executor, monkeypatch)

    with pytest.raises(RemediationError, match="may have been applied"):
        executor.execute("inc-1", "op")

    assert calls == []
    assert store.get_incident("inc-1")["status"] == "approved"


def test_after_an_interruption_a_cleared_signal_means_it_applied_and_it_is_not_repeated(tmp_path, monkeypatch):
    executor, store = build(tmp_path, telemetry=FakeTelemetry(0.0))
    approve(store, root="service:checkout:cpu", evidence={"rule": "checkout_cpu_burn"})
    key = executor.idempotency_key("inc-1", store.get_incident("inc-1")["data"]["approval"])
    store.transition_status("inc-1", "approved", "executing")
    store.claim_execution(key, "inc-1", "clear_fault", "inventory", {}, "op", max_per_window=5, window_seconds=300)
    store.recover_interrupted_executions()
    calls = posts(executor, monkeypatch)

    result = executor.execute("inc-1", "op")

    assert calls == []
    assert result["status"] == "already_executed"
    assert store.get_execution(key)["state"] == "succeeded"
    assert store.get_incident("inc-1")["status"] == "open"


def test_after_an_interruption_a_firing_signal_allows_one_new_attempt(tmp_path, monkeypatch):
    executor, store = build(tmp_path, telemetry=FakeTelemetry(1.0))
    approve(store, root="service:checkout:cpu", evidence={"rule": "checkout_cpu_burn"})
    key = executor.idempotency_key("inc-1", store.get_incident("inc-1")["data"]["approval"])
    store.transition_status("inc-1", "approved", "executing")
    store.claim_execution(key, "inc-1", "clear_fault", "inventory", {}, "op", max_per_window=5, window_seconds=300)
    store.recover_interrupted_executions()
    calls = posts(executor, monkeypatch)

    result = executor.execute("inc-1", "op")

    assert len(calls) == 1
    assert result["status"] == "executed"
    assert [e["state"] for e in store.executions("inc-1")] == ["succeeded"]


# ─── Retries, timeouts, and failure classification ────────────────────────────


def test_the_admin_timeout_comes_from_settings(tmp_path):
    executor, _ = build(tmp_path, remediation_timeout_seconds=9)

    assert executor._client.timeout.read == 9.0
    assert executor._client.timeout.connect == 2.0


def test_transient_failures_are_retried_with_exponential_backoff(tmp_path, monkeypatch):
    executor, store = build(tmp_path, remediation_max_attempts=4, remediation_backoff_ms=100)
    approve(store)
    waits = []
    monkeypatch.setattr(executor._stop, "wait", lambda seconds: waits.append(seconds) or False)

    def responder(call):
        if call == 1:
            raise httpx.ConnectError("refused")
        if call == 2:
            raise status_error(503)
        if call == 3:
            raise httpx.ReadTimeout("slow")
        return Ok()

    calls = posts(executor, monkeypatch, responder)

    result = executor.execute("inc-1", "op")

    assert len(calls) == 4
    assert waits == [0.1, 0.2, 0.4]
    assert result["attempts"] == 4
    assert store.get_execution(result["idempotency_key"])["attempts"] == 4


def test_a_rejection_is_not_retried(tmp_path, monkeypatch):
    executor, store = build(tmp_path)
    approve(store)

    def responder(call):
        raise status_error(403)

    calls = posts(executor, monkeypatch, responder)

    with pytest.raises(RemediationActionFailed, match="rejected, not applied"):
        executor.execute("inc-1", "op")

    assert len(calls) == 1
    assert [e["state"] for e in store.executions("inc-1")] == ["failed"]
    assert store.get_incident("inc-1")["status"] == "approved"


def test_exhausted_retries_report_the_action_as_failed_with_every_attempt(tmp_path, monkeypatch):
    executor, store = build(tmp_path, remediation_max_attempts=3)
    approve(store)

    def responder(call):
        raise httpx.ConnectError("refused")

    calls = posts(executor, monkeypatch, responder)

    with pytest.raises(RemediationActionFailed) as caught:
        executor.execute("inc-1", "op")

    assert len(calls) == 3
    assert caught.value.status_code == 502
    assert "after 3 attempts" in str(caught.value)
    failed = [e for e in store.events("inc-1") if e["kind"] == "remediation_failed"]
    assert len(failed) == 1
    assert len(failed[0]["data"]["errors"]) == 3
    assert store.executions("inc-1")[0]["state"] == "failed"


def test_a_timeout_that_may_have_applied_leaves_the_execution_unknown(tmp_path, monkeypatch):
    executor, store = build(tmp_path, remediation_max_attempts=1)
    approve(store)

    def responder(call):
        raise httpx.ReadTimeout("slow")

    posts(executor, monkeypatch, responder)

    with pytest.raises(RemediationActionFailed, match="may have been applied"):
        executor.execute("inc-1", "op")

    assert store.executions("inc-1")[0]["state"] == "unknown"
    assert store.get_incident("inc-1")["status"] == "approved"


def test_an_unexpected_error_releases_the_incident_and_the_target(tmp_path, monkeypatch):
    executor, store = build(tmp_path)
    approve(store)

    def responder(call):
        raise RuntimeError("boom")

    posts(executor, monkeypatch, responder)

    with pytest.raises(RuntimeError):
        executor.execute("inc-1", "op")

    assert store.get_incident("inc-1")["status"] == "approved"
    assert [e["state"] for e in store.executions("inc-1")] == ["unknown"]


# ─── Guardrails ───────────────────────────────────────────────────────────────


def test_actions_outside_the_configured_allowlist_are_refused_before_any_call(tmp_path, monkeypatch):
    executor, store = build(tmp_path, remediation_allowed_actions_raw="checkout:clear_fault")
    approve(store)
    calls = posts(executor, monkeypatch)

    with pytest.raises(RemediationError, match="not permitted"):
        executor.execute("inc-1", "op")
    with pytest.raises(RemediationError, match="not permitted"):
        executor.ensure_permitted(CLEAR_DEPENDENCY)

    assert calls == []
    assert store.get_incident("inc-1")["status"] == "approved"


@pytest.mark.parametrize("replicas", [True, 2.5, 0, 4, "abc", None, [2]])
def test_scale_parameters_must_be_real_integers_in_bounds(replicas):
    recommendation = {
        "action": "scale_simulation",
        "target": "checkout",
        "parameters": {"replicas": replicas},
    }

    with pytest.raises(RemediationError, match="Simulation scale"):
        RemediationExecutor.validate_recommendation(recommendation)


@pytest.mark.parametrize("replicas", [1, 3, 2.0, "2"])
def test_scale_parameters_in_bounds_are_accepted(replicas):
    recommendation = {
        "action": "scale_simulation",
        "target": "checkout",
        "parameters": {"replicas": replicas},
    }

    assert RemediationExecutor.validate_recommendation(recommendation) == ("scale_simulation", "checkout")


def test_the_scale_payload_sent_is_the_validated_integer(tmp_path, monkeypatch):
    executor, store = build(tmp_path)
    recommendation = {"action": "scale_simulation", "target": "checkout", "parameters": {"replicas": "3"}}
    approve(store, recommendation=recommendation, root="service:checkout")
    calls = posts(executor, monkeypatch)

    executor.execute("inc-1", "op")

    assert calls == [("http://checkout/admin/scale", {"replicas": 3})]


def test_executions_beyond_the_per_target_limit_are_refused_with_a_retry_hint(tmp_path, monkeypatch):
    executor, store = build(tmp_path, remediation_max_per_window=1)
    approve(store, "inc-1")
    approve(store, "inc-2", root="dependency:inventory:2")
    calls = posts(executor, monkeypatch)
    executor.execute("inc-1", "op")

    with pytest.raises(RemediationRateLimited) as caught:
        executor.execute("inc-2", "op")

    assert len(calls) == 1
    assert caught.value.status_code == 429
    assert 0 < caught.value.retry_after <= 300
    assert store.get_incident("inc-2")["status"] == "approved"


def test_a_second_execution_on_a_busy_target_is_refused(tmp_path, monkeypatch):
    executor, store = build(tmp_path)
    approve(store, "inc-1")
    approve(store, "inc-2", root="dependency:inventory:2")
    in_flight, release = threading.Event(), threading.Event()
    calls = []

    def slow_post(url, json, headers=None):
        calls.append(url)
        in_flight.set()
        release.wait(timeout=5)
        return Ok()

    monkeypatch.setattr(executor._client, "post", slow_post)
    first = threading.Thread(target=lambda: executor.execute("inc-1", "op"))
    first.start()
    assert in_flight.wait(timeout=5)

    try:
        with pytest.raises(RemediationError, match="already running on inventory"):
            executor.execute("inc-2", "op")
    finally:
        release.set()
        first.join(timeout=5)

    assert len(calls) == 1
    assert store.get_incident("inc-2")["status"] == "approved"


def test_dry_run_validates_and_reports_but_changes_nothing(tmp_path, monkeypatch):
    executor, store = build(tmp_path, remediation_dry_run=True)
    approve(store)
    calls = posts(executor, monkeypatch)

    result = executor.execute("inc-1", "op")

    assert calls == []
    assert result["status"] == "dry_run"
    assert result["result"] == {
        "endpoint": "http://inventory/admin/faults/clear",
        "payload": {"fault": "dependency"},
    }
    assert store.get_incident("inc-1")["status"] == "approved"
    assert store.executions("inc-1") == []
    assert [e["kind"] for e in store.events("inc-1") if e["kind"] == "remediation_dry_run"]


def test_dry_run_still_refuses_what_a_real_run_would_refuse(tmp_path):
    executor, store = build(tmp_path, remediation_dry_run=True, remediation_allowed_actions_raw="checkout:clear_fault")
    approve(store)

    with pytest.raises(RemediationError, match="not permitted"):
        executor.execute("inc-1", "op")


# ─── Audit trail ──────────────────────────────────────────────────────────────


def test_every_outcome_is_audited_with_enough_detail_to_reconstruct_it(tmp_path, monkeypatch):
    entries = []
    executor, store = build(tmp_path, audit=lambda action, detail: entries.append((action, detail)))
    approve(store)
    calls = posts(executor, monkeypatch)

    first = executor.execute("inc-1", "op")
    executor.execute("inc-1", "op")
    with pytest.raises(RemediationError):
        executor.execute("missing", "op")

    assert len(calls) == 1
    actions = [action for action, _ in entries]
    assert actions == ["execute", "execute_replayed", "execute_refused"]
    executed = entries[0][1]
    assert executed == {
        "incident_id": "inc-1",
        "approver": "op",
        "action": "clear_fault",
        "target": "inventory",
        "idempotency_key": first["idempotency_key"],
        "attempts": 1,
    }
    assert entries[2][1]["reason"] == "Incident not found"


def test_a_failed_action_is_audited_with_its_attempts_and_outcome(tmp_path, monkeypatch):
    entries = []
    executor, store = build(
        tmp_path, audit=lambda action, detail: entries.append((action, detail)), remediation_max_attempts=2
    )
    approve(store)

    def responder(call):
        raise httpx.ConnectError("refused")

    posts(executor, monkeypatch, responder)

    with pytest.raises(RemediationActionFailed):
        executor.execute("inc-1", "op")

    action, detail = entries[0]
    assert action == "execute_failed"
    assert detail["attempts"] == 2
    assert detail["outcome"] == "not sent, not applied"
    assert detail["idempotency_key"]
    assert detail["target"] == "inventory"


def test_dry_run_is_audited(tmp_path, monkeypatch):
    entries = []
    executor, store = build(
        tmp_path, audit=lambda action, detail: entries.append((action, detail)), remediation_dry_run=True
    )
    approve(store)

    executor.execute("inc-1", "op")

    assert [action for action, _ in entries] == ["execute_dry_run"]
