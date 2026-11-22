"""After an action succeeds, the triggering signal is re-checked and the outcome is recorded."""

import time

import pytest

from aegis.remediation import RemediationExecutor
from aegis.settings import Settings
from aegis.storage import Store

RECOMMENDATION = {"action": "clear_fault", "target": "checkout", "parameters": {"fault": "cpu"}}


class SequenceTelemetry:
    """Returns the queued values in order, then repeats the last; None means unreadable."""

    def __init__(self, *values):
        self.values = list(values)
        self.calls = 0

    def prometheus_query(self, query):
        value = self.values[min(self.calls, len(self.values) - 1)]
        self.calls += 1
        if value is None:
            return {"query": query, "value": None, "error": "prometheus down"}
        return {"query": query, "value": value}


class Ok:
    def raise_for_status(self):
        return None

    def json(self):
        return {"status": "cleared"}


def build(tmp_path, telemetry, *, audit=None, window=10, interval=1, cycles=2):
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"),
        checkout_url="http://checkout",
        inventory_url="http://inventory",
        api_key="test-key",
        remediation_backoff_ms=0,
        remediation_verify_seconds=window,
        remediation_verify_interval=interval,
        resolution_cycles=cycles,
    )
    store = Store(settings.db_path)
    executor = RemediationExecutor(settings, store, telemetry=telemetry, audit=audit)
    # Time must not pass for real while polling.
    executor._stop.wait = lambda seconds: False  # type: ignore[method-assign]
    return executor, store


def remediated(store, incident_id="inc-1", state="verifying"):
    """An incident whose remediation just succeeded and awaits verification."""
    store.upsert_incident(incident_id, "t", "high", "service:checkout:cpu", {"rule": "checkout_cpu_burn"})
    record = {
        "action": "clear_fault",
        "target": "checkout",
        "approver": "op",
        "result": {},
        "idempotency_key": "key-1",
        "attempts": 1,
        "verification": {"state": state, "window_seconds": 10},
    }
    store.merge_incident(incident_id, {"remediation": record}, status="open")


def verification(store, incident_id="inc-1"):
    return store.get_incident(incident_id)["data"]["remediation"]["verification"]


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_a_cleared_signal_marks_the_remediation_verified(tmp_path):
    audit = []
    executor, store = build(tmp_path, SequenceTelemetry(0.0), audit=lambda a, d: audit.append((a, d)))
    remediated(store)

    assert executor.verify("inc-1") == "verified"

    record = verification(store)
    assert record["state"] == "verified"
    assert record["readings"] == [{"rule": "checkout_cpu_burn", "value": 0.0, "threshold": 0.5, "clear": True}]
    incident = store.get_incident("inc-1")
    assert (incident["status"], incident["severity"]) == ("open", "high")
    assert [e["kind"] for e in store.events("inc-1")][-1] == "remediation_verified"
    assert audit == [("remediation_verified", {"incident_id": "inc-1", "idempotency_key": "key-1", "rules": ["checkout_cpu_burn"]})]


def test_a_signal_that_keeps_firing_escalates_even_though_the_action_succeeded(tmp_path):
    audit = []
    telemetry = SequenceTelemetry(1.0)
    executor, store = build(tmp_path, telemetry, audit=lambda a, d: audit.append((a, d)), window=4, interval=2)
    remediated(store)

    assert executor.verify("inc-1") == "failed"

    assert telemetry.calls == 3  # at 0s, 2s and 4s
    record = verification(store)
    assert (record["state"], record["escalated"]) == ("failed", True)
    incident = store.get_incident("inc-1")
    assert incident["severity"] == "critical"
    assert incident["status"] == "open"
    escalated = [e for e in store.events("inc-1") if e["kind"] == "remediation_escalated"]
    assert len(escalated) == 1
    assert "action succeeded" in escalated[0]["message"]
    assert "still firing" in escalated[0]["message"]
    assert escalated[0]["data"]["previous_severity"] == "high"
    assert audit[0][0] == "remediation_escalated"
    assert audit[0][1]["state"] == "failed"


def test_an_unreadable_signal_is_escalated_as_unverified(tmp_path):
    executor, store = build(tmp_path, SequenceTelemetry(None), window=2, interval=1)
    remediated(store)

    assert executor.verify("inc-1") == "unverified"

    assert verification(store)["state"] == "unverified"
    assert store.get_incident("inc-1")["severity"] == "critical"
    message = next(e for e in store.events("inc-1") if e["kind"] == "remediation_escalated")["message"]
    assert "could not read" in message


def test_the_signal_must_stay_clear_for_the_configured_consecutive_checks(tmp_path):
    telemetry = SequenceTelemetry(0.0, 1.0, 0.0, 0.0)
    executor, store = build(tmp_path, telemetry, cycles=2)
    remediated(store)

    assert executor.verify("inc-1") == "verified"

    assert telemetry.calls == 4


def test_a_signal_that_only_clears_at_the_end_is_not_verified(tmp_path):
    executor, store = build(tmp_path, SequenceTelemetry(1.0, 1.0, 0.0), window=2, interval=1)
    remediated(store)

    assert executor.verify("inc-1") == "unverified"


def test_an_already_resolved_incident_is_not_escalated(tmp_path):
    executor, store = build(tmp_path, SequenceTelemetry(1.0), window=1, interval=1)
    remediated(store)
    store.update_incident("inc-1", status="resolved")

    assert executor.verify("inc-1") == "failed"

    assert store.get_incident("inc-1")["severity"] == "high"
    assert verification(store)["state"] == "failed"


def test_a_newer_execution_is_not_overwritten_by_a_stale_verification(tmp_path):
    executor, store = build(tmp_path, SequenceTelemetry(0.0))
    remediated(store)
    original_query = executor.telemetry.prometheus_query

    def query_then_supersede(query):
        record = store.get_incident("inc-1")["data"]["remediation"]
        store.merge_incident("inc-1", {"remediation": {**record, "idempotency_key": "key-2"}})
        return original_query(query)

    executor.telemetry.prometheus_query = query_then_supersede

    executor.verify("inc-1")

    assert store.get_incident("inc-1")["data"]["remediation"]["idempotency_key"] == "key-2"
    assert verification(store)["state"] == "verifying"


def test_execute_verifies_in_the_background_and_reports_the_state(tmp_path, monkeypatch):
    executor, store = build(tmp_path, SequenceTelemetry(0.0))
    store.upsert_incident("inc-1", "t", "high", "service:checkout:cpu", {"rule": "checkout_cpu_burn"})
    approval = {"approver": "op", "approved_at": "2026-01-01T00:00:00+00:00", "recommendation": RECOMMENDATION}
    store.merge_incident("inc-1", {"approval": approval}, status="approved")
    monkeypatch.setattr(executor._client, "post", lambda url, json, headers=None: Ok())

    result = executor.execute("inc-1", "op")

    assert result["verification"] == "verifying"
    assert wait_for(lambda: verification(store)["state"] == "verified")
    assert store.get_incident("inc-1")["data"]["remediation"]["idempotency_key"] == result["idempotency_key"]
    executor.close()


def test_a_replay_reports_the_current_verification_state(tmp_path, monkeypatch):
    executor, store = build(tmp_path, SequenceTelemetry(0.0))
    store.upsert_incident("inc-1", "t", "high", "service:checkout:cpu", {"rule": "checkout_cpu_burn"})
    approval = {"approver": "op", "approved_at": "2026-01-01T00:00:00+00:00", "recommendation": RECOMMENDATION}
    store.merge_incident("inc-1", {"approval": approval}, status="approved")
    monkeypatch.setattr(executor._client, "post", lambda url, json, headers=None: Ok())
    executor.execute("inc-1", "op")
    assert wait_for(lambda: verification(store)["state"] == "verified")

    assert executor.execute("inc-1", "op")["verification"] == "verified"
    executor.close()


def test_verification_is_off_when_the_window_is_zero(tmp_path, monkeypatch):
    executor, store = build(tmp_path, SequenceTelemetry(0.0), window=0)
    store.upsert_incident("inc-1", "t", "high", "service:checkout:cpu", {"rule": "checkout_cpu_burn"})
    approval = {"approver": "op", "approved_at": "2026-01-01T00:00:00+00:00", "recommendation": RECOMMENDATION}
    store.merge_incident("inc-1", {"approval": approval}, status="approved")
    monkeypatch.setattr(executor._client, "post", lambda url, json, headers=None: Ok())

    result = executor.execute("inc-1", "op")

    assert result["verification"] is None
    assert "verification" not in store.get_incident("inc-1")["data"]["remediation"]


def test_verification_interrupted_by_a_restart_is_resumed(tmp_path):
    executor, store = build(tmp_path, SequenceTelemetry(0.0))
    remediated(store)
    remediated(store, "inc-2", state="verified")  # already concluded: must not run again
    store.upsert_incident("inc-3", "t", "high", "service:checkout", {"rule": "checkout_cpu_burn"})  # never remediated

    executor.resume_verifications()

    assert wait_for(lambda: verification(store)["state"] == "verified")
    assert executor.telemetry.calls == 2  # one incident, two consecutive clear checks
    executor.close()


def test_shutdown_stops_verifying_and_leaves_it_resumable(tmp_path):
    executor, store = build(tmp_path, SequenceTelemetry(1.0), window=60, interval=5)
    del executor._stop.wait  # use the real wait so close() has to interrupt it
    remediated(store)
    executor.resume_verifications()
    assert wait_for(lambda: executor.telemetry.calls >= 1)

    started = time.monotonic()
    executor.close()

    assert time.monotonic() - started < 3
    assert verification(store)["state"] == "verifying"
    assert not [e for e in store.events("inc-1") if e["kind"] == "remediation_escalated"]


@pytest.mark.parametrize("state", ["verified", "failed", "unverified"])
def test_concluded_verifications_are_not_resumed(tmp_path, state):
    executor, store = build(tmp_path, SequenceTelemetry(0.0))
    remediated(store, state=state)

    executor.resume_verifications()

    assert executor._workers == set()
