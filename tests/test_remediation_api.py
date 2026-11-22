"""Execute and approve endpoints: outcomes map to distinct statuses and every one is audited."""

import dataclasses

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.control_plane import app, store

RECOMMENDATION = {
    "action": "clear_fault",
    "target": "inventory",
    "parameters": {"fault": "dependency"},
}


class Ok:
    def raise_for_status(self):
        return None

    def json(self):
        return {"status": "cleared"}


@pytest.fixture
def client(monkeypatch):
    # Live settings for the shared executor, with verification off so no thread outlives a test.
    live = dataclasses.replace(
        control_plane.remediation.settings,
        api_key="test-key",
        remediation_verify_seconds=0,
        remediation_backoff_ms=0,
        remediation_max_attempts=2,
        remediation_max_per_window=50,
    )
    monkeypatch.setattr(control_plane.remediation, "settings", live)
    return TestClient(app)


@pytest.fixture
def calls(monkeypatch):
    sent = []

    def post(url, json, headers=None):
        sent.append(url)
        return Ok()

    monkeypatch.setattr(control_plane.remediation._client, "post", post)
    return sent


def approved(incident_id, root=None, recommendation=RECOMMENDATION):
    store.upsert_incident(incident_id, "t", "high", root or f"service:{incident_id}", {"n": 0})
    approval = {"approver": "op", "approved_at": "2026-01-01T00:00:00+00:00", "recommendation": recommendation}
    store.merge_incident(incident_id, {"recommendation": recommendation, "approval": approval}, status="approved")
    return incident_id


def audit_actions(client, incident_id):
    entries = client.get("/api/audit?limit=200").json()["entries"]
    return [e for e in entries if e.get("incident_id") == incident_id]


def test_execute_returns_the_key_and_a_double_click_is_a_harmless_replay(client, calls):
    approved("inc-api-1")

    first = client.post("/api/incidents/inc-api-1/execute", json={"approver": "op"})
    second = client.post("/api/incidents/inc-api-1/execute", json={"approver": "op"})

    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == "executed"
    assert second.json()["status"] == "already_executed"
    assert second.json()["idempotency_key"] == first.json()["idempotency_key"]
    assert first.json()["attempts"] == 1
    assert len(calls) == 1
    assert [e["action"] for e in audit_actions(client, "inc-api-1")] == ["execute_replayed", "execute"]


def test_a_failed_action_is_a_502_and_is_audited_with_its_attempts(client, monkeypatch):
    approved("inc-api-2")

    def refuse(url, json, headers=None):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(control_plane.remediation._client, "post", refuse)

    response = client.post("/api/incidents/inc-api-2/execute", json={"approver": "op"})

    assert response.status_code == 502
    assert "after 2 attempts" in response.json()["detail"]
    entry = audit_actions(client, "inc-api-2")[0]
    assert (entry["action"], entry["attempts"], entry["outcome"]) == ("execute_failed", 2, "not sent, not applied")
    assert store.get_incident("inc-api-2")["status"] == "approved"


def test_a_refusal_stays_a_409_and_is_audited(client, calls):
    store.upsert_incident("inc-api-3", "t", "high", "service:inc-api-3", {"n": 0})

    response = client.post("/api/incidents/inc-api-3/execute", json={"approver": "op"})

    assert response.status_code == 409
    entry = audit_actions(client, "inc-api-3")[0]
    assert entry["action"] == "execute_refused"
    assert "requires an approved" in entry["reason"]
    assert calls == []


def test_the_per_target_limit_is_a_429_with_retry_after(client, calls, monkeypatch):
    limited = dataclasses.replace(control_plane.remediation.settings, remediation_max_per_window=1)
    monkeypatch.setattr(control_plane.remediation, "settings", limited)
    # The shared store may already hold executions from earlier tests in the window.
    store.db.execute("DELETE FROM remediation_executions")
    store.db.commit()
    approved("inc-api-4")
    approved("inc-api-5")
    assert client.post("/api/incidents/inc-api-4/execute", json={"approver": "op"}).status_code == 200

    response = client.post("/api/incidents/inc-api-5/execute", json={"approver": "op"})

    assert response.status_code == 429
    assert 0 < int(response.headers["Retry-After"]) <= 300
    assert len(calls) == 1
    assert audit_actions(client, "inc-api-5")[0]["action"] == "execute_refused"


def test_dry_run_changes_nothing_and_says_so(client, calls, monkeypatch):
    dry = dataclasses.replace(control_plane.remediation.settings, remediation_dry_run=True)
    monkeypatch.setattr(control_plane.remediation, "settings", dry)
    approved("inc-api-6")

    response = client.post("/api/incidents/inc-api-6/execute", json={"approver": "op"})

    assert response.status_code == 200
    assert response.json()["status"] == "dry_run"
    assert response.json()["result"]["payload"] == {"fault": "dependency"}
    assert calls == []
    assert store.get_incident("inc-api-6")["status"] == "approved"
    assert audit_actions(client, "inc-api-6")[0]["action"] == "execute_dry_run"


def test_approval_refuses_what_the_allowlist_does_not_permit(client, monkeypatch):
    narrow = dataclasses.replace(
        control_plane.remediation.settings, remediation_allowed_actions_raw="checkout:clear_fault"
    )
    monkeypatch.setattr(control_plane.remediation, "settings", narrow)
    store.upsert_incident("inc-api-7", "t", "high", "service:inc-api-7", {"n": 0})
    store.merge_incident("inc-api-7", {"recommendation": RECOMMENDATION}, status="recommendation_pending")

    response = client.post("/api/incidents/inc-api-7/approve", json={"approver": "op"})
    batch = client.post("/api/incidents/batch/approve", json={"approver": "op"})

    assert response.status_code == 400
    assert "not permitted" in response.json()["detail"]
    assert "inc-api-7" not in batch.json()["approved"]
    assert store.get_incident("inc-api-7")["status"] == "recommendation_pending"


def test_the_shared_executor_verifies_and_audits_through_the_control_plane():
    assert control_plane.remediation.telemetry is control_plane.telemetry
    assert control_plane.remediation._audit is control_plane._audit


def test_startup_recovers_executions_then_resumes_verification(monkeypatch):
    order = []
    # The lifespan would start the real engine and close the shared store on exit.
    for target in (control_plane.engine, control_plane.telemetry, control_plane.remediation):
        monkeypatch.setattr(target, "start", lambda: None, raising=False)
        monkeypatch.setattr(target, "stop", lambda: None, raising=False)
        monkeypatch.setattr(target, "close", lambda: None, raising=False)
    monkeypatch.setattr(store, "close", lambda: None)
    monkeypatch.setattr(store, "recover_interrupted_executions", lambda: order.append("recover") or [])
    monkeypatch.setattr(control_plane.remediation, "resume_verifications", lambda: order.append("resume"))

    with TestClient(app):
        pass

    assert order == ["recover", "resume"]
