"""Approval writes merge atomically instead of writing back a stale incident snapshot."""

import threading

import pytest
from fastapi.testclient import TestClient

from aegis.control_plane import app, store

RECOMMENDATION = {
    "action": "clear_fault",
    "target": "inventory",
    "parameters": {"fault": "dependency"},
}


@pytest.fixture
def pending():
    incident_id = "inc-approve-merge"
    store.upsert_incident(incident_id, "t", "high", "service:approve-merge", {"n": 0})
    store.merge_incident(incident_id, {"recommendation": RECOMMENDATION}, status="recommendation_pending")
    return incident_id


def test_approval_keeps_evidence_appended_after_the_read(pending, monkeypatch):
    real_get = store.get_incident

    def get_then_signal(incident_id):
        snapshot = real_get(incident_id)
        monkeypatch.setattr(store, "get_incident", real_get)
        # A signal lands between the endpoint's read and its write.
        store.upsert_incident("x", "t", "high", "service:approve-merge", {"n": 1})
        return snapshot

    monkeypatch.setattr(store, "get_incident", get_then_signal)

    response = TestClient(app).post(f"/api/incidents/{pending}/approve", json={"approver": "op"})

    assert response.status_code == 200
    data = real_get(pending)["data"]
    assert [item["n"] for item in data["evidence"]] == [0, 1]
    assert data["approval"]["approver"] == "op"


def test_concurrent_approvals_succeed_exactly_once(pending):
    client = TestClient(app)
    codes: list[int] = []

    def approve():
        codes.append(client.post(f"/api/incidents/{pending}/approve", json={"approver": "op"}).status_code)

    threads = [threading.Thread(target=approve) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert sorted(codes) == [200] + [409] * 5
