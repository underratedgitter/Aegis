"""The audit log is durable: it lives in SQLite, survives restarts, and is paged and filtered in SQL."""

import pytest
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.control_plane import app, store
from aegis.storage import Store

RECOMMENDATION = {"action": "clear_fault", "target": "inventory", "parameters": {"fault": "dependency"}}


@pytest.fixture
def client():
    return TestClient(app)


def mine(client, **params):
    """The /api/audit response for the given filters."""
    response = client.get("/api/audit", params={"limit": 200, **params})
    assert response.status_code == 200
    return response.json()


class TestStoreAudit:
    def test_entries_survive_a_restart_and_are_not_capped(self, tmp_path):
        path = str(tmp_path / "aegis.db")
        first = Store(path)
        for n in range(1200):
            first.add_audit("approve", {"incident_id": "inc-1", "approver": "op", "n": n})
        first.close()

        reopened = Store(path)
        try:
            entries, total = reopened.audit_entries(limit=5)
        finally:
            reopened.close()

        assert total == 1200
        assert [e["n"] for e in entries] == [1199, 1198, 1197, 1196, 1195]

    def test_entry_is_flat_and_carries_who_and_where(self, tmp_path):
        store = Store(str(tmp_path / "aegis.db"))
        store.add_audit(
            "approve",
            {"incident_id": "inc-1", "approver": "ops", "extra": 7},
            client_ip="10.0.0.9",
            request_id="req-1",
        )
        entries, _ = store.audit_entries()
        store.close()

        entry = entries[0]
        assert entry["action"] == "approve"
        assert entry["incident_id"] == "inc-1"
        assert entry["approver"] == "ops"
        assert entry["extra"] == 7
        assert entry["client_ip"] == "10.0.0.9"
        assert entry["request_id"] == "req-1"
        assert entry["at"]

    def test_paging_and_filters_are_applied_in_sql(self, tmp_path):
        store = Store(str(tmp_path / "aegis.db"))
        for n in range(6):
            store.add_audit("approve", {"incident_id": "inc-a", "approver": "alice", "n": n})
        for n in range(4):
            store.add_audit("execute", {"incident_id": "inc-b", "approver": "bob", "n": n})

        page, total = store.audit_entries(limit=3, offset=2, action="approve")
        assert (total, [e["n"] for e in page]) == (6, [3, 2, 1])
        assert store.audit_entries(incident_id="inc-b")[1] == 4
        assert store.audit_entries(approver="alice", action="execute")[1] == 0
        assert store.audit_entries()[1] == 10
        store.close()


class TestAuditApi:
    def test_approval_is_recorded_with_client_ip_and_request_id(self, client):
        store.upsert_incident("inc-audit-1", "t", "high", "service:audit-1", {"n": 0})
        store.merge_incident(
            "inc-audit-1", {"recommendation": RECOMMENDATION}, status="recommendation_pending"
        )

        response = client.post(
            "/api/incidents/inc-audit-1/approve",
            json={"approver": "ops"},
            headers={"X-Request-Id": "req-abc"},
        )

        assert response.status_code == 200
        [entry] = mine(client, incident_id="inc-audit-1")["entries"]
        assert entry["action"] == "approve"
        assert entry["approver"] == "ops"
        assert entry["request_id"] == "req-abc"
        assert entry["client_ip"] == "testclient"

    def test_manual_investigation_is_audited(self, client, monkeypatch):
        store.upsert_incident("inc-audit-2", "t", "high", "service:audit-2", {"n": 0})
        result = {"mode": "local_fallback", "hypothesis": "h", "confidence": "low"}
        monkeypatch.setattr(control_plane.agent, "investigate", lambda incident_id: result)

        assert client.post("/api/incidents/inc-audit-2/investigate").status_code == 200

        [entry] = mine(client, incident_id="inc-audit-2")["entries"]
        assert entry["action"] == "investigate"
        assert entry["request_id"]

    def test_engine_run_once_is_audited(self, client, monkeypatch):
        monkeypatch.setattr(control_plane.engine, "run_once", lambda: [{"id": "a"}, {"id": "b"}])
        before = mine(client, action="engine_run_once")["total"]

        assert client.post("/api/engine/run-once").status_code == 200

        body = mine(client, action="engine_run_once")
        assert body["total"] == before + 1
        assert body["entries"][0]["fired"] == 2

    def test_audit_is_paged_and_filtered_by_the_server(self, client):
        for n in range(5):
            store.add_audit("probe_action", {"incident_id": "inc-audit-3", "n": n})

        body = mine(client, action="probe_action", limit=2, offset=1)

        assert body["total"] >= 5
        assert (body["limit"], body["offset"]) == (2, 1)
        assert [e["n"] for e in body["entries"]] == [3, 2]

    def test_a_negative_offset_is_rejected(self, client):
        assert client.get("/api/audit?offset=-1").status_code == 422

    def test_audit_entries_come_from_the_database_not_process_memory(self):
        assert not hasattr(control_plane, "_audit_log")
