"""Tests for control plane API endpoints."""

import pytest
from fastapi.testclient import TestClient

from aegis.control_plane import app, store
from aegis.storage import utc_now


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


@pytest.fixture
def sample_incident():
    """Create a sample incident for testing."""
    incident, _ = store.upsert_incident(
        "inc-test-1",
        "Test Incident",
        "high",
        "service:test",
        {"rule": "test", "value": 1.0},
    )
    return incident


class TestHealthEndpoint:
    def test_healthz(self, client):
        response = client.get("/healthz")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "aegis-control-plane"


class TestOverviewEndpoint:
    def test_overview(self, client):
        response = client.get("/api/overview")
        assert response.status_code == 200
        data = response.json()
        assert "incidents" in data
        assert "open_incidents" in data
        assert "mttr_seconds" in data
        assert "services" in data
        assert "telemetry" in data


class TestIncidentsEndpoint:
    def test_list_incidents(self, client, sample_incident):
        response = client.get("/api/incidents")
        assert response.status_code == 200
        data = response.json()
        assert "incidents" in data
        assert "pagination" in data
        assert isinstance(data["incidents"], list)
        assert len(data["incidents"]) >= 1

    def test_list_incidents_with_pagination(self, client, sample_incident):
        response = client.get("/api/incidents?page=1&limit=5")
        assert response.status_code == 200
        data = response.json()
        assert data["pagination"]["page"] == 1
        assert data["pagination"]["limit"] == 5

    def test_list_incidents_with_status_filter(self, client, sample_incident):
        response = client.get("/api/incidents?status=open")
        assert response.status_code == 200
        data = response.json()
        assert all(i["status"] == "open" for i in data["incidents"])

    def test_list_incidents_with_search(self, client, sample_incident):
        response = client.get("/api/incidents?search=test")
        assert response.status_code == 200
        data = response.json()
        assert len(data["incidents"]) >= 1

    def test_get_incident(self, client, sample_incident):
        response = client.get("/api/incidents/inc-test-1")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "inc-test-1"
        assert "events" in data

    def test_get_nonexistent_incident(self, client):
        response = client.get("/api/incidents/nonexistent")
        assert response.status_code == 404


class TestAuditEndpoint:
    def test_audit_log(self, client):
        response = client.get("/api/audit")
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data
        assert "total" in data


class TestExportEndpoint:
    def test_export_json(self, client):
        response = client.get("/api/incidents/export?format=json")
        assert response.status_code == 200
        data = response.json()
        assert "incidents" in data
        assert "exported_at" in data

    def test_export_csv(self, client):
        response = client.get("/api/incidents/export?format=csv")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"


class TestChaosEndpoint:
    def test_chaos_invalid_service(self, client):
        response = client.post(
            "/api/chaos",
            json={"service": "invalid", "fault": "latency"},
        )
        assert response.status_code == 422


class TestMetricsEndpoint:
    def test_metrics(self, client):
        response = client.get("/api/metrics")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestLogsEndpoint:
    def test_logs(self, client):
        response = client.get("/api/logs")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestRunbooksEndpoint:
    def test_runbooks(self, client):
        response = client.get("/api/runbooks")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestEngineEndpoint:
    def test_run_engine_once(self, client):
        response = client.post("/api/engine/run-once")
        assert response.status_code == 200
        data = response.json()
        assert "fired" in data


class TestInvestigateResolvedIncident:
    def test_resolved_incident_is_not_reopened_by_investigation(self, client):
        store.upsert_incident("inc-resolved-1", "Done", "high", "service:resolved", {"v": 1})
        store.update_incident("inc-resolved-1", status="resolved", resolved_at=utc_now())

        response = client.post("/api/incidents/inc-resolved-1/investigate")

        assert response.status_code == 409
        assert store.get_incident("inc-resolved-1")["status"] == "resolved"


class TestInvestigateMalformedLlmOutput:
    def test_malformed_llm_answer_returns_a_valid_local_investigation(self, client, monkeypatch):
        from aegis.control_plane import agent

        store.upsert_incident("inc-llm-bad", "Bad LLM", "high", "service:llm-bad", {"v": 1})
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setattr(agent, "_llm_investigation", lambda incident: {"hypothesis": "h"})

        response = client.post("/api/incidents/inc-llm-bad/investigate")

        assert response.status_code == 200
        assert response.json()["investigation"]["mode"] == "local_fallback"


class TestStartupRecovery:
    def test_incident_stuck_executing_is_returned_to_approved_on_startup(self, monkeypatch):
        from aegis import control_plane

        # The lifespan would start the real engine and close the shared store on exit.
        for target in (control_plane.engine, control_plane.telemetry, control_plane.remediation):
            monkeypatch.setattr(target, "start", lambda: None, raising=False)
            monkeypatch.setattr(target, "stop", lambda: None, raising=False)
            monkeypatch.setattr(target, "close", lambda: None, raising=False)
        monkeypatch.setattr(store, "close", lambda: None)
        store.upsert_incident("inc-crashed", "Crashed", "high", "service:crashed", {"v": 1})
        store.update_incident("inc-crashed", status="executing")

        with TestClient(app):
            assert store.get_incident("inc-crashed")["status"] == "approved"

        assert store.events("inc-crashed")[-1]["kind"] == "recovery"
