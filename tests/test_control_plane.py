"""Tests for control plane API endpoints."""

import pytest
from fastapi.testclient import TestClient

from aegis.control_plane import app, store


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
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_incident(self, client, sample_incident):
        response = client.get("/api/incidents/inc-test-1")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "inc-test-1"
        assert "events" in data

    def test_get_nonexistent_incident(self, client):
        response = client.get("/api/incidents/nonexistent")
        assert response.status_code == 404


class TestChaosEndpoint:
    def test_chaos_injection(self, client):
        # Mock the service response
        from unittest.mock import MagicMock, patch

        mock_response = MagicMock()
        mock_response.json.return_value = {"fault": "latency", "status": "injected"}
        mock_response.raise_for_status = MagicMock()

        with patch("aegis.control_plane.httpx.post", return_value=mock_response):
            response = client.post(
                "/api/chaos",
                json={
                    "service": "checkout",
                    "fault": "latency",
                    "duration_seconds": 10,
                    "intensity": 1.0,
                },
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "injected"

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

    def test_logs_with_limit(self, client):
        response = client.get("/api/logs?limit=10")
        assert response.status_code == 200


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
