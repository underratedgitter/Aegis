"""The control plane reports engine health and exposes its own Prometheus metrics."""

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from aegis import control_plane
from aegis.breaker import BreakerStatus
from aegis.supervisor import EngineStatus


def _status(state="ok", reason=None, **overrides):
    values = {
        "state": state,
        "reason": reason,
        "running": state != "stopped",
        "poll_seconds": 5,
        "cycle_timeout_seconds": 60,
        "stale_after_seconds": 75,
        "last_success_at": "2026-01-01T00:00:00+00:00",
        "last_success_age_seconds": 2.0,
        "last_error": "RuntimeError: secret-detail",
        "consecutive_failures": 0,
        "cycles_total": 10,
        "failures_total": 1,
        "breakers": {"prometheus": BreakerStatus(state="closed", consecutive_failures=0)},
    }
    return EngineStatus(**{**values, **overrides})


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(
        control_plane.telemetry, "prometheus_query", lambda q: {"value": 1.0}
    )
    monkeypatch.setattr(
        control_plane.telemetry, "loki_status", lambda: control_plane.TelemetryStatus(available=True)
    )
    monkeypatch.setattr(type(control_plane.engine), "is_running", True)
    return TestClient(control_plane.app)


def _engine_reports(monkeypatch, status):
    monkeypatch.setattr(control_plane.engine, "status", lambda: status)


class TestReadiness:
    def test_a_stalled_engine_makes_the_service_unavailable_with_a_reason(self, client, monkeypatch):
        _engine_reports(
            monkeypatch,
            _status("stalled", "no successful cycle for 90s (limit 75s)", consecutive_failures=4),
        )

        response = client.get("/readyz")

        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "unavailable"
        assert body["checks"]["engine"] == "stalled"
        assert body["checks"]["engine_reason"] == "no successful cycle for 90s (limit 75s)"
        assert "secret-detail" not in response.text

    def test_a_failing_engine_with_a_fresh_heartbeat_is_degraded_but_ready(self, client, monkeypatch):
        _engine_reports(monkeypatch, _status("degraded", "2 consecutive cycle failures"))

        response = client.get("/readyz")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["engine"] == "degraded"
        assert body["checks"]["engine_reason"] == "2 consecutive cycle failures"

    def test_a_healthy_engine_adds_no_reason(self, client, monkeypatch):
        _engine_reports(monkeypatch, _status())

        body = client.get("/readyz").json()

        assert body["checks"]["engine"] == "ok"
        assert "engine_reason" not in body["checks"]


class TestEngineStatusEndpoint:
    def test_reports_the_heartbeat_and_backend_breakers(self, client):
        response = client.get("/api/engine/status")

        assert response.status_code == 200
        body = response.json()
        assert set(body) >= {
            "state", "reason", "running", "last_success_at", "last_error",
            "consecutive_failures", "stale_after_seconds", "breakers",
        }
        assert set(body["breakers"]) == {"prometheus", "loki", "llm"}
        assert body["breakers"]["llm"]["state"] == "closed"

    def test_returns_the_supervisor_status_verbatim(self, client, monkeypatch):
        _engine_reports(monkeypatch, _status("degraded", "1 consecutive cycle failure"))

        body = client.get("/api/engine/status").json()

        assert body["state"] == "degraded"
        assert body["last_error"] == "RuntimeError: secret-detail"


def _sample(name, labels=None):
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


class TestMetricsEndpoint:
    def test_is_served_in_prometheus_format_and_hidden_from_the_schema(self, client):
        response = client.get("/metrics")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "/metrics" not in control_plane.app.openapi()["paths"]

    def test_exposes_the_engine_self_observability_series(self, client):
        text = client.get("/metrics").text

        for name in (
            "aegis_engine_cycle_seconds_bucket",
            "aegis_engine_up",
            "aegis_engine_consecutive_failures",
            "aegis_incidents_open",
            "aegis_remediation_executions_total",
            'aegis_breaker_open{backend="prometheus"}',
            'aegis_breaker_open{backend="llm"}',
        ):
            assert name in text, name

    def test_engine_state_is_reflected(self, client, monkeypatch):
        _engine_reports(monkeypatch, _status("stalled", "x", consecutive_failures=3))

        text = client.get("/metrics").text

        assert "aegis_engine_up 0.0" in text
        assert "aegis_engine_consecutive_failures 3.0" in text
        assert "aegis_engine_last_success_age_seconds 2.0" in text

    def test_open_breakers_are_flagged(self, client, monkeypatch):
        breakers = {
            "prometheus": BreakerStatus(state="open", consecutive_failures=1, retry_in_seconds=5),
            "loki": BreakerStatus(state="closed", consecutive_failures=0),
        }
        _engine_reports(monkeypatch, _status(breakers=breakers))

        text = client.get("/metrics").text

        assert 'aegis_breaker_open{backend="prometheus"} 1.0' in text
        assert 'aegis_breaker_open{backend="loki"} 0.0' in text

    def test_counts_open_incidents_and_executions_by_result(self, client):
        store = control_plane.store
        open_before = _sample("aegis_incidents_open")
        ok_before = _sample("aegis_remediation_executions_total", {"result": "executed"})
        failed_before = _sample("aegis_remediation_executions_total", {"result": "failed"})
        store.upsert_incident("inc-metrics-1", "t", "high", "service:metrics", {"value": 1})
        store.add_event("inc-metrics-1", "remediation_executed", "done")
        store.add_event("inc-metrics-1", "remediation_failed", "nope")
        store.add_event("inc-metrics-1", "remediation_failed", "nope again")
        store.add_event("inc-metrics-1", "note", "unrelated")

        assert _sample("aegis_incidents_open") == open_before + 1
        assert _sample("aegis_remediation_executions_total", {"result": "executed"}) == ok_before + 1
        assert _sample("aegis_remediation_executions_total", {"result": "failed"}) == failed_before + 2

        store.update_incident("inc-metrics-1", status="resolved")
        assert _sample("aegis_incidents_open") == open_before
