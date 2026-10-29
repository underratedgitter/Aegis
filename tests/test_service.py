import asyncio
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from aegis.service import (
    CPU_BURN_ACTIVE,
    FAULT_ACTIVE,
    SERVICE,
    FaultRequest,
    FaultState,
    ScaleRequest,
    app,
    metrics,
)


def test_metrics_endpoint_is_scrapeable_without_a_redirect():
    response = asyncio.run(metrics())

    assert response.status_code == 200
    assert b"aegis_http_requests_total" in response.body


def test_service_chaos_inputs_are_bounded():
    with pytest.raises(ValidationError):
        FaultRequest(fault="dependency", duration_seconds=901)
    with pytest.raises(ValidationError):
        ScaleRequest(replicas=4)

    state = FaultState()
    injected = state.inject("dependency", duration=9999, intensity=99)
    assert injected["duration_seconds"] == 900
    assert injected["intensity"] == 10
    state.clear("not-a-fault")
    assert "dependency" in state.snapshot()
    state.clear()
    assert state.snapshot() == {}


def _gauge(gauge, *labels):
    return gauge.labels(*labels)._value.get()


def test_admin_routes_require_the_shared_key(monkeypatch):
    monkeypatch.setenv("AEGIS_API_KEY", "test-key")
    client = TestClient(app)

    assert client.get("/admin/faults").status_code == 401
    assert client.post("/admin/faults", json={"fault": "latency"}).status_code == 401
    assert client.post("/admin/scale", json={"replicas": 2}).status_code == 401

    headers = {"Authorization": "Bearer test-key"}
    assert client.get("/admin/faults", headers=headers).status_code == 200
    injected = client.post(
        "/admin/faults",
        json={"fault": "latency", "duration_seconds": 1},
        headers=headers,
    )
    assert injected.status_code == 200
    assert client.post("/admin/faults/clear", json={}, headers=headers).status_code == 200


def test_admin_routes_fail_closed_without_a_key(monkeypatch):
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    client = TestClient(app)

    response = client.get("/admin/faults")
    assert response.status_code == 503
    assert "AEGIS_API_KEY" in response.json()["detail"]


def test_cpu_fault_expires_and_resets_gauges():
    state = FaultState()
    try:
        state.inject("cpu", duration=1, intensity=1)
        assert "cpu" in state.snapshot()
        assert _gauge(FAULT_ACTIVE, SERVICE, "cpu") == 1
        assert _gauge(CPU_BURN_ACTIVE, SERVICE) == 1

        time.sleep(1.2)

        assert "cpu" not in state.snapshot()
        assert _gauge(FAULT_ACTIVE, SERVICE, "cpu") == 0
        assert _gauge(CPU_BURN_ACTIVE, SERVICE) == 0
    finally:
        state.clear()


def test_clear_stops_the_cpu_burner():
    state = FaultState()
    state.inject("cpu", duration=60, intensity=1)
    stop_event = state._stop_events["cpu"]

    state.clear("cpu")

    assert stop_event.is_set()
    assert state.snapshot() == {}
    assert _gauge(CPU_BURN_ACTIVE, SERVICE) == 0


def test_repeated_cpu_injection_replaces_the_previous_burner():
    state = FaultState()
    try:
        state.inject("cpu", duration=60, intensity=1)
        first = state._stop_events["cpu"]
        state.inject("cpu", duration=60, intensity=2)
        second = state._stop_events["cpu"]

        assert first.is_set()
        assert second is not first
    finally:
        state.clear()
