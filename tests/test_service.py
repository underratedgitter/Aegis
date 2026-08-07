import asyncio

import pytest
from pydantic import ValidationError

from aegis.service import FaultRequest, FaultState, ScaleRequest, metrics


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
