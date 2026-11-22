"""Checkout's call to inventory: success, upstream 5xx and timeouts, with the metrics each leaves."""

import httpx
import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from aegis import service

DEPENDENCY = "inventory"


@pytest.fixture
def checkout(monkeypatch):
    """The checkout app with its inventory dependency answered by `handler`."""
    real_client = httpx.AsyncClient

    def install(handler):
        def mocked(**kwargs):
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(service, "SERVICE", "checkout")
        monkeypatch.setattr(service, "DEPENDENCY_URL", "http://inventory.test")
        monkeypatch.setattr(service.httpx, "AsyncClient", mocked)
        service.faults.clear()
        return TestClient(service.app)

    return install


def sample(name, **labels):
    return REGISTRY.get_sample_value(name, {"service": "checkout", "dependency": DEPENDENCY, **labels}) or 0.0


def test_a_healthy_inventory_confirms_the_order(checkout):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"sku": "aegis-widget", "available": 42})

    before = sample("aegis_dependency_requests_total", status="200")

    response = checkout(handler).get("/api/checkout")

    assert response.status_code == 200
    assert response.json()["status"] == "confirmed"
    assert seen == ["http://inventory.test/api/inventory"]
    assert sample("aegis_dependency_requests_total", status="200") == before + 1


@pytest.mark.parametrize("upstream", [500, 503])
def test_an_inventory_5xx_is_a_502_and_counts_as_an_upstream_error(checkout, upstream):
    errors = sample("aegis_dependency_errors_total", reason="upstream_5xx")
    requests = sample("aegis_dependency_requests_total", status=str(upstream))
    latency = sample("aegis_dependency_request_duration_seconds_count")

    response = checkout(lambda request: httpx.Response(upstream)).get("/api/checkout")

    assert response.status_code == 502
    assert response.json() == {"error": "inventory dependency failed"}
    assert sample("aegis_dependency_errors_total", reason="upstream_5xx") == errors + 1
    assert sample("aegis_dependency_requests_total", status=str(upstream)) == requests + 1
    assert sample("aegis_dependency_request_duration_seconds_count") == latency + 1


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ReadTimeout("read timed out"),
        httpx.ConnectTimeout("connect timed out"),
        httpx.ConnectError("connection refused"),
    ],
    ids=["read-timeout", "connect-timeout", "connect-error"],
)
def test_an_unreachable_or_slow_inventory_is_a_504_and_counts_as_a_timeout(checkout, failure):
    errors = sample("aegis_dependency_errors_total", reason="timeout")
    requests = sample("aegis_dependency_requests_total", status="timeout")
    latency = sample("aegis_dependency_request_duration_seconds_count")

    def handler(request):
        raise failure

    response = checkout(handler).get("/api/checkout")

    assert response.status_code == 504
    assert response.json() == {"error": "inventory dependency timed out"}
    assert sample("aegis_dependency_errors_total", reason="timeout") == errors + 1
    assert sample("aegis_dependency_requests_total", status="timeout") == requests + 1
    assert sample("aegis_dependency_request_duration_seconds_count") == latency + 1

