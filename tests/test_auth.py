"""Bearer headers must match the key the demo service admin routes accept."""

import pytest
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.auth import bearer_header
from aegis.control_plane import app as control_app
from aegis.service import app as service_app
from aegis.service import faults


def test_bearer_header_is_exact():
    assert bearer_header("test-key") == {"Authorization": "Bearer test-key"}


@pytest.mark.parametrize("key", ["", "   "])
def test_bearer_header_rejects_an_empty_key(key):
    with pytest.raises(ValueError, match="non-empty"):
        bearer_header(key)


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"status": "injected"}


def test_control_plane_chaos_forwards_the_configured_key(monkeypatch):
    monkeypatch.setattr(control_plane, "API_KEY", "test-key")
    calls = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url, json, headers))
        return FakeResponse()

    monkeypatch.setattr(control_plane.httpx, "post", fake_post)
    response = TestClient(control_app).post(
        "/api/chaos",
        json={"service": "inventory", "fault": "dependency"},
        headers={"Authorization": "Bearer test-key"},
    )

    assert response.status_code == 200
    assert calls == [
        (
            "http://localhost:8081/admin/faults",
            {"fault": "dependency", "duration_seconds": 60.0, "intensity": 1.0},
            {"Authorization": "Bearer test-key"},
        )
    ]


def test_demo_admin_route_accepts_the_key_the_control_plane_forwards(monkeypatch):
    """End-to-end: control-plane chaos -> demo service admin route, no 401."""
    monkeypatch.setenv("AEGIS_API_KEY", "test-key")
    monkeypatch.setattr(control_plane, "API_KEY", "test-key")
    service_client = TestClient(service_app)

    def post_to_service(url, json=None, headers=None, timeout=None):
        assert url == "http://localhost:8080/admin/faults"
        response = service_client.post("/admin/faults", json=json, headers=headers)
        response.raise_for_status()
        return response

    monkeypatch.setattr(control_plane.httpx, "post", post_to_service)
    try:
        response = TestClient(control_app).post(
            "/api/chaos",
            json={"service": "checkout", "fault": "latency", "duration_seconds": 1},
            headers={"Authorization": "Bearer test-key"},
        )

        assert response.status_code == 200, response.text
        assert response.json()["result"]["injected"]["fault"] == "latency"
    finally:
        faults.clear("latency")
