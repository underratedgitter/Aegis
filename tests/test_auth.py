"""Bearer headers must match the key the demo service admin routes accept."""

import time

import pytest
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.auth import AuthFailureLimiter, bearer_header, presented_token, token_matches
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


class TestAuthFailureLimiter:
    def test_clients_under_the_limit_are_not_locked(self):
        limiter = AuthFailureLimiter(3, 60)
        for _ in range(2):
            limiter.record_failure("198.51.100.1")
        assert limiter.retry_after("198.51.100.1") == 0

    def test_lockout_reports_a_bounded_retry_after(self):
        limiter = AuthFailureLimiter(3, 60)
        for _ in range(3):
            limiter.record_failure("198.51.100.1")
        assert 1 <= limiter.retry_after("198.51.100.1") <= 60

    def test_clients_are_tracked_independently(self):
        limiter = AuthFailureLimiter(1, 60)
        limiter.record_failure("198.51.100.1")
        assert limiter.retry_after("198.51.100.2") == 0

    def test_lockout_expires_with_the_window(self):
        limiter = AuthFailureLimiter(1, 0.05)
        limiter.record_failure("198.51.100.1")
        assert limiter.retry_after("198.51.100.1") > 0
        time.sleep(0.06)
        assert limiter.retry_after("198.51.100.1") == 0

    def test_reset_clears_all_state(self):
        limiter = AuthFailureLimiter(1, 60)
        limiter.record_failure("198.51.100.1")
        limiter.reset()
        assert limiter.retry_after("198.51.100.1") == 0

    def test_idle_clients_are_evicted(self):
        limiter = AuthFailureLimiter(5, 0.01)
        for i in range(AuthFailureLimiter.MAX_TRACKED_CLIENTS + 200):
            limiter.record_failure(f"10.0.{i // 250}.{i % 250}")
            if i == AuthFailureLimiter.MAX_TRACKED_CLIENTS - 1:
                time.sleep(0.02)
        assert len(limiter._failures) < AuthFailureLimiter.MAX_TRACKED_CLIENTS


class TestTokenHelpers:
    @pytest.mark.parametrize("header", ["", "test-key", "Basic abc", "Bearer ", "bearer abc"])
    def test_no_bearer_token_is_presented(self, header):
        assert presented_token(header) is None

    def test_bearer_token_is_extracted(self):
        assert presented_token("Bearer abc def") == "abc def"

    def test_token_comparison_is_exact_and_handles_non_ascii(self):
        assert token_matches("abc", "abc")
        assert not token_matches("abd", "abc")
        assert not token_matches("caf\u00e9", "cafe")
