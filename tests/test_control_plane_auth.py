"""Tests that the bearer-token guard is actually enforced on state-changing routes."""

import pytest
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.control_plane import app

# (method, path) pairs that must require a key once one is configured.
PROTECTED_ROUTES = [
    ("post", "/api/incidents/inc-auth-1/investigate"),
    ("post", "/api/incidents/inc-auth-1/approve"),
    ("post", "/api/incidents/inc-auth-1/execute"),
    ("post", "/api/incidents/batch/approve"),
    ("post", "/api/chaos"),
    ("post", "/api/engine/run-once"),
    ("get", "/api/audit"),
]

# Read-only routes stay open so the control room renders without a key.
PUBLIC_ROUTES = [
    ("get", "/healthz"),
    ("get", "/api/incidents"),
]


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def with_api_key(monkeypatch):
    """Configure a key the way AEGIS_API_KEY would at startup."""
    monkeypatch.setattr(control_plane, "API_KEY", "test-key")
    return "test-key"


def _call(client, method, path, headers=None):
    """GET has no request body; only POST routes take one."""
    if method == "get":
        return client.get(path, headers=headers)
    return client.post(path, json={}, headers=headers)


class TestAuthDisabledByDefault:
    def test_no_key_configured_leaves_routes_open(self, client, monkeypatch):
        """The local demo must run with no configuration at all."""
        monkeypatch.setattr(control_plane, "API_KEY", "")
        response = client.post("/api/engine/run-once")
        assert response.status_code != 401


class TestAuthEnforced:
    @pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
    def test_missing_key_is_rejected(self, client, with_api_key, method, path):
        assert _call(client, method, path).status_code == 401

    @pytest.mark.parametrize("method,path", PROTECTED_ROUTES)
    def test_wrong_key_is_rejected(self, client, with_api_key, method, path):
        response = _call(client, method, path, headers={"Authorization": "Bearer wrong"})
        assert response.status_code == 401

    def test_malformed_header_is_rejected(self, client, with_api_key):
        response = client.post(
            "/api/engine/run-once", headers={"Authorization": "test-key"}
        )
        assert response.status_code == 401

    def test_correct_key_is_accepted(self, client, with_api_key):
        response = client.post(
            "/api/engine/run-once", headers={"Authorization": f"Bearer {with_api_key}"}
        )
        assert response.status_code == 200

    @pytest.mark.parametrize("method,path", PUBLIC_ROUTES)
    def test_read_only_routes_stay_public(self, client, with_api_key, method, path):
        assert _call(client, method, path).status_code == 200
