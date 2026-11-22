"""Tests that the bearer-token guard is actually enforced on state-changing routes."""

from pathlib import Path

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


@pytest.fixture(autouse=True)
def _fresh_lockout_state():
    """Failed attempts from one test must not lock out the next."""
    control_plane._auth_failures.reset()
    yield
    control_plane._auth_failures.reset()


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


class TestAuthNotConfigured:
    def test_read_only_routes_stay_public(self, client, monkeypatch):
        """The dashboard still renders without a key."""
        monkeypatch.setattr(control_plane, "API_KEY", "")
        assert client.get("/api/incidents").status_code == 200

    def test_fault_injection_is_disabled(self, client, monkeypatch):
        """Fault injection must fail closed when no admin key exists."""
        monkeypatch.setattr(control_plane, "API_KEY", "")
        response = client.post(
            "/api/chaos",
            json={"service": "checkout", "fault": "latency"},
        )
        assert response.status_code == 503
        assert "AEGIS_API_KEY" in response.json()["detail"]


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


class TestBatchApproveRouting:
    def test_batch_approve_is_not_shadowed_by_incident_id_route(self, client, with_api_key):
        """/batch/approve must not be captured as incident_id="batch" (404)."""
        recommendation = {
            "action": "clear_fault",
            "target": "checkout",
            "parameters": {"fault": "latency"},
        }
        incident, _ = control_plane.store.upsert_incident(
            "inc-batch-1", "Batch", "high", "service:batch", {"rule": "r"}
        )
        control_plane.store.update_incident(
            incident["id"],
            status="recommendation_pending",
            data={**incident["data"], "recommendation": recommendation},
        )

        response = client.post(
            "/api/incidents/batch/approve",
            json={"approver": "tester"},
            headers={"Authorization": f"Bearer {with_api_key}"},
        )

        assert response.status_code != 404
        assert response.status_code == 200
        assert "inc-batch-1" in response.json()["approved"]
        assert control_plane.store.get_incident("inc-batch-1")["status"] == "approved"


class TestWebUiSendsKey:
    """The UI has no JS test harness, so check the shipped script statically."""

    APP_JS = (Path(control_plane.__file__).parent / "static" / "app.js").read_text()

    def test_write_calls_send_bearer_header(self):
        assert "Authorization = `Bearer ${key}`" in self.APP_JS
        # Every POST is built by postOptions, which attaches the header, and every write in the
        # UI goes through the single post() helper that uses it.
        assert self.APP_JS.count('method: "POST"') == 1
        assert self.APP_JS.count("getJson(url, postOptions(body))") >= 1
        assert self.APP_JS.count("await post(") >= 4
        # The protected audit GET carries the header too.
        assert "headers: authHeaders()" in self.APP_JS

    def test_key_is_kept_out_of_urls_and_persistent_storage(self):
        assert "localStorage" not in self.APP_JS
        assert "sessionStorage" in self.APP_JS


class TestNonAsciiToken:
    def test_non_ascii_bearer_token_is_rejected_with_401(self, client, with_api_key):
        """compare_digest raises TypeError on non-ASCII str; that must not become a 500."""
        response = client.get(
            "/api/audit", headers={"Authorization": "Bearer caf\u00e9".encode("latin-1")}
        )
        assert response.status_code == 401


class TestWebUiHandlesExecutingStatus:
    """The UI has no JS test harness, so check the shipped assets statically."""

    STATIC = Path(control_plane.__file__).parent / "static"

    def test_status_filter_offers_executing(self):
        assert '<option value="executing">' in (self.STATIC / "index.html").read_text()

    def test_executing_status_is_styled(self):
        assert ".status-executing" in (self.STATIC / "styles.css").read_text()

    def test_action_buttons_are_only_offered_in_their_own_status(self):
        app_js = (self.STATIC / "app.js").read_text()
        # Buttons are delegated (data-action), not inline handlers, and gated on status.
        assert 'const pending = incident.status === "recommendation_pending"' in app_js
        assert 'const approved = incident.status === "approved"' in app_js
        assert 'pending ? actionButton("approve"' in app_js
        assert 'approved ? actionButton("execute"' in app_js
