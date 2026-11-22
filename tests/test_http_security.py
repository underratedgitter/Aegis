"""Tests for security headers, CORS, request size limits and failed-auth lockout."""

import logging
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegis import control_plane, service
from aegis.auth import AuthFailureLimiter
from aegis.http_security import UI_CSP, BodyLimitMiddleware
from aegis.settings import Settings

STATIC = Path(control_plane.__file__).parent / "static"
EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


@pytest.fixture(autouse=True)
def _fresh_limiter_state():
    """Per-client counters are process-global; start each test from zero."""
    control_plane._rate_limits.clear()
    control_plane._auth_failures.reset()
    yield
    control_plane._rate_limits.clear()
    control_plane._auth_failures.reset()


@pytest.fixture
def client():
    return TestClient(control_plane.app)


@pytest.fixture
def with_api_key(monkeypatch):
    monkeypatch.setattr(control_plane, "API_KEY", "test-key")
    monkeypatch.setattr(control_plane, "_auth_failures", AuthFailureLimiter(3, 60))
    return "test-key"


def assert_hardened(response):
    for name, value in EXPECTED_HEADERS.items():
        assert response.headers[name] == value
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


class TestSecurityHeaders:
    @pytest.mark.parametrize("path", ["/", "/healthz", "/api/incidents", "/static/app.js", "/static/nope", "/nope"])
    def test_every_get_response_is_hardened(self, client, path):
        assert_hardened(client.get(path))

    def test_validation_and_auth_errors_are_hardened(self, client, with_api_key):
        assert_hardened(client.post("/api/chaos", json={}))
        assert_hardened(client.post("/api/engine/run-once"))

    def test_rate_limit_responses_are_hardened(self, client, monkeypatch):
        monkeypatch.setattr(control_plane, "RATE_LIMIT_MAX_REQUESTS", 0)
        response = client.get("/api/incidents")
        assert response.status_code == 429
        assert_hardened(response)

    def test_unhandled_errors_are_generic_and_hardened(self, monkeypatch):
        def boom(*_args, **_kwargs):
            raise RuntimeError("secret internal detail")

        monkeypatch.setattr(control_plane.store, "list_incidents", boom)
        response = TestClient(control_plane.app, raise_server_exceptions=False).get("/api/incidents")
        assert response.status_code == 500
        assert response.json() == {"detail": "Internal server error."}
        assert_hardened(response)

    def test_ui_policy_has_no_inline_script_or_style_elements(self):
        policy = dict(item.split(" ", 1) for item in UI_CSP.split("; "))
        assert "'unsafe-inline'" not in policy["script-src"]
        assert "'unsafe-inline'" not in policy["style-src"]
        assert policy["default-src"] == "'self'"
        assert policy["object-src"] == "'none'"

    def test_ui_assets_only_need_what_the_policy_allows(self):
        """The control room must keep working: no inline elements, no foreign origins."""
        html = (STATIC / "index.html").read_text()
        app_js = (STATIC / "app.js").read_text()
        css = (STATIC / "styles.css").read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)", html)
        assert "<style" not in html
        assert not re.search(r"(?:src|href)=[\"']https?:", html)
        assert "eval(" not in app_js
        assert "new Function" not in app_js
        assert "javascript:" not in html + app_js
        assert not re.search(r"https?://", app_js + css)
        # Inline handlers are the one inline construct, covered by script-src-attr.
        assert "script-src-attr 'unsafe-inline'" in UI_CSP

    def test_docs_pages_get_a_policy_that_lets_swagger_load(self, client):
        for path in ("/docs", "/redoc"):
            response = client.get(path)
            assert "https://cdn.jsdelivr.net" in response.headers["content-security-policy"]
            assert_hardened(response)
        assert "jsdelivr" not in client.get("/").headers["content-security-policy"]

    def test_hsts_only_over_https(self, client):
        assert "strict-transport-security" not in client.get("/healthz").headers
        secure = TestClient(control_plane.app, base_url="https://testserver")
        assert "max-age=" in secure.get("/healthz").headers["strict-transport-security"]


def _cors_app(origins: str) -> TestClient:
    application = FastAPI()

    @application.get("/ping")
    def ping() -> dict[str, str]:
        return {"ok": "yes"}

    control_plane._install_hardening(application, Settings(cors_origins_raw=origins))
    return TestClient(application)


def _host_client(application: FastAPI, hosts: str = "") -> TestClient:
    control_plane._install_hardening(application, Settings(allowed_hosts_raw=hosts))
    return TestClient(application)


def _ping_app() -> FastAPI:
    application = FastAPI()

    @application.get("/ping")
    def ping() -> dict[str, str]:
        return {"ok": "yes"}

    return application


class TestHostHeader:
    """A DNS-rebinding page reaches the API under its own hostname; that Host must be refused."""

    @pytest.mark.parametrize(
        "host", ["localhost", "localhost:8000", "127.0.0.1:8000", "control:8000", "checkout:8000", "inventory"]
    )
    def test_local_and_compose_names_are_allowed_by_default(self, host):
        assert _host_client(_ping_app()).get("/ping", headers={"Host": host}).status_code == 200

    @pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "localhost.evil.example", "192.0.2.9"])
    def test_other_hosts_are_refused(self, host):
        response = _host_client(_ping_app()).get("/ping", headers={"Host": host})
        assert response.status_code == 400
        assert "ok" not in response.text

    def test_configured_hosts_are_added_to_the_defaults(self):
        client = _host_client(_ping_app(), "ops.example.com, *.internal.example")
        assert client.get("/ping", headers={"Host": "ops.example.com"}).status_code == 200
        assert client.get("/ping", headers={"Host": "a.internal.example:8443"}).status_code == 200
        assert client.get("/ping", headers={"Host": "localhost"}).status_code == 200
        assert client.get("/ping", headers={"Host": "evil.example"}).status_code == 400

    def test_the_control_plane_refuses_unknown_hosts(self, client):
        assert client.get("/api/incidents", headers={"Host": "evil.example"}).status_code == 400
        assert client.get("/api/incidents", headers={"Host": "localhost:8000"}).status_code == 200

    def test_the_demo_service_refuses_unknown_hosts(self):
        svc = TestClient(service.app)
        assert svc.get("/healthz", headers={"Host": "evil.example"}).status_code == 400
        assert svc.get("/healthz", headers={"Host": "checkout:8000"}).status_code == 200


class TestCors:
    def test_default_allows_no_cross_origin_reads(self, client):
        response = client.get("/healthz", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in response.headers

    def test_default_preflight_is_not_approved(self, client):
        response = client.options(
            "/api/engine/run-once",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
        )
        assert "access-control-allow-origin" not in response.headers

    def test_listed_origin_is_allowed_and_others_are_not(self):
        cors = _cors_app("https://ops.example.com,http://localhost:3000")
        allowed = cors.get("/ping", headers={"Origin": "https://ops.example.com"})
        assert allowed.headers["access-control-allow-origin"] == "https://ops.example.com"
        assert "access-control-allow-credentials" not in allowed.headers
        denied = cors.get("/ping", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in denied.headers

    def test_preflight_lists_only_needed_methods_and_headers_and_is_hardened(self):
        cors = _cors_app("https://ops.example.com")
        response = cors.options(
            "/ping",
            headers={
                "Origin": "https://ops.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "https://ops.example.com"
        assert response.headers["access-control-allow-origin"] != "*"
        assert "DELETE" not in response.headers["access-control-allow-methods"]
        assert_hardened(response)

    def test_preflight_for_an_unlisted_header_is_refused(self):
        cors = _cors_app("https://ops.example.com")
        response = cors.options(
            "/ping",
            headers={
                "Origin": "https://ops.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "x-evil",
            },
        )
        assert response.status_code == 400


class TestBodyLimit:
    def test_declared_oversize_body_is_413(self, client):
        response = client.post("/api/engine/run-once", content=b"x" * (control_plane.settings.max_body_bytes + 1))
        assert response.status_code == 413
        assert_hardened(response)

    def test_streamed_oversize_body_is_413(self, client):
        def chunks():
            for _ in range(control_plane.settings.max_body_bytes // 1000 + 2):
                yield b"x" * 1000

        response = client.post("/api/incidents/batch/approve", content=chunks())
        assert response.status_code == 413

    def test_normal_bodies_pass(self, client):
        response = client.post("/api/incidents/batch/approve", json={"approver": "tester"})
        assert response.status_code == 200

    def test_limit_is_exact_and_rejects_bad_content_length(self):
        application = FastAPI()

        @application.post("/echo")
        async def echo(payload: dict[str, str]) -> dict[str, str]:
            return payload

        application.add_middleware(BodyLimitMiddleware, max_bytes=20)
        limited = TestClient(application)
        json_type = {"Content-Type": "application/json"}
        exact = limited.post("/echo", content=b'{"a":"0123456789ab"}', headers=json_type)  # 20 bytes
        assert exact.status_code == 200
        over = limited.post("/echo", content=b'{"a":"0123456789abc"}', headers=json_type)  # 21 bytes
        assert over.status_code == 413
        bad = limited.post("/echo", content=b"{}", headers={**json_type, "Content-Length": "-1"})
        assert bad.status_code == 400


class TestAuthLockout:
    def _bad(self, client, token="wrong"):
        return client.post("/api/engine/run-once", headers={"Authorization": f"Bearer {token}"})

    def test_repeated_wrong_tokens_are_locked_out_with_retry_after(self, client, with_api_key):
        assert [self._bad(client).status_code for _ in range(3)] == [401, 401, 401]
        locked = self._bad(client)
        assert locked.status_code == 429
        assert 1 <= int(locked.headers["retry-after"]) <= 60
        assert_hardened(locked)

    def test_correct_key_is_refused_during_lockout(self, client, with_api_key):
        for _ in range(3):
            self._bad(client)
        assert self._bad(client, token=with_api_key).status_code == 429

    def test_lockout_is_per_client(self, client, with_api_key):
        for _ in range(4):
            self._bad(client)
        other = TestClient(control_plane.app, client=("203.0.113.7", 5000))
        assert self._bad(other, token=with_api_key).status_code == 200

    def test_requests_without_a_token_are_not_counted(self, client, with_api_key):
        for _ in range(10):
            assert client.post("/api/engine/run-once").status_code == 401
        assert self._bad(client, token=with_api_key).status_code == 200

    def test_successful_requests_do_not_lock_out_a_valid_client(self, client, with_api_key):
        for _ in range(10):
            assert self._bad(client, token=with_api_key).status_code == 200

    def test_public_routes_stay_available_during_lockout(self, client, with_api_key):
        for _ in range(4):
            self._bad(client)
        assert client.get("/api/incidents").status_code == 200

    def test_no_lockout_in_demo_mode(self, client, monkeypatch):
        monkeypatch.setattr(control_plane, "API_KEY", "")
        for _ in range(20):
            assert self._bad(client).status_code == 200


class TestInputValidation:
    def test_approve_rejects_markup_in_approver(self, client, with_api_key):
        response = client.post(
            "/api/incidents/x/approve",
            json={"approver": "<img src=x onerror=alert(1)>"},
            headers={"Authorization": f"Bearer {with_api_key}"},
        )
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "payload",
        [
            {"service": "payments", "fault": "latency"},
            {"service": "checkout", "fault": "rm -rf"},
            {"service": "checkout", "fault": "latency", "duration_seconds": 10**6},
            {"service": "checkout", "fault": "latency", "extra": 1},
        ],
    )
    def test_chaos_rejects_out_of_range_payloads(self, client, with_api_key, payload):
        response = client.post("/api/chaos", json=payload, headers={"Authorization": f"Bearer {with_api_key}"})
        assert response.status_code == 422

    def test_overlong_query_parameters_are_rejected(self, client):
        assert client.get("/api/incidents", params={"search": "a" * 201}).status_code == 422
        assert client.get("/api/logs", params={"service": "a" * 65}).status_code == 422


class TestStartupWarning:
    @pytest.fixture
    def records(self, monkeypatch):
        monkeypatch.setattr(control_plane.logger, "propagate", True)
        captured: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(record)

        handler = Capture()
        control_plane.logger.addHandler(handler)
        yield captured
        control_plane.logger.removeHandler(handler)

    def test_missing_key_logs_a_prominent_warning(self, monkeypatch, records):
        monkeypatch.setattr(control_plane, "API_KEY", "")
        control_plane._warn_if_unauthenticated()
        assert [r.levelno for r in records] == [logging.WARNING]
        assert "SECURITY WARNING" in records[0].getMessage()
        assert "AEGIS_API_KEY" in records[0].getMessage()

    def test_configured_key_logs_nothing(self, monkeypatch, records):
        monkeypatch.setattr(control_plane, "API_KEY", "test-key")
        control_plane._warn_if_unauthenticated()
        assert records == []


class TestDemoServiceHardening:
    @pytest.fixture
    def svc(self, monkeypatch):
        monkeypatch.setenv("AEGIS_API_KEY", "svc-key")
        monkeypatch.setattr(service, "_auth_failures", AuthFailureLimiter(2, 60))
        return TestClient(service.app, raise_server_exceptions=False)

    def test_responses_are_hardened_and_deny_all_content(self, svc):
        response = svc.get("/healthz")
        assert_hardened(response)
        assert response.headers["content-security-policy"].startswith("default-src 'none'")

    def test_oversize_admin_body_is_413(self, svc):
        response = svc.post(
            "/admin/faults",
            content=b"x" * (service._settings.max_body_bytes + 1),
            headers={"Authorization": "Bearer svc-key"},
        )
        assert response.status_code == 413

    def test_streamed_oversize_admin_body_is_413(self, svc):
        def chunks():
            for _ in range(service._settings.max_body_bytes // 1000 + 2):
                yield b"x" * 1000

        response = svc.post("/admin/faults", content=chunks(), headers={"Authorization": "Bearer svc-key"})
        assert response.status_code == 413

    def test_admin_brute_force_is_locked_out(self, svc):
        codes = [svc.get("/admin/faults", headers={"Authorization": "Bearer nope"}).status_code for _ in range(3)]
        assert codes == [401, 401, 429]
        assert svc.get("/admin/faults", headers={"Authorization": "Bearer svc-key"}).status_code == 429
