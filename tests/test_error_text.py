"""Error text that reaches clients carries the error class and status, never URLs or credentials."""

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.agent import AgentInvestigator
from aegis.breaker import CircuitBreaker
from aegis.errors import error_summary, redact_urls
from aegis.remediation import RemediationExecutor
from aegis.settings import Settings
from aegis.storage import Store
from aegis.supervisor import SupervisedEngine
from aegis.telemetry import Telemetry

SECRET_URL = "http://admin:hunter2@prometheus.internal:9090/api/v1/query"


def _status_error(status: int = 503) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", SECRET_URL)
    response = httpx.Response(status, request=request)
    return httpx.HTTPStatusError(f"Server error for url '{SECRET_URL}'", request=request, response=response)


def assert_clean(text: str | None) -> None:
    assert text
    for leaked in ("hunter2", "admin:", "prometheus.internal"):
        assert leaked not in text


class TestHelpers:
    def test_redact_urls_drops_credentials_and_keeps_the_rest(self):
        assert redact_urls("GET http://u:p@a@host:9090/x failed") == "GET http://host:9090/x failed"
        assert redact_urls("see https://host/a?mail=x@y") == "see https://host/a?mail=x@y"

    def test_http_errors_reduce_to_class_and_status(self):
        assert error_summary(_status_error(503)) == "HTTPStatusError (HTTP 503)"

    def test_library_errors_reduce_to_the_class(self):
        assert error_summary(httpx.ConnectError(f"cannot reach {SECRET_URL}")) == "ConnectError"
        assert error_summary(httpx.InvalidURL(SECRET_URL)) == "InvalidURL"

    def test_our_own_errors_keep_their_message_without_credentials(self):
        assert error_summary(TimeoutError("cycle timed out after 60s")) == "TimeoutError: cycle timed out after 60s"
        assert error_summary(RuntimeError(f"bad {SECRET_URL}")) == (
            "RuntimeError: bad http://prometheus.internal:9090/api/v1/query"
        )


class TestTelemetry:
    @pytest.fixture
    def telemetry(self, monkeypatch):
        instance = Telemetry(Settings(prometheus_url="http://prom", loki_url="http://loki"))
        monkeypatch.setattr("aegis.telemetry.time.sleep", lambda seconds: None)
        yield instance
        instance.close()

    def test_prometheus_error_carries_no_url(self, telemetry, monkeypatch):
        def fail(url, params=None, **kwargs):
            raise _status_error(503)

        monkeypatch.setattr(telemetry._client, "get", fail)

        result = telemetry.prometheus_query("up")

        assert result["error"] == "HTTP error: HTTPStatusError (HTTP 503)"
        assert_clean(telemetry.prometheus_breaker.snapshot().last_error)

    def test_invalid_url_error_carries_no_credentials(self, telemetry, monkeypatch):
        def fail(url, params=None, **kwargs):
            raise httpx.InvalidURL(SECRET_URL)

        monkeypatch.setattr(telemetry._client, "get", fail)

        assert_clean(telemetry.prometheus_query("up")["error"])
        assert_clean(telemetry.prometheus_breaker.snapshot().last_error)

    def test_loki_error_carries_no_credentials(self, telemetry, monkeypatch):
        def fail(url, **kwargs):
            raise httpx.ConnectError(f"cannot reach {SECRET_URL}")

        monkeypatch.setattr(telemetry._client, "get", fail)

        status = telemetry.loki_status()

        assert status.error == "ConnectError"
        assert telemetry.loki_breaker.snapshot().last_error == "ConnectError"


def test_breaker_never_stores_url_credentials():
    breaker = CircuitBreaker("x", 1, 1.0)

    breaker.record_failure(f"failed {SECRET_URL}")

    assert breaker.snapshot().last_error == "failed http://prometheus.internal:9090/api/v1/query"


def test_engine_last_error_carries_no_url(tmp_path):
    settings = Settings(db_path=str(tmp_path / "db"))
    store = Store(settings.db_path)
    engine = SupervisedEngine(settings, store, Telemetry(settings))

    engine._record_failure("error", _status_error())

    assert engine.status().last_error == "HTTPStatusError (HTTP 503)"
    store.close()


def test_overview_service_errors_carry_no_url(monkeypatch):
    def fail(url, **kwargs):
        raise httpx.ConnectError(f"cannot reach {SECRET_URL}")

    monkeypatch.setattr(control_plane.httpx, "get", fail)

    body = TestClient(control_plane.app).get("/api/overview").json()

    assert [service["error"] for service in body["services"]] == ["ConnectError", "ConnectError"]


def test_remediation_failure_events_carry_no_url(tmp_path, monkeypatch):
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"),
        inventory_url="http://admin:hunter2@inventory.internal",
        api_key="test-key",
    )
    store = Store(settings.db_path)
    store.upsert_incident("inc-1", "t", "high", "dependency:inventory", {"n": 0})
    recommendation = {"action": "clear_fault", "target": "inventory", "parameters": {"fault": "dependency"}}
    store.merge_incident(
        "inc-1",
        {"recommendation": recommendation, "approval": {"approver": "op", "recommendation": recommendation}},
        status="approved",
    )
    executor = RemediationExecutor(settings, store)

    def fail(url, json, headers=None):
        raise httpx.ConnectError(f"cannot reach {url}")

    monkeypatch.setattr(executor._client, "post", fail)

    with pytest.raises(Exception, match="failed") as raised:
        executor.execute("inc-1", "op")

    events = [e for e in store.events("inc-1") if e["kind"] == "remediation_failed"]
    texts = [str(raised.value), events[0]["message"], str(events[0]["data"])]
    for text in texts:
        assert "hunter2" not in text
        assert "inventory.internal" not in text
    executor.close()


def test_agent_fallback_reason_carries_no_url(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    settings = Settings(db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks")
    store = Store(settings.db_path)
    store.upsert_incident("inc-1", "t", "high", "dependency:inventory", {"value": 1})
    agent = AgentInvestigator(settings, store, Telemetry(settings))

    def fail(incident):
        raise httpx.ConnectError(f"cannot reach {SECRET_URL}")

    monkeypatch.setattr(agent, "_llm_investigation", fail)

    result = agent.investigate("inc-1")

    assert result["fallback_reason"] == "ConnectError"
    assert agent.llm_breaker.snapshot().last_error == "ConnectError"
