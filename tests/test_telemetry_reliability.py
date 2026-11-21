"""Prometheus calls time out, retry transient failures with backoff, and fail fast during an outage."""

from typing import ClassVar

import httpx
import pytest

from aegis import telemetry as telemetry_module
from aegis.settings import Settings
from aegis.telemetry import Telemetry

OK_PAYLOAD = {"status": "success", "data": {"result": [{"value": [0, "2.5"]}]}}


class Scripted:
    """Stands in for httpx.Client.get, replaying outcomes in order."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(self, url, params=None, **kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _response(status, payload=None):
    request = httpx.Request("GET", "http://prom/api/v1/query")
    return httpx.Response(status, json=payload if payload is not None else OK_PAYLOAD, request=request)


@pytest.fixture
def clock(monkeypatch):
    class Clock:
        now = 1000.0
        sleeps: ClassVar[list[float]] = []

    monkeypatch.setattr(telemetry_module.time, "sleep", lambda seconds: Clock.sleeps.append(seconds))
    monkeypatch.setattr(telemetry_module.time, "monotonic", lambda: Clock.now)
    Clock.sleeps = []
    Clock.now = 1000.0
    return Clock


@pytest.fixture
def telemetry():
    instance = Telemetry(Settings(prometheus_url="http://prom", log_dir="./logs"))
    yield instance
    instance.close()


def test_http_client_has_explicit_timeouts(telemetry):
    assert telemetry._client.timeout.connect == telemetry_module.CONNECT_TIMEOUT_SECONDS
    assert telemetry._client.timeout.read == telemetry_module.READ_TIMEOUT_SECONDS


def test_transient_failures_are_retried_with_exponential_backoff(telemetry, clock, monkeypatch):
    get = Scripted(httpx.ReadTimeout("slow"), _response(503), _response(200))
    monkeypatch.setattr(telemetry._client, "get", get)

    result = telemetry.prometheus_query("up")

    assert result["value"] == 2.5
    assert get.calls == 3
    assert clock.sleeps == [0.25, 0.5]


def test_retries_are_bounded(telemetry, clock, monkeypatch):
    get = Scripted(httpx.ConnectError("refused"))
    monkeypatch.setattr(telemetry._client, "get", get)

    result = telemetry.prometheus_query("up")

    assert get.calls == telemetry_module.QUERY_ATTEMPTS
    assert result["value"] is None
    assert "refused" in result["error"]


def test_client_errors_are_not_retried_and_do_not_trip_the_breaker(telemetry, clock, monkeypatch):
    get = Scripted(_response(400, {"status": "error", "error": "bad query"}))
    monkeypatch.setattr(telemetry._client, "get", get)

    assert telemetry.prometheus_query("bad")["value"] is None
    assert telemetry.prometheus_query("bad")["value"] is None

    assert get.calls == 2
    assert clock.sleeps == []


def test_breaker_fails_fast_during_an_outage_then_recovers(telemetry, clock, monkeypatch):
    get = Scripted(httpx.ConnectError("refused"))
    monkeypatch.setattr(telemetry._client, "get", get)
    telemetry.prometheus_query("up")
    calls_after_first = get.calls

    result = telemetry.prometheus_query("up")

    assert get.calls == calls_after_first
    assert "unavailable" in result["error"]

    clock.now += telemetry_module.BREAKER_COOLDOWN_SECONDS + 1
    get.outcomes = [_response(200)]
    assert telemetry.prometheus_query("up")["value"] == 2.5
    assert telemetry.prometheus_query("up")["value"] == 2.5  # breaker stays closed


@pytest.mark.parametrize("payload", [[1, 2], {"status": "success", "data": {"result": [None]}},
                                     {"status": "success", "data": {"result": [{"value": []}]}},
                                     {"status": "success", "data": None}])
def test_unexpected_response_shapes_become_error_results(telemetry, clock, monkeypatch, payload):
    monkeypatch.setattr(telemetry._client, "get", Scripted(_response(200, payload)))

    result = telemetry.prometheus_query("up")

    assert result["value"] is None
    assert "Parse error" in result["error"]


def test_non_json_body_becomes_an_error_result(telemetry, clock, monkeypatch):
    request = httpx.Request("GET", "http://prom/api/v1/query")
    monkeypatch.setattr(
        telemetry._client, "get", Scripted(httpx.Response(200, text="<html>", request=request))
    )

    assert "Parse error" in telemetry.prometheus_query("up")["error"]


def test_malformed_prometheus_url_is_an_error_result(clock):
    config = Settings(log_dir="./logs")
    # Settings rejects malformed URLs at startup; Telemetry must still not raise if one slips through.
    object.__setattr__(config, "prometheus_url", "http://bad host:99999")
    instance = Telemetry(config)
    try:
        result = instance.prometheus_query("up")
        assert result["value"] is None
        assert "error" in result
    finally:
        instance.close()


def test_loki_status_never_raises_and_is_not_retried(telemetry, monkeypatch):
    get = Scripted(httpx.ReadTimeout("slow"))
    monkeypatch.setattr(telemetry._client, "get", get)

    status = telemetry.loki_status()

    assert status.available is False
    assert get.calls == 1
