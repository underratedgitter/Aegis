"""A circuit breaker stops calls to a dead backend and probes it again after a cooldown."""

import pytest

from aegis import breaker as breaker_module
from aegis.breaker import CircuitBreaker


@pytest.fixture
def now(monkeypatch):
    clock = {"t": 100.0}
    monkeypatch.setattr(breaker_module.time, "monotonic", lambda: clock["t"])
    return clock


def test_starts_closed_and_allows_calls():
    breaker = CircuitBreaker("prometheus", failure_threshold=2, cooldown_seconds=10)

    assert breaker.allow()
    assert breaker.snapshot().state == "closed"


def test_opens_after_the_failure_threshold_and_then_rejects(now):
    breaker = CircuitBreaker("prometheus", failure_threshold=2, cooldown_seconds=10)

    breaker.record_failure("refused")
    assert breaker.allow()
    breaker.record_failure("refused")

    assert not breaker.allow()
    snapshot = breaker.snapshot()
    assert snapshot.state == "open"
    assert snapshot.consecutive_failures == 2
    assert snapshot.last_error == "refused"
    assert snapshot.retry_in_seconds == 10


def test_a_success_resets_the_failure_count(now):
    breaker = CircuitBreaker("loki", failure_threshold=2, cooldown_seconds=10)

    breaker.record_failure("x")
    breaker.record_success()
    breaker.record_failure("x")

    assert breaker.allow()
    assert breaker.snapshot().consecutive_failures == 1


def test_after_the_cooldown_exactly_one_probe_is_let_through(now):
    breaker = CircuitBreaker("llm", failure_threshold=1, cooldown_seconds=10)
    breaker.record_failure("down")

    now["t"] += 10
    assert breaker.allow()
    assert breaker.snapshot().state == "half_open"
    assert not breaker.allow()  # the probe is still in flight


def test_a_successful_probe_closes_the_breaker(now):
    breaker = CircuitBreaker("llm", failure_threshold=1, cooldown_seconds=10)
    breaker.record_failure("down")
    now["t"] += 10
    assert breaker.allow()

    breaker.record_success()

    assert breaker.snapshot().state == "closed"
    assert breaker.allow()
    assert breaker.allow()


def test_a_failed_probe_reopens_for_a_full_cooldown(now):
    breaker = CircuitBreaker("llm", failure_threshold=1, cooldown_seconds=10)
    breaker.record_failure("down")
    now["t"] += 10
    assert breaker.allow()

    breaker.record_failure("still down")

    assert breaker.snapshot().state == "open"
    now["t"] += 9
    assert not breaker.allow()
    now["t"] += 1
    assert breaker.allow()


@pytest.mark.parametrize(("threshold", "cooldown"), [(0, 10), (1, 0)])
def test_rejects_unusable_configuration(threshold, cooldown):
    with pytest.raises(ValueError, match="at least"):
        CircuitBreaker("x", failure_threshold=threshold, cooldown_seconds=cooldown)
