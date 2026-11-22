"""The engine loop survives failing and hung cycles, backs off, and reports its own health."""

import threading
import time

import pytest

from aegis import supervisor as supervisor_module
from aegis.breaker import CircuitBreaker
from aegis.settings import Settings
from aegis.storage import Store
from aegis.supervisor import SupervisedEngine


class FakeTelemetry:
    def prometheus_query(self, query):
        return {"value": 0.0}


def wait_until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached in time")


@pytest.fixture
def make_engine(tmp_path):
    created = []

    def build(**overrides):
        settings = Settings(db_path=str(tmp_path / f"db{len(created)}"), **overrides)
        store = Store(settings.db_path)
        engine = SupervisedEngine(settings, store, FakeTelemetry())
        created.append((engine, store))
        return engine

    yield build
    for engine, store in created:
        engine.stop(timeout=3)
        store.close()


@pytest.fixture
def delays(monkeypatch):
    """Record the pause between cycles instead of sleeping through it."""
    recorded: list[float] = []

    def pause(self, seconds):
        recorded.append(seconds)
        self._stop.wait(0.005)

    monkeypatch.setattr(SupervisedEngine, "_pause", pause)
    return recorded


def test_an_exception_in_a_cycle_never_kills_the_loop(make_engine, delays, monkeypatch):
    engine = make_engine(poll_seconds=5)
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) <= 2:
            raise RuntimeError("boom")
        return []

    monkeypatch.setattr(engine, "run_once", flaky)
    engine.start()

    wait_until(lambda: engine.status().last_success_at is not None)

    status = engine.status()
    assert engine.is_running
    assert status.consecutive_failures == 0
    assert status.failures_total == 2
    assert status.cycles_total >= 3
    assert status.last_error is not None
    assert "RuntimeError: boom" in status.last_error
    assert status.last_error_at is not None
    assert status.state == "ok"


def test_repeated_failures_back_off_exponentially_up_to_the_cap_and_reset(
    make_engine, delays, monkeypatch
):
    engine = make_engine(poll_seconds=5, engine_max_backoff_seconds=60)
    calls = []
    finished = threading.Event()

    def flaky():
        calls.append(1)
        if len(calls) <= 6:
            raise RuntimeError("boom")
        finished.set()
        return []

    monkeypatch.setattr(engine, "run_once", flaky)
    engine.start()
    assert finished.wait(5)
    wait_until(lambda: len(delays) >= 7)

    assert delays[:7] == [5, 10, 20, 40, 60, 60, 5]


def test_the_backoff_cap_never_drops_below_the_poll_interval(make_engine, delays, monkeypatch):
    engine = make_engine(poll_seconds=30, engine_max_backoff_seconds=10)
    monkeypatch.setattr(engine, "run_once", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    engine.start()

    wait_until(lambda: len(delays) >= 3)

    assert delays[:3] == [30, 30, 30]


def test_a_hung_cycle_is_abandoned_and_does_not_pile_up_new_cycles(make_engine, delays, monkeypatch):
    engine = make_engine(poll_seconds=1, cycle_timeout_seconds=1)
    release = threading.Event()
    calls = []

    def hang():
        calls.append(1)
        release.wait(10)
        return []

    monkeypatch.setattr(engine, "run_once", hang)
    engine.start()

    wait_until(lambda: engine.status().consecutive_failures >= 3, timeout=8)

    assert len(calls) == 1  # no second cycle while the hung one still runs
    assert engine.is_running
    assert "timed out after 1s" in (engine.status().last_error or "") or "still running" in (
        engine.status().last_error or ""
    )

    release.set()
    wait_until(lambda: engine.status().last_success_at is not None, timeout=8)
    assert len(calls) >= 2
    assert engine.status().consecutive_failures == 0


def test_stop_lets_an_in_flight_cycle_finish_within_the_grace_period(make_engine, monkeypatch):
    engine = make_engine(poll_seconds=3600, shutdown_grace_seconds=5)
    started, finished = threading.Event(), threading.Event()

    def slow():
        started.set()
        time.sleep(0.4)
        finished.set()
        return []

    monkeypatch.setattr(engine, "run_once", slow)
    engine.start()
    assert started.wait(2)

    engine.stop(timeout=10)

    assert finished.is_set()
    assert engine.status().last_success_at is not None
    assert not engine.is_running


def test_stop_abandons_a_hung_cycle_after_the_grace_period(make_engine, monkeypatch):
    engine = make_engine(poll_seconds=3600, cycle_timeout_seconds=600, shutdown_grace_seconds=0)
    started, release = threading.Event(), threading.Event()

    def hang():
        started.set()
        release.wait(30)
        return []

    monkeypatch.setattr(engine, "run_once", hang)
    engine.start()
    assert started.wait(2)

    began = time.monotonic()
    engine.stop(timeout=10)
    release.set()

    assert time.monotonic() - began < 3
    assert not engine.is_running


def test_stop_waits_for_the_grace_period_plus_a_margin_by_default(make_engine, monkeypatch):
    engine = make_engine(shutdown_grace_seconds=7)
    seen = []
    monkeypatch.setattr(supervisor_module.IncidentEngine, "stop", lambda self, timeout: seen.append(timeout))

    engine.stop()

    assert seen == [7 + supervisor_module.STOP_MARGIN_SECONDS]


def test_a_failure_inside_the_supervisor_itself_does_not_end_the_loop(
    make_engine, delays, monkeypatch
):
    engine = make_engine(poll_seconds=5)
    original = engine._supervise_cycle
    attempts = []

    def broken():
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("can't start new thread")
        original()

    monkeypatch.setattr(engine, "_supervise_cycle", broken)
    engine.start()

    wait_until(lambda: engine.status().last_success_at is not None)

    assert engine.is_running
    assert "can't start new thread" in (engine.status().last_error or "")


class TestStatus:
    @pytest.fixture
    def clock(self, monkeypatch):
        offset = {"s": 0.0}
        real = time.monotonic
        monkeypatch.setattr(supervisor_module.time, "monotonic", lambda: real() + offset["s"])
        return offset

    def test_ok_after_a_successful_cycle(self, make_engine, clock, monkeypatch):
        engine = make_engine(poll_seconds=3600)
        engine.start()
        wait_until(lambda: engine.status().last_success_at is not None)

        status = engine.status()

        assert status.state == "ok"
        assert status.reason is None
        assert status.running is True
        assert status.last_success_age_seconds is not None
        assert status.last_cycle_seconds is not None

    def test_degraded_while_cycles_fail_but_the_heartbeat_is_fresh(self, make_engine, clock, monkeypatch):
        engine = make_engine(poll_seconds=3600)
        engine.start()
        wait_until(lambda: engine.status().last_success_at is not None)
        engine._record_failure("error", RuntimeError("boom"))

        status = engine.status()

        assert status.state == "degraded"
        assert status.reason == "1 consecutive cycle failure"
        assert status.consecutive_failures == 1

    def test_stalled_when_the_heartbeat_is_older_than_the_limit(self, make_engine, clock):
        engine = make_engine(poll_seconds=5, cycle_timeout_seconds=60, engine_stale_intervals=3)
        engine.start()
        wait_until(lambda: engine.status().last_success_at is not None)
        assert engine.status().stale_after_seconds == 75

        clock["s"] = 74
        assert engine.status().state == "ok"
        clock["s"] = 76
        status = engine.status()

        assert status.state == "stalled"
        assert status.reason is not None
        assert "no successful cycle for 76s" in status.reason
        assert "limit 75s" in status.reason

    def test_stalled_before_the_first_success_counts_from_the_start(self, make_engine, clock, monkeypatch):
        engine = make_engine(poll_seconds=5, cycle_timeout_seconds=60)
        release = threading.Event()
        monkeypatch.setattr(engine, "run_once", lambda: release.wait(10) and [])
        engine.start()
        try:
            clock["s"] = 100
            assert engine.status().state == "stalled"
        finally:
            release.set()

    def test_stopped_when_the_thread_is_not_running(self, make_engine):
        engine = make_engine(poll_seconds=3600)
        engine.start()
        engine.stop()

        status = engine.status()

        assert status.state == "stopped"
        assert status.running is False
        assert status.reason == "engine loop is not running"

    def test_includes_breaker_state(self, tmp_path):
        settings = Settings(db_path=str(tmp_path / "db"))
        store = Store(settings.db_path)
        breaker = CircuitBreaker("prometheus", 1, 30)
        breaker.record_failure("refused")
        engine = SupervisedEngine(settings, store, FakeTelemetry(), breakers={"prometheus": breaker})
        try:
            assert engine.status().breakers["prometheus"].state == "open"
        finally:
            store.close()


def test_a_restart_after_an_abandoned_execution_recovers_and_resumes(tmp_path, monkeypatch):
    settings = Settings(
        db_path=str(tmp_path / "db"), poll_seconds=3600, cycle_timeout_seconds=600, shutdown_grace_seconds=0
    )
    store = Store(settings.db_path)
    store.upsert_incident("inc-1", "t", "high", "service:checkout", {"value": 1})
    store.transition_status("inc-1", "open", "executing")
    engine = SupervisedEngine(settings, store, FakeTelemetry())
    started, release = threading.Event(), threading.Event()
    monkeypatch.setattr(engine, "run_once", lambda: (started.set(), release.wait(30), [])[2])
    engine.start()
    assert started.wait(2)
    engine.stop(timeout=5)  # abandons the hung cycle
    release.set()
    store.close()

    reopened = Store(settings.db_path)
    try:
        assert reopened.recover_interrupted_executions() == ["inc-1"]
        assert reopened.get_incident("inc-1")["status"] == "approved"
        fresh = SupervisedEngine(settings, reopened, FakeTelemetry())
        fresh.start()
        wait_until(lambda: fresh.status().last_success_at is not None)
        fresh.stop(timeout=5)
    finally:
        reopened.close()
