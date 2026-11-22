"""The engine loop survives every failing dependency and never resolves on a missing reading."""

import sqlite3
import threading
import time

from aegis.incidents import RULES, IncidentEngine
from aegis.queries import CHECKOUT_ERROR_RATE, INVENTORY_DEPENDENCY_ERRORS
from aegis.settings import Settings
from aegis.storage import Store


class ScriptedTelemetry:
    """Answers each query from a mapping; a value that is an Exception is raised."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.queries: list[str] = []

    def prometheus_query(self, query):
        self.queries.append(query)
        answer = self.answers.get(query, {"value": 0.0})
        if isinstance(answer, Exception):
            raise answer
        return answer

    def metric_snapshot(self):
        return []

    def recent_logs(self, service=None, limit=30):
        return []


def _engine(tmp_path, telemetry, **settings):
    config = Settings(
        db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks", detection_cycles=1
    )
    # Settings validates at construction; the engine must still survive values that
    # slip past it (e.g. a zero poll interval), so the overrides bypass validation.
    for name, value in settings.items():
        object.__setattr__(config, name, value)
    store = Store(config.db_path)
    engine = IncidentEngine(config, store, telemetry)
    engine._investigate = lambda incident_id: None
    return engine, store


def _incident_by_root(store, root):
    return next(i for i in store.list_incidents() if i["root_cause_key"] == root)


def test_one_rule_raising_does_not_stop_the_others(tmp_path):
    telemetry = ScriptedTelemetry(
        {
            CHECKOUT_ERROR_RATE: RuntimeError("prometheus client exploded"),
            INVENTORY_DEPENDENCY_ERRORS: {"value": 1.0},
        }
    )
    engine, _ = _engine(tmp_path, telemetry)

    fired = engine.run_once()

    assert [i["root_cause_key"] for i in fired] == ["dependency:inventory"]
    assert set(telemetry.queries) >= {rule.query for rule in RULES}


def test_store_failures_are_contained_per_cycle(tmp_path, monkeypatch):
    telemetry = ScriptedTelemetry({INVENTORY_DEPENDENCY_ERRORS: {"value": 1.0}})
    engine, store = _engine(tmp_path, telemetry)

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "upsert_incident", locked)
    monkeypatch.setattr(store, "list_incidents", locked)

    assert engine.run_once() == []  # does not raise


def test_error_results_do_not_feed_the_anomaly_baseline(tmp_path):
    telemetry = ScriptedTelemetry({rule.query: {"value": None, "error": "HTTP error: down"} for rule in RULES})
    engine, _ = _engine(tmp_path, telemetry)

    for _ in range(10):
        engine.run_once()

    assert engine.detector.samples == {}


def test_a_prometheus_outage_never_resolves_incidents(tmp_path):
    telemetry = ScriptedTelemetry({INVENTORY_DEPENDENCY_ERRORS: {"value": 1.0}})
    engine, store = _engine(tmp_path, telemetry, resolution_cycles=2)
    engine.run_once()
    incident = _incident_by_root(store, "dependency:inventory")
    # Only open incidents auto-resolve; the investigation is stubbed out here.
    store.update_incident(incident["id"], status="open")

    telemetry.answers = {rule.query: {"value": None, "error": "HTTP error: down"} for rule in RULES}
    for _ in range(6):
        engine.run_once()

    current = store.get_incident(incident["id"])
    assert current["status"] == "open"
    unavailable = [e for e in store.events(incident["id"]) if e["kind"] == "telemetry_unavailable"]
    assert len(unavailable) == 1  # recorded once per outage, not once per cycle

    # Healthy readings after the outage still resolve it, after the full window.
    telemetry.answers = {}
    engine.run_once()
    assert store.get_incident(incident["id"])["status"] == "open"
    engine.run_once()
    assert store.get_incident(incident["id"])["status"] == "resolved"


def test_failed_dependency_check_skips_instead_of_filing_under_the_wrong_root(tmp_path):
    telemetry = ScriptedTelemetry(
        {
            CHECKOUT_ERROR_RATE: {"value": 0.9},
            INVENTORY_DEPENDENCY_ERRORS: {"value": None, "error": "HTTP error: down"},
        }
    )
    engine, store = _engine(tmp_path, telemetry)

    assert engine.run_once() == []
    assert store.list_incidents() == []


def test_new_incident_moves_to_investigating_and_starts_one_investigation(tmp_path):
    telemetry = ScriptedTelemetry({INVENTORY_DEPENDENCY_ERRORS: {"value": 1.0}})
    engine, store = _engine(tmp_path, telemetry)
    started = threading.Event()
    engine._investigate = lambda incident_id: started.set()

    engine.run_once()

    assert started.wait(timeout=5)
    incident = _incident_by_root(store, "dependency:inventory")
    assert incident["status"] == "investigating"
    kinds = [e["kind"] for e in store.events(incident["id"])]
    assert "investigation_started" in kinds


class ExplodingAgent:
    def investigate(self, incident_id):
        raise RuntimeError("llm exploded")


def test_a_crashing_investigation_is_recorded_and_releases_the_incident(tmp_path):
    engine, store = _engine(tmp_path, ScriptedTelemetry())
    engine.agent = ExplodingAgent()
    del engine._investigate  # use the real method
    store.upsert_incident("inc-1", "t", "high", "service:x", {})
    store.update_incident("inc-1", status="investigating")

    engine._investigate("inc-1")

    assert store.get_incident("inc-1")["status"] == "open"
    assert [e["message"] for e in store.events("inc-1") if e["kind"] == "agent_error"] == ["llm exploded"]


def test_a_crashing_investigation_does_not_reopen_an_incident_that_moved_on(tmp_path):
    engine, store = _engine(tmp_path, ScriptedTelemetry())
    engine.agent = ExplodingAgent()
    del engine._investigate
    store.upsert_incident("inc-1", "t", "high", "service:x", {})
    store.update_incident("inc-1", status="approved")

    engine._investigate("inc-1")

    assert store.get_incident("inc-1")["status"] == "approved"


def test_investigation_thread_survives_the_store_failing_while_recording(tmp_path, monkeypatch):
    engine, store = _engine(tmp_path, ScriptedTelemetry())
    engine.agent = ExplodingAgent()
    del engine._investigate

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "add_event", locked)

    engine._investigate("inc-1")  # does not raise


def test_the_engine_thread_keeps_running_after_cycles_raise(tmp_path):
    engine, _ = _engine(tmp_path, ScriptedTelemetry(), poll_seconds=0)
    cycles = []
    three_failures = threading.Event()

    def failing_cycle():
        cycles.append(1)
        if len(cycles) >= 3:
            three_failures.set()
        raise RuntimeError("boom")

    engine.run_once = failing_cycle
    engine._stop.wait = lambda timeout=None: time.sleep(0.01)

    engine.start()
    try:
        assert three_failures.wait(timeout=5)
        assert engine._thread is not None
        assert engine._thread.is_alive()
    finally:
        engine.stop()


def test_a_zero_poll_interval_cannot_busy_loop(tmp_path):
    engine, _ = _engine(tmp_path, ScriptedTelemetry(), poll_seconds=0)
    waits = []

    def record_wait(timeout=None):
        waits.append(timeout)
        engine._stop.set()

    engine._stop.wait = record_wait
    engine._run()

    assert waits == [1]


def test_interrupted_investigations_resume_on_start(tmp_path):
    engine, store = _engine(tmp_path, ScriptedTelemetry())
    store.upsert_incident("inc-stuck", "t", "high", "service:x", {})
    store.update_incident("inc-stuck", status="investigating")
    store.upsert_incident("inc-open", "t", "high", "service:y", {})
    resumed = []
    done = threading.Event()

    def record(incident_id):
        resumed.append(incident_id)
        done.set()

    engine._investigate = record
    engine._stop.wait = lambda timeout=None: time.sleep(0.01)
    engine.start()
    try:
        assert done.wait(timeout=5)
    finally:
        engine.stop()

    assert resumed == ["inc-stuck"]
