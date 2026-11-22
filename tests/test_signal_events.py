"""A still-active signal is logged on change or at most once per interval; evidence history is unaffected."""

from datetime import UTC, datetime, timedelta

import pytest

from aegis import storage
from aegis.incidents import IncidentEngine
from aegis.queries import CHECKOUT_ERROR_RATE
from aegis.settings import Settings
from aegis.storage import Store


class Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self):
        return self.now.isoformat()

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(storage, "utc_now", fake)
    return fake


def _store(tmp_path, interval=60.0, max_evidence=100):
    return Store(str(tmp_path / "db.sqlite"), max_evidence, signal_event_interval=interval)


def _signals(store, incident_id="inc-1"):
    return [e for e in store.events(incident_id) if e["kind"] == "signal"]


def _poll(store, rule="checkout_error_rate", value=1.0, root="service:checkout"):
    return store.upsert_incident("inc-x", "t", "high", root, {"rule": rule, "value": value})


def test_repeated_polls_within_the_interval_add_no_signal_events(tmp_path, clock):
    store = _store(tmp_path)
    _poll(store)
    for _ in range(11):  # a minute of 5 s polls
        clock.advance(5)
        _poll(store, value=2.0)

    incident = store.list_incidents()[0]
    assert _signals(store, incident["id"]) == []


def test_one_signal_event_is_recorded_per_interval(tmp_path, clock):
    store = _store(tmp_path, interval=60)
    incident, _ = _poll(store)
    for _ in range(36):  # three minutes of 5 s polls
        clock.advance(5)
        _poll(store)

    assert len(_signals(store, incident["id"])) == 3


def test_a_newly_firing_signal_is_recorded_immediately(tmp_path, clock):
    store = _store(tmp_path)
    incident, _ = _poll(store, rule="checkout_error_rate")
    clock.advance(5)
    _poll(store, rule="checkout_p95_latency")
    clock.advance(5)
    _poll(store, rule="checkout_p95_latency")
    clock.advance(5)
    _poll(store, rule="checkout_error_rate")

    signals = _signals(store, incident["id"])
    assert [e["data"]["rule"] for e in signals] == ["checkout_p95_latency"]


def test_alternating_rules_each_respect_their_own_interval(tmp_path, clock):
    store = _store(tmp_path, interval=60)
    incident, _ = _poll(store, rule="a")
    _poll(store, rule="b")
    for _ in range(11):
        clock.advance(5)
        _poll(store, rule="a")
        _poll(store, rule="b")

    assert len(_signals(store, incident["id"])) == 1  # only b's first appearance


def test_evidence_history_still_grows_every_poll_and_stays_bounded(tmp_path, clock):
    store = _store(tmp_path, max_evidence=5)
    incident, _ = _poll(store, value=0.0)
    for n in range(1, 11):
        clock.advance(5)
        incident, _ = _poll(store, value=float(n))

    assert [item["value"] for item in incident["data"]["evidence"]] == [6.0, 7.0, 8.0, 9.0, 10.0]
    assert incident["data"]["latest_evidence"]["value"] == 10.0
    assert incident["last_seen"] == clock()


def test_a_zero_interval_records_every_poll(tmp_path, clock):
    store = _store(tmp_path, interval=0)
    incident, _ = _poll(store)
    for _ in range(3):
        clock.advance(5)
        _poll(store)

    assert len(_signals(store, incident["id"])) == 3


def test_throttling_survives_a_restart(tmp_path, clock):
    first = _store(tmp_path)
    incident, _ = _poll(first)
    first.close()

    second = _store(tmp_path)
    clock.advance(5)
    _poll(second)

    assert _signals(second, incident["id"]) == []


def test_the_engine_does_not_spam_the_timeline(tmp_path, clock):
    class Telemetry:
        def prometheus_query(self, query):
            return {"value": 0.5 if query == CHECKOUT_ERROR_RATE else 0.0}

    config = Settings(
        db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks", detection_cycles=1
    )
    store = _store(tmp_path)
    engine = IncidentEngine(config, store, Telemetry())
    engine._investigate = lambda incident_id: None

    for _ in range(24):  # two minutes of 5 s polls
        engine.run_once()
        clock.advance(5)

    incidents = store.list_incidents()
    assert len(incidents) == 1
    events = store.events(incidents[0]["id"])
    assert len(events) < 10, [e["kind"] for e in events]
    assert len(incidents[0]["data"]["evidence"]) == 24
