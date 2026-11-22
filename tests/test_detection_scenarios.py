"""Replay recorded metric sequences through the engine and assert the exact incident lifecycle.

Each step is one evaluation cycle. A reading is a number, None (the query matched no
series) or "error" (the backend could not be queried); readings not given default to
a healthy 0.0.
"""

import threading
from datetime import UTC, datetime, timedelta

import pytest

from aegis.incidents import RULES, IncidentEngine
from aegis.settings import Settings
from aegis.storage import Store

QUERY = {rule.name: rule.query for rule in RULES}
ERRORS = "checkout_error_rate"
LATENCY = "checkout_p95_latency"
DEPENDENCY = "inventory_dependency_errors"
DOWN = "checkout_down"
ALL_NO_DATA = dict.fromkeys(QUERY)
ALL_ERRORS = dict.fromkeys(QUERY, "error")


class Replay:
    def __init__(self, tmp_path, **overrides):
        settings = {"detection_cycles": 2, "resolution_cycles": 2, "blind_seconds": 0, "reopen_cooldown_seconds": 0}
        settings.update(overrides)
        config = Settings(db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks", **settings)
        self.store = Store(config.db_path)
        self.answers: dict[str, dict] = {}
        self.engine = self._engine(config)
        self.config = config
        self.now = 1000.0
        self.engine._clock = lambda: self.now

    def _engine(self, config):
        engine = IncidentEngine(config, self.store, self)
        # Investigations are asynchronous; replay them as one that finished and released the incident.
        engine._spawn_investigation = lambda incident_id: self.store.transition_status(
            incident_id, "investigating", "open"
        )
        return engine

    def restart(self):
        self.engine = self._engine(self.config)
        self.engine._clock = lambda: self.now

    # Telemetry double
    def prometheus_query(self, query):
        name = next(name for name, text in QUERY.items() if text == query)
        reading = self.answers.get(name, 0.0)
        if reading == "error":
            return {"value": None, "error": "HTTP error: down"}
        return {"value": reading}

    def metric_snapshot(self):
        return []

    def recent_logs(self, service=None, limit=30):
        return []

    def step(self, seconds=5, **readings):
        self.answers = readings
        self.now += seconds
        return self.engine.run_once()

    def play(self, readings_per_cycle):
        for readings in readings_per_cycle:
            self.step(**readings)

    def incidents(self, root=None):
        found = sorted(self.store.list_incidents(limit=1000), key=lambda i: i["first_seen"])
        return [i for i in found if root is None or i["root_cause_key"] == root]

    def statuses(self, root=None):
        return [i["status"] for i in self.incidents(root)]

    def kinds(self, incident):
        return [e["kind"] for e in self.store.events(incident["id"])]


BAD = {ERRORS: 0.6}
GOOD: dict = {}


@pytest.fixture
def replay(tmp_path):
    return Replay(tmp_path)


def test_a_steady_healthy_service_never_opens_an_incident(replay):
    replay.play([GOOD] * 30)

    assert replay.incidents() == []


def test_a_single_spike_is_debounced(replay):
    replay.play([GOOD, GOOD, BAD, GOOD, GOOD])

    assert replay.incidents() == []


def test_a_sustained_breach_opens_exactly_one_incident_on_the_kth_cycle(replay):
    replay.step(**BAD)
    assert replay.incidents() == []

    fired = replay.step(**BAD)
    assert [i["root_cause_key"] for i in fired] == ["service:checkout"]

    replay.play([BAD] * 10)
    assert replay.statuses() == ["open"]


def test_k_is_configurable(tmp_path):
    replay = Replay(tmp_path, detection_cycles=4)

    replay.play([BAD] * 3)
    assert replay.incidents() == []
    replay.step(**BAD)
    assert len(replay.incidents()) == 1


def test_an_incident_resolves_after_exactly_m_healthy_cycles_and_not_before(replay):
    replay.play([BAD, BAD])
    replay.step(**GOOD)
    assert replay.statuses() == ["open"]

    replay.step(**GOOD)
    assert replay.statuses() == ["resolved"]
    assert "resolved" in replay.kinds(replay.incidents()[0])


def test_oscillation_around_the_threshold_never_opens_an_incident(replay):
    replay.play([BAD, GOOD] * 15)

    assert replay.incidents() == []


def test_oscillation_never_resolves_or_duplicates_an_open_incident(replay):
    replay.play([BAD, BAD])

    replay.play([GOOD, BAD] * 15)

    assert replay.statuses() == ["open"]


def test_a_slow_ramp_opens_only_once_the_threshold_is_crossed_for_k_cycles(replay):
    ramp = [{ERRORS: value} for value in (0.02, 0.05, 0.08, 0.11, 0.14, 0.15)]  # at or below 0.15
    replay.play(ramp)
    assert replay.incidents() == []

    replay.step(**{ERRORS: 0.16})
    assert replay.incidents() == []
    replay.step(**{ERRORS: 0.2})
    assert replay.statuses() == ["open"]


def test_recovery_then_a_new_breach_within_the_cooldown_reopens_the_same_incident(tmp_path):
    replay = Replay(tmp_path, reopen_cooldown_seconds=300)
    replay.play([BAD, BAD, GOOD, GOOD])
    assert replay.statuses() == ["resolved"]

    replay.play([BAD, BAD])

    incidents = replay.incidents()
    assert [i["status"] for i in incidents] == ["open"]
    assert incidents[0]["resolved_at"] is None
    assert "reopened" in replay.kinds(incidents[0])


def test_a_recurrence_after_the_cooldown_is_a_new_incident(tmp_path):
    replay = Replay(tmp_path, reopen_cooldown_seconds=300)
    replay.play([BAD, BAD, GOOD, GOOD])
    old = (datetime.now(UTC) - timedelta(seconds=301)).isoformat()
    replay.store.update_incident(replay.incidents()[0]["id"], resolved_at=old)

    replay.play([BAD, BAD])

    assert replay.statuses() == ["resolved", "open"]


def test_a_zero_cooldown_always_opens_a_new_incident(replay):
    replay.play([BAD, BAD, GOOD, GOOD, BAD, BAD])

    assert replay.statuses() == ["resolved", "open"]


def test_closed_incidents_are_never_reopened(tmp_path):
    replay = Replay(tmp_path, reopen_cooldown_seconds=300)
    replay.play([BAD, BAD])
    replay.store.update_incident(replay.incidents()[0]["id"], status="closed", resolved_at=datetime.now(UTC).isoformat())

    replay.play([BAD, BAD])

    assert replay.statuses() == ["closed", "open"]


# ─── No data is not healthy ──────────────────────────────────────────────────


def test_a_prometheus_error_gap_never_resolves_and_recovery_still_does(replay):
    replay.play([BAD, BAD])

    replay.play([ALL_ERRORS] * 10)
    assert replay.statuses() == ["open"]

    replay.step(**GOOD)
    assert replay.statuses() == ["open"]
    replay.step(**GOOD)
    assert replay.statuses() == ["resolved"]


def test_empty_results_without_a_live_target_never_resolve_an_incident(replay):
    replay.play([BAD, BAD])

    replay.play([ALL_NO_DATA] * 10)

    assert replay.statuses() == ["open"]


def test_an_unavailable_cycle_breaks_a_streak_of_breaches(replay):
    replay.play([BAD, ALL_NO_DATA, BAD, ALL_NO_DATA, BAD])

    assert replay.incidents() == []


def test_empty_results_from_a_live_idle_service_count_as_healthy(replay):
    replay.play([BAD, BAD])

    idle = {ERRORS: None, LATENCY: None, DEPENDENCY: None}
    replay.play([idle, idle])

    assert replay.statuses() == ["resolved"]


def test_empty_results_do_not_feed_the_anomaly_baseline(replay):
    replay.play([ALL_NO_DATA] * 6)

    assert replay.engine.detector.samples == {}


def test_signal_states_say_whether_each_signal_is_readable(replay):
    replay.step(**{ERRORS: 0.6, LATENCY: "error", "checkout_cpu_burn": None, DOWN: None})

    assert replay.engine.signal_states[ERRORS] == "breaching"
    assert replay.engine.signal_states[LATENCY] == "unavailable"
    assert replay.engine.signal_states["checkout_cpu_burn"] == "unavailable"
    assert replay.engine.signal_states[DOWN] == "unavailable"

    replay.step(**GOOD)
    assert set(replay.engine.signal_states.values()) == {"ok"}


# ─── A dead target is an outage, not silence ─────────────────────────────────


def test_a_checkout_that_stops_answering_scrapes_opens_an_incident(replay):
    replay.play([{DOWN: 1.0}, {DOWN: 1.0}])

    assert replay.statuses("service:checkout") == ["open"]


def test_a_checkout_that_is_down_does_not_look_healthy_through_empty_series(replay):
    replay.play([{DOWN: 1.0, ERRORS: None, LATENCY: None, DEPENDENCY: None}] * 6)

    assert replay.statuses("service:checkout") == ["open"]
    assert replay.incidents("service:checkout")[0]["status"] != "resolved"


# ─── Telemetry blindness ─────────────────────────────────────────────────────


def test_prolonged_blindness_opens_one_telemetry_incident_and_recovery_resolves_it(tmp_path):
    replay = Replay(tmp_path, blind_seconds=60)

    replay.play([ALL_ERRORS] * 5)  # 25 s
    assert replay.incidents() == []

    replay.play([ALL_ERRORS] * 10)  # 75 s
    blind = replay.incidents("telemetry:blind")
    assert [i["status"] for i in blind] == ["open"]
    assert replay.incidents() == blind  # nothing else was invented from missing data

    replay.play([GOOD] * 2)
    assert replay.statuses("telemetry:blind") == ["resolved"]


def test_blindness_that_ends_before_the_limit_opens_nothing(tmp_path):
    replay = Replay(tmp_path, blind_seconds=60)

    replay.play([ALL_NO_DATA] * 8)  # 40 s
    replay.play([GOOD] * 20)
    replay.play([ALL_NO_DATA] * 8)

    assert replay.incidents() == []


def test_blindness_is_not_reported_when_the_limit_is_zero(replay):
    replay.play([ALL_ERRORS] * 100)

    assert replay.incidents() == []


def test_a_blind_incident_is_not_sent_to_the_investigator(tmp_path):
    replay = Replay(tmp_path, blind_seconds=10)

    replay.play([ALL_ERRORS] * 6)

    assert replay.incidents("telemetry:blind")[0]["status"] == "open"
    assert "investigation_started" not in replay.kinds(replay.incidents()[0])


# ─── Dedup and correlation ───────────────────────────────────────────────────


def test_a_restart_does_not_duplicate_an_open_incident(replay):
    replay.play([BAD, BAD])

    replay.restart()
    replay.play([BAD])

    assert replay.statuses() == ["open"]


def test_concurrent_cycles_open_one_incident_and_start_one_investigation(tmp_path):
    replay = Replay(tmp_path, detection_cycles=1)
    started: list[str] = []
    replay.engine._spawn_investigation = started.append
    replay.answers = BAD
    barrier = threading.Barrier(8)

    def cycle():
        barrier.wait()
        replay.engine.run_once()

    threads = [threading.Thread(target=cycle) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(replay.incidents()) == 1
    assert len(started) == 1


def test_checkout_symptoms_join_the_dependency_incident_when_it_is_the_cause(replay):
    replay.play([{ERRORS: 0.6, DEPENDENCY: 1.0}] * 2)

    assert [i["root_cause_key"] for i in replay.incidents()] == ["dependency:inventory"]


def test_a_dependency_reading_dipping_below_the_threshold_does_not_split_the_incident(replay):
    replay.play([{ERRORS: 0.6, DEPENDENCY: 1.0}] * 2)

    # 0.03 is under the 0.05 attribution threshold but the dependency incident is still active.
    replay.play([{ERRORS: 0.6, DEPENDENCY: 0.03}] * 6)

    assert [i["root_cause_key"] for i in replay.incidents()] == ["dependency:inventory"]


def test_a_recovered_dependency_stops_absorbing_checkout_symptoms(replay):
    replay.play([{ERRORS: 0.6, DEPENDENCY: 1.0}] * 2)

    replay.play([{ERRORS: 0.6, DEPENDENCY: 0.0}] * 2)

    assert sorted(i["root_cause_key"] for i in replay.incidents()) == ["dependency:inventory", "service:checkout"]


def test_an_unreadable_dependency_signal_defers_attribution_instead_of_guessing(replay):
    replay.play([{ERRORS: 0.6, DEPENDENCY: "error"}] * 4)

    assert replay.incidents() == []
