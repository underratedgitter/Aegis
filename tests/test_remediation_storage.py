"""Execution records: idempotency keys, per-target exclusivity, rate limit, crash recovery."""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from aegis.storage import Store

PARAMS = {"fault": "dependency"}


@pytest.fixture
def store(tmp_path):
    store = Store(str(tmp_path / "db.sqlite"))
    store.upsert_incident("inc-1", "t", "high", "dependency:inventory", {"n": 0})
    return store


def claim(store, key="k1", incident="inc-1", target="inventory", **limits):
    return store.claim_execution(
        key,
        incident,
        "clear_fault",
        target,
        PARAMS,
        "op",
        max_per_window=limits.get("max_per_window", 5),
        window_seconds=limits.get("window_seconds", 300),
    )


def test_migration_adds_the_table_to_a_database_created_before_it_existed(tmp_path):
    path = str(tmp_path / "legacy.sqlite")
    legacy = sqlite3.connect(path)
    legacy.executescript(
        """
        CREATE TABLE incidents (id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL,
          status TEXT NOT NULL, root_cause_key TEXT NOT NULL, first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL, resolved_at TEXT, data_json TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
          at TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL,
          data_json TEXT NOT NULL DEFAULT '{}');
        INSERT INTO incidents VALUES ('old', 'kept', 'low', 'open', 'k', 'a', 'b', NULL, '{}');
        """
    )
    legacy.commit()
    legacy.close()

    Store(path).close()
    reopened = Store(path)  # a second start must be a no-op

    assert reopened.get_incident("old")["title"] == "kept"
    assert reopened.executions("old") == []


def test_first_claim_records_an_in_flight_execution(store):
    outcome, row = claim(store)

    assert outcome == "claimed"
    assert row["state"] == "in_flight"
    assert row["idempotency_key"] == "k1"
    assert row["parameters"] == PARAMS
    assert store.get_execution("k1")["approver"] == "op"


@pytest.mark.parametrize("state", ["in_flight", "succeeded", "unknown"])
def test_the_same_key_is_never_claimed_twice_unless_the_last_attempt_failed(store, state):
    claim(store)
    if state != "in_flight":
        store.finish_execution("k1", state, 1, {})

    outcome, row = claim(store)

    assert outcome == "existing"
    assert row["state"] == state


def test_a_failed_execution_can_be_claimed_again_under_the_same_key(store):
    claim(store)
    store.finish_execution("k1", "failed", 3, {"error": "refused"})

    outcome, row = claim(store)

    assert outcome == "claimed"
    assert row["state"] == "in_flight"
    assert row["detail"] == {}
    assert len(store.executions("inc-1")) == 1


def test_only_one_execution_may_be_in_flight_per_target(store):
    claim(store, "k1")

    outcome, row = claim(store, "k2", target="inventory")

    assert outcome == "target_busy"
    assert row["idempotency_key"] == "k1"
    assert claim(store, "k3", target="checkout")[0] == "claimed"


def test_the_target_is_free_again_once_the_execution_finishes(store):
    claim(store, "k1")
    store.finish_execution("k1", "succeeded", 1, {})

    assert claim(store, "k2")[0] == "claimed"


def test_executions_beyond_the_window_limit_are_refused(store):
    for index in range(2):
        claim(store, f"k{index}", max_per_window=2)
        store.finish_execution(f"k{index}", "succeeded", 1, {})

    outcome, oldest = claim(store, "k9", max_per_window=2)

    assert outcome == "rate_limited"
    assert oldest["idempotency_key"] == "k0"
    assert claim(store, "k9", target="checkout", max_per_window=2)[0] == "claimed"


def test_attempts_known_not_to_have_applied_do_not_use_up_the_limit(store):
    for index in range(3):
        claim(store, f"k{index}", max_per_window=1)
        store.finish_execution(f"k{index}", "failed", 3, {})

    assert claim(store, "k9", max_per_window=1)[0] == "claimed"


def test_old_executions_fall_out_of_the_window(store):
    claim(store, "k0", max_per_window=1)
    store.finish_execution("k0", "succeeded", 1, {})
    old = (datetime.now(UTC) - timedelta(seconds=301)).isoformat()
    store.db.execute("UPDATE remediation_executions SET started_at = ?", (old,))
    store.db.commit()

    assert claim(store, "k1", max_per_window=1)[0] == "claimed"


def test_finish_records_state_attempts_and_detail(store):
    claim(store)

    store.finish_execution("k1", "succeeded", 2, {"result": {"ok": True}})

    row = store.get_execution("k1")
    assert (row["state"], row["attempts"], row["detail"]) == ("succeeded", 2, {"result": {"ok": True}})
    assert row["finished_at"]


def test_restart_marks_an_interrupted_execution_unknown_and_reopens_the_incident(store):
    store.merge_incident("inc-1", {}, status="executing")
    claim(store)

    assert store.recover_interrupted_executions() == ["inc-1"]

    assert store.get_execution("k1")["state"] == "unknown"
    assert store.get_incident("inc-1")["status"] == "approved"
    assert claim(store, "k2")[0] == "claimed"  # the target is no longer blocked


def test_restart_completes_an_execution_that_succeeded_before_the_crash(store):
    store.merge_incident("inc-1", {}, status="executing")
    claim(store)
    record = {"action": "clear_fault", "target": "inventory", "idempotency_key": "k1", "result": {"ok": 1}}
    store.finish_execution("k1", "succeeded", 1, record)

    assert store.recover_interrupted_executions() == ["inc-1"]

    incident = store.get_incident("inc-1")
    assert incident["status"] == "open"
    assert incident["data"]["remediation"] == record
    assert [e["kind"] for e in store.events("inc-1")][-1] == "remediation_executed"
