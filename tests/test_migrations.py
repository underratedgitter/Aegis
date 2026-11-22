"""Schema migrations: a database written by an older build upgrades in place, transactionally."""

import sqlite3

import pytest

from aegis import storage
from aegis.storage import MIGRATIONS, Store

LEGACY_SCHEMA = """
CREATE TABLE incidents (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
  root_cause_key TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  resolved_at TEXT, data_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, at TEXT NOT NULL,
  kind TEXT NOT NULL, message TEXT NOT NULL, data_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX events_incident_idx ON events(incident_id, id);
CREATE TABLE remediation_executions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, idempotency_key TEXT NOT NULL UNIQUE,
  incident_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  parameters_json TEXT NOT NULL DEFAULT '{}', approver TEXT NOT NULL, state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, started_at TEXT NOT NULL, finished_at TEXT,
  detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX remediation_incident_idx ON remediation_executions(incident_id, id);
CREATE UNIQUE INDEX remediation_one_in_flight
  ON remediation_executions(target) WHERE state = 'in_flight';
"""


def legacy_database(path):
    """A database as the first release wrote it: no user_version, no migration bookkeeping."""
    db = sqlite3.connect(path)
    db.executescript(LEGACY_SCHEMA)
    db.execute(
        "INSERT INTO incidents(id,title,severity,status,root_cause_key,first_seen,last_seen,data_json)"
        " VALUES('inc-old','Old','high','recommendation_pending','service:x','t0','t1','{\"k\": 1}')"
    )
    db.execute(
        "INSERT INTO events(incident_id,at,kind,message) VALUES('inc-old','t0','detected','seen')"
    )
    db.execute(
        "INSERT INTO remediation_executions(idempotency_key,incident_id,action,target,approver,"
        "state,started_at) VALUES('k1','inc-old','clear_fault','checkout','ops','succeeded','t0')"
    )
    db.commit()
    assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    db.close()


def version(path):
    db = sqlite3.connect(path)
    try:
        return db.execute("PRAGMA user_version").fetchone()[0]
    finally:
        db.close()


def test_a_fresh_database_is_created_at_the_latest_version(tmp_path):
    path = str(tmp_path / "aegis.db")
    Store(path).close()
    assert version(path) == len(MIGRATIONS)


def test_a_legacy_database_upgrades_in_place_and_keeps_its_data(tmp_path):
    path = str(tmp_path / "aegis.db")
    legacy_database(path)

    store = Store(path)
    try:
        incident = store.get_incident("inc-old")
        assert incident is not None
        assert incident["status"] == "recommendation_pending"
        assert incident["data"] == {"k": 1}
        assert [e["kind"] for e in store.events("inc-old")] == ["detected"]
        assert store.get_execution("k1") is not None
        store.add_event("inc-old", "signal", "still firing")
    finally:
        store.close()
    assert version(path) == len(MIGRATIONS)


def test_migrations_that_already_ran_are_not_applied_again(tmp_path, monkeypatch):
    path = str(tmp_path / "aegis.db")
    legacy_database(path)
    Store(path).close()

    poisoned = (("SELECT * FROM table_that_does_not_exist",), *MIGRATIONS[1:])
    monkeypatch.setattr(storage, "MIGRATIONS", poisoned)
    Store(path).close()


def test_a_failing_migration_rolls_back_and_leaves_the_version_unchanged(tmp_path, monkeypatch):
    path = str(tmp_path / "aegis.db")
    Store(path).close()
    latest = len(MIGRATIONS)
    broken = (
        *MIGRATIONS,
        ("CREATE TABLE half_done (id INTEGER)", "CREATE TABLE half_done (id INTEGER)"),
    )
    monkeypatch.setattr(storage, "MIGRATIONS", broken)

    with pytest.raises(sqlite3.OperationalError):
        Store(path)

    assert version(path) == latest
    db = sqlite3.connect(path)
    try:
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        db.close()
    assert "half_done" not in tables


def test_a_store_that_fails_to_open_does_not_leak_its_connection(tmp_path, monkeypatch):
    path = str(tmp_path / "aegis.db")
    Store(path).close()
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version = {len(MIGRATIONS) + 1}")
    db.close()
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        opened.append(real_connect(*args, **kwargs))
        return opened[-1]

    monkeypatch.setattr(storage.sqlite3, "connect", recording_connect)

    with pytest.raises(RuntimeError):
        Store(path)

    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        opened[0].execute("SELECT 1")


def test_a_database_from_a_newer_build_is_refused(tmp_path):
    path = str(tmp_path / "aegis.db")
    Store(path).close()
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version = {len(MIGRATIONS) + 1}")
    db.close()

    with pytest.raises(RuntimeError, match="newer"):
        Store(path)
