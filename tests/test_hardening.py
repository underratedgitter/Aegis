"""Tests for durability and bounded-memory behaviour."""

import sqlite3
import time

import pytest

from aegis import control_plane
from aegis.storage import Store


class TestEventDurability:
    """add_event must persist on its own; callers should not reach for db.commit()."""

    def test_event_is_visible_to_another_connection(self, tmp_path):
        path = str(tmp_path / "aegis.db")
        store = Store(path)
        store.upsert_incident("inc-1", "T", "high", "service:checkout", {"rule": "r"})
        store.add_event("inc-1", "note", "standalone event")

        # A separate connection only sees committed rows.
        other = sqlite3.connect(path)
        try:
            rows = other.execute(
                "SELECT message FROM events WHERE incident_id = ?", ("inc-1",)
            ).fetchall()
        finally:
            other.close()
        store.close()

        assert "standalone event" in [row[0] for row in rows]

    def test_event_survives_reopening_the_store(self, tmp_path):
        path = str(tmp_path / "aegis.db")
        store = Store(path)
        store.upsert_incident("inc-2", "T", "high", "service:checkout", {"rule": "r"})
        store.add_event("inc-2", "note", "persisted")
        store.close()

        reopened = Store(path)
        try:
            messages = [event["message"] for event in reopened.events("inc-2")]
        finally:
            reopened.close()
        assert "persisted" in messages

    def test_deferred_event_is_committed_by_upsert(self, tmp_path):
        """commit=False callers still land, because upsert commits the batch."""
        path = str(tmp_path / "aegis.db")
        store = Store(path)
        store.upsert_incident("inc-3", "T", "high", "service:checkout", {"rule": "r"})
        store.close()

        reopened = Store(path)
        try:
            kinds = [event["kind"] for event in reopened.events("inc-3")]
        finally:
            reopened.close()
        assert "detected" in kinds


class TestAuditLogIsBounded:
    @pytest.fixture(autouse=True)
    def _restore(self):
        saved = list(control_plane._audit_log)
        control_plane._audit_log.clear()
        yield
        control_plane._audit_log.clear()
        control_plane._audit_log.extend(saved)

    def test_oldest_entries_are_dropped(self):
        limit = control_plane.AUDIT_LOG_MAX_ENTRIES
        for i in range(limit + 250):
            control_plane._audit("test", {"n": i})

        assert len(control_plane._audit_log) == limit
        # The most recent entry is retained, the earliest is gone.
        assert control_plane._audit_log[-1]["n"] == limit + 249
        assert control_plane._audit_log[0]["n"] == 250


class TestRateLimiterIsBounded:
    @pytest.fixture(autouse=True)
    def _restore(self):
        saved = dict(control_plane._rate_limits)
        control_plane._rate_limits.clear()
        yield
        control_plane._rate_limits.clear()
        control_plane._rate_limits.update(saved)

    def test_idle_clients_are_evicted(self, monkeypatch):
        """One bucket per source address must not accumulate forever."""
        monkeypatch.setattr(control_plane, "RATE_LIMIT_WINDOW", 0)
        for i in range(1200):
            control_plane._check_rate_limit(f"10.0.0.{i}")
        assert len(control_plane._rate_limits) < 1200

    def test_requests_within_the_limit_are_allowed(self, monkeypatch):
        monkeypatch.setattr(control_plane, "RATE_LIMIT_MAX_REQUESTS", 5)
        monkeypatch.setattr(control_plane, "RATE_LIMIT_WINDOW", 60)
        for _ in range(5):
            control_plane._check_rate_limit("192.0.2.1")

    def test_exceeding_the_limit_raises_429(self, monkeypatch):
        from fastapi import HTTPException

        monkeypatch.setattr(control_plane, "RATE_LIMIT_MAX_REQUESTS", 3)
        monkeypatch.setattr(control_plane, "RATE_LIMIT_WINDOW", 60)
        for _ in range(3):
            control_plane._check_rate_limit("192.0.2.2")
        with pytest.raises(HTTPException) as exc:
            control_plane._check_rate_limit("192.0.2.2")
        assert exc.value.status_code == 429

    def test_the_window_rolls_forward(self, monkeypatch):
        monkeypatch.setattr(control_plane, "RATE_LIMIT_MAX_REQUESTS", 2)
        monkeypatch.setattr(control_plane, "RATE_LIMIT_WINDOW", 0.05)
        control_plane._check_rate_limit("192.0.2.3")
        control_plane._check_rate_limit("192.0.2.3")
        time.sleep(0.06)
        control_plane._check_rate_limit("192.0.2.3")  # window expired, allowed again
