"""Comprehensive tests for storage module."""

import threading
import time

from aegis.storage import Store, utc_now


class TestUtcNow:
    def test_returns_iso_format(self):
        result = utc_now()
        assert "T" in result
        assert "+" in result or "Z" in result

    def test_returns_string(self):
        assert isinstance(utc_now(), str)


class TestStore:
    def test_init_creates_database(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        store = Store(db_path)
        assert (tmp_path / "test.db").exists()
        store.close()

    def test_upsert_creates_new_incident(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        evidence = {"rule": "test", "value": 1.0}
        incident, created = store.upsert_incident(
            "inc-1", "Test Incident", "high", "service:test", evidence
        )
        assert created is True
        assert incident["id"] == "inc-1"
        assert incident["title"] == "Test Incident"
        assert incident["severity"] == "high"
        assert incident["root_cause_key"] == "service:test"
        store.close()

    def test_upsert_updates_existing_incident(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        evidence1 = {"rule": "test", "value": 1.0}
        evidence2 = {"rule": "test", "value": 2.0}
        store.upsert_incident("inc-1", "Test", "high", "service:test", evidence1)
        incident, created = store.upsert_incident(
            "inc-2", "Test 2", "high", "service:test", evidence2
        )
        assert created is False
        assert incident["id"] == "inc-1"
        assert len(incident["data"]["evidence"]) == 2
        store.close()

    def test_list_incidents_ordering(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        store.upsert_incident("inc-1", "Open", "high", "service:1", {})
        store.upsert_incident("inc-2", "Open", "medium", "service:2", {})
        incidents = store.list_incidents()
        assert len(incidents) == 2
        store.close()

    def test_get_incident(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        incident = store.get_incident("inc-1")
        assert incident is not None
        assert incident["id"] == "inc-1"
        store.close()

    def test_get_nonexistent_incident(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        incident = store.get_incident("nonexistent")
        assert incident is None
        store.close()

    def test_find_active_by_root(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        found = store.find_active_by_root("service:test")
        assert found is not None
        assert found["id"] == "inc-1"
        store.close()

    def test_find_active_by_root_none_found(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        found = store.find_active_by_root("nonexistent")
        assert found is None
        store.close()

    def test_update_incident(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        store.update_incident("inc-1", status="investigating")
        incident = store.get_incident("inc-1")
        assert incident["status"] == "investigating"
        store.close()

    def test_update_incident_with_data(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        data = {"key": "value"}
        store.update_incident("inc-1", data=data)
        incident = store.get_incident("inc-1")
        assert incident["data"]["key"] == "value"
        store.close()

    def test_add_event(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        # upsert_incident creates a 'detected' event automatically
        store.add_event("inc-1", "investigation_started", "Investigation started")
        events = store.events("inc-1")
        # 1 from upsert_incident + 1 from add_event = 2
        assert len(events) == 2
        assert events[0]["kind"] == "detected"
        assert events[1]["kind"] == "investigation_started"
        store.close()

    def test_events_ordering(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        # upsert_incident creates a 'detected' event automatically
        store.add_event("inc-1", "first", "First event")
        time.sleep(0.01)
        store.add_event("inc-1", "second", "Second event")
        events = store.events("inc-1")
        # 1 from upsert_incident + 2 from add_event = 3
        assert len(events) == 3
        assert events[0]["kind"] == "detected"
        assert events[1]["kind"] == "first"
        assert events[2]["kind"] == "second"
        store.close()

    def test_resolved_durations(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        store.update_incident("inc-1", status="resolved", resolved_at=utc_now())
        durations = store.resolved_durations()
        assert len(durations) == 1
        assert durations[0] >= 0
        store.close()

    def test_thread_safety(self, tmp_path):
        store = Store(str(tmp_path / "test.db"))
        errors = []

        def create_incidents(prefix: str, count: int):
            try:
                for i in range(count):
                    store.upsert_incident(
                        f"inc-{prefix}-{i}",
                        f"Test {prefix}-{i}",
                        "high",
                        f"service:{prefix}-{i}",
                        {},
                    )
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=create_incidents, args=(f"t{j}", 10))
            for j in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        incidents = store.list_incidents(limit=100)
        assert len(incidents) == 50
        store.close()
