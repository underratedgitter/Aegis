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


def test_evidence_history_is_capped_at_the_configured_size(tmp_path):
    store = Store(str(tmp_path / "db.sqlite"), max_evidence=3)
    for value in range(5):
        incident, _ = store.upsert_incident("inc-cap", "t", "high", "service:cap", {"value": value})

    assert [item["value"] for item in incident["data"]["evidence"]] == [2, 3, 4]


def test_transition_status_is_a_compare_and_swap(tmp_path):
    store = Store(str(tmp_path / "db.sqlite"))
    store.upsert_incident("inc-cas", "t", "high", "service:cas", {})
    store.update_incident("inc-cas", status="approved")

    assert store.transition_status("inc-cas", "approved", "executing") is True
    assert store.transition_status("inc-cas", "approved", "executing") is False
    assert store.transition_status("missing", "approved", "executing") is False
    assert store.get_incident("inc-cas")["status"] == "executing"


def test_recover_interrupted_executions_returns_them_to_approved_with_an_event(tmp_path):
    store = Store(str(tmp_path / "db.sqlite"))
    for incident_id, status in [("inc-stuck", "executing"), ("inc-done", "resolved")]:
        store.upsert_incident(incident_id, "t", "high", f"service:{incident_id}", {})
        store.update_incident(incident_id, status=status)

    assert store.recover_interrupted_executions() == ["inc-stuck"]

    assert store.get_incident("inc-stuck")["status"] == "approved"
    assert store.get_incident("inc-done")["status"] == "resolved"
    event = store.events("inc-stuck")[-1]
    assert event["kind"] == "recovery"
    assert "interrupted" in event["message"]
    assert store.recover_interrupted_executions() == []


def test_executing_incidents_are_listed_before_resolved_ones(tmp_path):
    store = Store(str(tmp_path / "db.sqlite"))
    store.upsert_incident("inc-old-exec", "t", "high", "service:a", {})
    store.update_incident("inc-old-exec", status="executing", last_seen="2020-01-01T00:00:00+00:00")
    store.upsert_incident("inc-new-done", "t", "high", "service:b", {})
    store.update_incident("inc-new-done", status="resolved")

    assert [i["id"] for i in store.list_incidents()] == ["inc-old-exec", "inc-new-done"]
