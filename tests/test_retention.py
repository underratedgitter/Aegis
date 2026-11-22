"""Events are paged, counted from an index, and old resolved history is pruned by retention."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.control_plane import app, store
from aegis.incidents import IncidentEngine
from aegis.settings import Settings, SettingsError
from aegis.storage import Store


@pytest.fixture
def local(tmp_path):
    local_store = Store(str(tmp_path / "aegis.db"))
    yield local_store
    local_store.close()


def days_ago(days):
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


def finished_incident(target, incident_id, *, age_days, status="resolved", events=3):
    """A resolved incident with events and an execution, finished `age_days` ago."""
    target.upsert_incident(incident_id, "t", "high", f"root:{incident_id}", {"n": 0})
    for n in range(events):
        target.add_event(incident_id, "note", f"event {n}")
    target.claim_execution(
        f"key-{incident_id}", incident_id, "clear_fault", f"target-{incident_id}", {}, "op",
        max_per_window=5, window_seconds=300,
    )
    target.update_incident(incident_id, status=status, resolved_at=days_ago(age_days))


class TestEventPaging:
    def test_events_default_to_the_latest_page_oldest_first(self, local):
        local.upsert_incident("inc-1", "t", "high", "root:1", {})
        for n in range(250):
            local.add_event("inc-1", "note", f"event {n}")

        events = local.events("inc-1")

        assert len(events) == 100
        assert events[-1]["message"] == "event 249"
        assert [e["id"] for e in events] == sorted(e["id"] for e in events)

    def test_a_limit_and_a_before_cursor_page_backwards(self, local):
        local.upsert_incident("inc-1", "t", "high", "root:1", {})
        for n in range(30):
            local.add_event("inc-1", "note", f"event {n}")

        newest = local.events("inc-1", limit=10)
        older = local.events("inc-1", limit=10, before_id=newest[0]["id"])

        assert [e["message"] for e in newest] == [f"event {n}" for n in range(20, 30)]
        assert len(older) == 10
        assert older[-1]["id"] < newest[0]["id"]
        assert local.count_events("inc-1") == 31  # the 30 notes and the "detected" event

    def test_events_of_other_incidents_are_not_mixed_in(self, local):
        local.upsert_incident("inc-1", "t", "high", "root:1", {})
        local.upsert_incident("inc-2", "t", "high", "root:2", {})

        assert {e["incident_id"] for e in local.events("inc-2")} == {"inc-2"}

    def test_the_api_returns_the_latest_events_with_a_total_and_pages_back(self):
        client = TestClient(app)
        store.upsert_incident("inc-retention-api", "t", "high", "root:retention-api", {})
        for n in range(150):
            store.add_event("inc-retention-api", "note", f"event {n}")

        body = client.get("/api/incidents/inc-retention-api").json()
        assert len(body["events"]) == 100
        assert body["events_total"] == 151
        assert body["events"][-1]["message"] == "event 149"

        older = client.get(
            "/api/incidents/inc-retention-api",
            params={"events_limit": 20, "events_before": body["events"][0]["id"]},
        ).json()
        assert len(older["events"]) == 20
        assert older["events"][-1]["id"] < body["events"][0]["id"]

    def test_the_api_caps_the_events_limit(self):
        response = TestClient(app).get("/api/incidents/x", params={"events_limit": 100000})
        assert response.status_code == 422


def test_the_timeline_reports_earlier_events_from_the_total_the_api_sends():
    app_js = (Path(control_plane.__file__).parent / "static" / "app.js").read_text()

    assert "timelineHtml(incident.events ?? [], incident.events_total)" in app_js
    assert "const hidden = total - shown.length;" in app_js


class TestEventCounts:
    def test_counting_by_kind_uses_the_kind_index(self, local):
        plan = " ".join(
            row[3]
            for row in local.db.execute(
                "EXPLAIN QUERY PLAN SELECT kind, COUNT(*) FROM events WHERE kind IN ('a','b') "
                "GROUP BY kind"
            )
        )
        assert "events_kind_idx" in plan

    def test_counts_are_unchanged(self, local):
        local.upsert_incident("inc-1", "t", "high", "root:1", {})
        local.add_event("inc-1", "remediation_failed", "x")
        local.add_event("inc-1", "remediation_failed", "y")

        assert local.event_counts(["remediation_failed", "remediation_executed"]) == {
            "remediation_failed": 2
        }


class TestPrune:
    def test_old_resolved_incidents_go_with_their_events_and_executions(self, local):
        finished_incident(local, "inc-old", age_days=40)

        removed = local.prune(older_than_days=30)

        assert removed == {"incidents": 1, "events": 4, "executions": 1}
        assert local.get_incident("inc-old") is None
        assert local.events("inc-old") == []
        assert local.executions("inc-old") == []

    def test_recent_and_active_history_is_kept(self, local):
        finished_incident(local, "inc-recent", age_days=5)
        finished_incident(local, "inc-active", age_days=400, status="open")
        finished_incident(local, "inc-executing", age_days=400, status="executing")
        finished_incident(local, "inc-pending", age_days=400, status="recommendation_pending")

        assert local.prune(older_than_days=30) == {"incidents": 0, "events": 0, "executions": 0}
        for incident_id in ("inc-recent", "inc-active", "inc-executing", "inc-pending"):
            assert local.get_incident(incident_id) is not None
            assert local.events(incident_id)

    def test_closed_incidents_without_a_resolution_time_age_by_last_seen(self, local):
        local.upsert_incident("inc-closed", "t", "high", "root:closed", {})
        local.update_incident("inc-closed", status="closed", last_seen=days_ago(90))

        assert local.prune(older_than_days=30)["incidents"] == 1

    def test_the_audit_log_is_never_pruned(self, local):
        finished_incident(local, "inc-old", age_days=400)
        local.add_audit("approve", {"incident_id": "inc-old"})

        local.prune(older_than_days=1)

        assert local.audit_entries()[1] == 1


class FakeClock:
    now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def engine_for(tmp_path):
    made = []

    def build(retention_days):
        settings = Settings(
            db_path=str(tmp_path / f"db{len(made)}.sqlite"),
            runbook_dir="runbooks",
            retention_days=retention_days,
        )
        engine_store = Store(settings.db_path)
        made.append(engine_store)
        runner = IncidentEngine(settings, engine_store, telemetry=None)  # type: ignore[arg-type]
        return runner, engine_store

    yield build
    for opened in made:
        opened.close()


class TestEnginePrunes:
    def test_a_cycle_prunes_history_older_than_the_retention(self, engine_for):
        runner, engine_store = engine_for(30)
        finished_incident(engine_store, "inc-old", age_days=40)
        finished_incident(engine_store, "inc-new", age_days=1)

        runner._prune_history()

        assert engine_store.get_incident("inc-old") is None
        assert engine_store.get_incident("inc-new") is not None

    def test_zero_keeps_everything(self, engine_for):
        runner, engine_store = engine_for(0)
        finished_incident(engine_store, "inc-old", age_days=4000)

        runner._prune_history()

        assert engine_store.get_incident("inc-old") is not None

    def test_pruning_runs_at_most_once_per_interval(self, engine_for):
        runner, engine_store = engine_for(30)
        clock = FakeClock()
        runner._clock = clock
        runner._prune_history()
        finished_incident(engine_store, "inc-old", age_days=40)

        clock.now += 60
        runner._prune_history()
        assert engine_store.get_incident("inc-old") is not None

        clock.now += 3600
        runner._prune_history()
        assert engine_store.get_incident("inc-old") is None

    def test_a_failing_prune_does_not_fail_the_cycle(self, engine_for, monkeypatch):
        runner, engine_store = engine_for(30)

        def locked(**_kwargs):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(engine_store, "prune", locked)

        runner._prune_history()  # does not raise


class TestSetting:
    def test_default_is_thirty_days_and_zero_is_allowed(self, monkeypatch):
        monkeypatch.delenv("AEGIS_RETENTION_DAYS", raising=False)
        assert Settings().retention_days == 30
        monkeypatch.setenv("AEGIS_RETENTION_DAYS", "0")
        assert Settings().retention_days == 0

    def test_negative_is_refused(self, monkeypatch):
        monkeypatch.setenv("AEGIS_RETENTION_DAYS", "-1")
        with pytest.raises(SettingsError, match="AEGIS_RETENTION_DAYS"):
            Settings()
