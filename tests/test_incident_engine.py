import pytest

from aegis.incidents import IncidentEngine
from aegis.settings import Settings
from aegis.storage import Store


class FakeTelemetry:
    firing = True

    def prometheus_query(self, query):
        if not self.firing:
            return {"value": 0.0}
        if "dependency_errors_total" in query:
            return {"value": 1.0}
        if 'status=~"5.."' in query:
            return {"value": 0.4}
        if "histogram_quantile" in query:
            return {"value": 1.0}
        return {"value": 0.0}

    def metric_snapshot(self):
        return []

    def recent_logs(self, service=None, limit=30):
        return []


def test_engine_correlates_symptoms_and_waits_for_two_healthy_cycles(tmp_path):
    settings = Settings(db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks")
    store = Store(settings.db_path)
    telemetry = FakeTelemetry()
    engine = IncidentEngine(settings, store, telemetry)
    engine._investigate = lambda incident_id: None

    fired = engine.run_once()
    assert fired
    assert len(store.list_incidents()) == 1
    assert store.list_incidents()[0]["root_cause_key"] == "dependency:inventory"

    # Auto-resolution only applies before investigation starts; simulate an
    # incident that is back in the pre-investigation state.
    store.update_incident(store.list_incidents()[0]["id"], status="open")

    telemetry.firing = False
    engine.run_once()
    assert store.list_incidents()[0]["status"] != "resolved"
    engine.run_once()
    assert store.list_incidents()[0]["status"] == "resolved"


def test_engine_can_open_the_same_root_cause_again_after_resolution(tmp_path):
    settings = Settings(db_path=str(tmp_path / "db.sqlite"), runbook_dir="runbooks")
    store = Store(settings.db_path)
    telemetry = FakeTelemetry()
    engine = IncidentEngine(settings, store, telemetry)
    engine._investigate = lambda incident_id: None

    engine.run_once()
    first_id = store.list_incidents()[0]["id"]
    # Auto-resolution only applies before investigation starts.
    store.update_incident(first_id, status="open")
    telemetry.firing = False
    engine.run_once()
    engine.run_once()
    assert store.get_incident(first_id)["status"] == "resolved"

    telemetry.firing = True
    engine.run_once()
    incidents = store.list_incidents()
    assert len(incidents) == 2
    incident_ids = {incident["id"] for incident in incidents}
    assert first_id in incident_ids
    assert len(incident_ids) == 2


def _engine_with_incident(tmp_path, incident_id="inc-resolution"):
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"),
        runbook_dir="runbooks",
        resolution_cycles=2,
    )
    store = Store(settings.db_path)
    engine = IncidentEngine(settings, store, FakeTelemetry())
    engine._investigate = lambda incident_id: None
    incident, _ = store.upsert_incident(
        incident_id, "Test incident", "high", "service:test", {"value": 1}
    )
    return engine, store, incident


def test_open_incident_resolves_after_the_configured_misses(tmp_path):
    engine, store, incident = _engine_with_incident(tmp_path)

    engine._resolve_missing(set())
    assert store.get_incident(incident["id"])["status"] == "open"

    engine._resolve_missing(set())
    assert store.get_incident(incident["id"])["status"] == "resolved"


@pytest.mark.parametrize(
    "status", ["investigating", "recommendation_pending", "approved"]
)
def test_incidents_in_the_remediation_pipeline_do_not_auto_resolve(tmp_path, status):
    engine, store, incident = _engine_with_incident(tmp_path)
    store.update_incident(incident["id"], status=status)

    for _ in range(5):
        engine._resolve_missing(set())

    assert store.get_incident(incident["id"])["status"] == status
    assert incident["id"] not in engine._misses


def test_remediated_incident_gets_a_fresh_resolution_window(tmp_path):
    engine, store, incident = _engine_with_incident(tmp_path)
    store.update_incident(incident["id"], status="approved")

    # Signals stop while the approved action is still in flight.
    for _ in range(5):
        engine._resolve_missing(set())
    assert store.get_incident(incident["id"])["status"] == "approved"

    # Remediation finished and returned the incident to open. It must not
    # resolve on the next cycle using misses accumulated while it was approved.
    store.update_incident(incident["id"], status="open")
    engine._resolve_missing(set())
    assert store.get_incident(incident["id"])["status"] == "open"

    engine._resolve_missing(set())
    assert store.get_incident(incident["id"])["status"] == "resolved"
