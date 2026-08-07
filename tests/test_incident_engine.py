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
