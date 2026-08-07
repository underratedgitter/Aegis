from aegis.agent import AgentInvestigator
from aegis.settings import Settings
from aegis.storage import Store


class FakeTelemetry:
    def metric_snapshot(self):
        return [{"name": "inventory_dependency_errors", "value": 1.0, "query": "demo"}]

    def recent_logs(self, service=None, limit=30):
        return [{"message": "dependency_failure", "service": "checkout"}]


def test_local_investigator_proposes_bounded_dependency_fix(tmp_path):
    settings = Settings(
        db_path=str(tmp_path / "db.sqlite"), log_dir=str(tmp_path / "logs"), runbook_dir="runbooks"
    )
    store = Store(settings.db_path)
    incident, _ = store.upsert_incident(
        "inc-test", "dependency", "high", "dependency:inventory", {"value": 1}
    )
    result = AgentInvestigator(settings, store, FakeTelemetry()).investigate(incident["id"])
    assert result["mode"] == "local_fallback"
    assert result["recommendation"]["action"] == "clear_fault"
    assert result["recommendation"]["target"] == "inventory"
    assert store.get_incident(incident["id"])["status"] == "recommendation_pending"
