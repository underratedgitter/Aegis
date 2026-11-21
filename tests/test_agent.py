from aegis.agent import AgentInvestigator
from aegis.models import MetricSnapshot
from aegis.settings import Settings
from aegis.storage import Store


class FakeTelemetry:
    def metric_snapshot(self):
        # Must mirror the real Telemetry contract, which returns MetricSnapshot
        # models rather than plain dicts.
        return [
            MetricSnapshot(name="inventory_dependency_errors", value=1.0, query="demo")
        ]

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


class TestToolResultsAreSerialisable:
    """
    Regression: the investigator consumed metric snapshots as dicts, but
    Telemetry.metric_snapshot() returns MetricSnapshot models. Every local
    investigation raised AttributeError, and the LLM path would have failed at
    json.dumps. The old FakeTelemetry returned dicts, so tests never saw it.
    """

    def _agent(self, tmp_path):
        from aegis.telemetry import Telemetry

        settings = Settings(
            db_path=str(tmp_path / "db.sqlite"),
            log_dir=str(tmp_path / "logs"),
            runbook_dir="runbooks",
            # Unreachable on purpose: the snapshot still yields MetricSnapshot models.
            prometheus_url="http://127.0.0.1:1",
        )
        store = Store(settings.db_path)
        return AgentInvestigator(settings, store, Telemetry(settings)), store

    def test_investigation_completes_against_real_telemetry(self, tmp_path):
        agent, store = self._agent(tmp_path)
        incident, _ = store.upsert_incident(
            "inc-real", "dependency", "high", "dependency:inventory", {"value": 1}
        )
        result = agent.investigate(incident["id"])

        assert result["mode"] == "local_fallback"
        assert result["recommendation"]["target"] == "inventory"
        assert store.get_incident(incident["id"])["status"] == "recommendation_pending"

    def test_metrics_tool_result_is_json_serialisable(self, tmp_path):
        """The LLM path passes every tool result through json.dumps."""
        import json

        agent, store = self._agent(tmp_path)
        store.upsert_incident("inc-json", "t", "high", "service:checkout", {"value": 1})
        payload = agent._call_tool("get_current_metrics", {}, "inc-json")

        assert isinstance(payload, list)
        assert all(isinstance(item, dict) for item in payload)
        json.dumps(payload)  # must not raise

    def test_recommendation_passes_the_remediation_allowlist(self, tmp_path):
        """An investigation must produce something the executor will accept."""
        from aegis.remediation import RemediationExecutor

        agent, store = self._agent(tmp_path)
        incident, _ = store.upsert_incident(
            "inc-allow", "dependency", "high", "dependency:inventory", {"value": 1}
        )
        result = agent.investigate(incident["id"])

        executor = RemediationExecutor(agent.settings, store)
        action, target = executor.validate_recommendation(result["recommendation"])
        assert action == "clear_fault"
        assert target == "inventory"
        executor.close()


class TestMalformedLlmOutput:
    """A malformed LLM answer must not be stored or surface as a 500."""

    def _investigate_with_llm_answer(self, tmp_path, monkeypatch, answer):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        settings = Settings(
            db_path=str(tmp_path / "db.sqlite"),
            log_dir=str(tmp_path / "logs"),
            runbook_dir="runbooks",
        )
        store = Store(settings.db_path)
        agent = AgentInvestigator(settings, store, FakeTelemetry())
        monkeypatch.setattr(agent, "_llm_investigation", lambda incident: answer)
        incident, _ = store.upsert_incident(
            "inc-llm", "dependency", "high", "dependency:inventory", {"value": 1}
        )
        return agent.investigate(incident["id"]), store

    def test_missing_recommendation_falls_back_to_local(self, tmp_path, monkeypatch):
        result, store = self._investigate_with_llm_answer(
            tmp_path, monkeypatch, {"hypothesis": "h", "confidence": "high"}
        )

        assert result["mode"] == "local_fallback"
        assert "recommendation" in result["fallback_reason"]
        assert store.get_incident("inc-llm")["data"]["recommendation"]["target"] == "inventory"

    def test_invalid_recommendation_falls_back_to_local(self, tmp_path, monkeypatch):
        answer = {
            "hypothesis": "h",
            "confidence": "certain",
            "recommendation": {"action": ["clear_fault"], "target": "checkout"},
        }
        result, _ = self._investigate_with_llm_answer(tmp_path, monkeypatch, answer)

        assert result["mode"] == "local_fallback"
