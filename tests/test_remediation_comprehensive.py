"""Comprehensive tests for remediation module."""

from unittest.mock import MagicMock, patch

import pytest

from aegis.remediation import RemediationError, RemediationExecutor
from aegis.settings import Settings
from aegis.storage import Store


@pytest.fixture
def settings():
    return Settings(
        checkout_url="http://localhost:8080",
        inventory_url="http://localhost:8081",
    )


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "test.db"))


@pytest.fixture
def executor(settings, store):
    return RemediationExecutor(settings, store)


class TestRemediationExecutor:
    def test_validate_recommendation_clear_fault(self, executor):
        recommendation = {
            "action": "clear_fault",
            "target": "checkout",
            "parameters": {"fault": "errors"},
        }
        action, target = executor.validate_recommendation(recommendation)
        assert action == "clear_fault"
        assert target == "checkout"

    def test_validate_recommendation_scale_simulation(self, executor):
        recommendation = {
            "action": "scale_simulation",
            "target": "inventory",
            "parameters": {"replicas": 2},
        }
        action, target = executor.validate_recommendation(recommendation)
        assert action == "scale_simulation"
        assert target == "inventory"

    def test_validate_recommendation_invalid_action(self, executor):
        recommendation = {
            "action": "invalid_action",
            "target": "checkout",
            "parameters": {},
        }
        with pytest.raises(RemediationError, match="outside the Aegis allowlist"):
            executor.validate_recommendation(recommendation)

    def test_validate_recommendation_invalid_target(self, executor):
        recommendation = {
            "action": "clear_fault",
            "target": "invalid",
            "parameters": {"fault": "errors"},
        }
        with pytest.raises(RemediationError, match="outside the Aegis allowlist"):
            executor.validate_recommendation(recommendation)

    def test_validate_recommendation_invalid_fault(self, executor):
        recommendation = {
            "action": "clear_fault",
            "target": "checkout",
            "parameters": {"fault": "invalid_fault"},
        }
        with pytest.raises(RemediationError, match="outside the Aegis allowlist"):
            executor.validate_recommendation(recommendation)

    def test_validate_recommendation_fault_not_valid_for_target(self, executor):
        recommendation = {
            "action": "clear_fault",
            "target": "checkout",
            "parameters": {"fault": "dependency"},
        }
        with pytest.raises(RemediationError, match="not valid for the selected target"):
            executor.validate_recommendation(recommendation)

    def test_validate_recommendation_invalid_replicas(self, executor):
        recommendation = {
            "action": "scale_simulation",
            "target": "checkout",
            "parameters": {"replicas": 5},
        }
        with pytest.raises(RemediationError, match="between 1 and 3"):
            executor.validate_recommendation(recommendation)

    def test_validate_recommendation_non_dict(self, executor):
        with pytest.raises(RemediationError, match="must be an object"):
            executor.validate_recommendation("invalid")

    def test_execute_incident_not_found(self, executor):
        with pytest.raises(RemediationError, match="not found"):
            executor.execute("nonexistent", "approver")

    def test_execute_not_approved(self, executor, store):
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        with pytest.raises(RemediationError, match="requires an approved recommendation"):
            executor.execute("inc-1", "approver")

    def test_execute_clear_fault(self, executor, store):
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        recommendation = {
            "action": "clear_fault",
            "target": "checkout",
            "parameters": {"fault": "errors"},
        }
        store.update_incident(
            "inc-1",
            status="approved",
            data={
                "approval": {
                    "approver": "test",
                    "approved_at": "2024-01-01T00:00:00",
                    "recommendation": recommendation,
                }
            },
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "cleared"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(executor._client, "post", return_value=mock_response):
            result = executor.execute("inc-1", "approver")
            assert result["status"] == "executed"
            assert result["action"] == "clear_fault"

    def test_execute_scale_simulation(self, executor, store):
        store.upsert_incident("inc-1", "Test", "high", "service:test", {})
        recommendation = {
            "action": "scale_simulation",
            "target": "checkout",
            "parameters": {"replicas": 2},
        }
        store.update_incident(
            "inc-1",
            status="approved",
            data={
                "approval": {
                    "approver": "test",
                    "approved_at": "2024-01-01T00:00:00",
                    "recommendation": recommendation,
                }
            },
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "scaled"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(executor._client, "post", return_value=mock_response):
            result = executor.execute("inc-1", "approver")
            assert result["status"] == "executed"
            assert result["action"] == "scale_simulation"
