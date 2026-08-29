"""Tests for Pydantic models."""

import pytest
from pydantic import ValidationError

from aegis.models import (
    AlertRule,
    AnomalyResult,
    ApprovalRequest,
    ChaosRequest,
    Evidence,
    IncidentStatus,
    InvestigationMode,
    Recommendation,
    RemediationAction,
    Severity,
)


class TestEnums:
    def test_incident_status_values(self):
        assert IncidentStatus.OPEN == "open"
        assert IncidentStatus.INVESTIGATING == "investigating"
        assert IncidentStatus.RECOMMENDATION_PENDING == "recommendation_pending"
        assert IncidentStatus.APPROVED == "approved"
        assert IncidentStatus.RESOLVED == "resolved"
        assert IncidentStatus.CLOSED == "closed"

    def test_severity_values(self):
        assert Severity.LOW == "low"
        assert Severity.MEDIUM == "medium"
        assert Severity.HIGH == "high"
        assert Severity.CRITICAL == "critical"

    def test_investigation_mode_values(self):
        assert InvestigationMode.LOCAL_FALLBACK == "local_fallback"
        assert InvestigationMode.LLM_TOOL_CALLING == "llm_tool_calling"

    def test_remediation_action_values(self):
        assert RemediationAction.CLEAR_FAULT == "clear_fault"
        assert RemediationAction.SCALE_SIMULATION == "scale_simulation"


class TestEvidence:
    def test_valid_evidence(self):
        evidence = Evidence(
            source="prometheus",
            label="error_rate",
            detail="value=0.5 query=sum(rate(...))",
        )
        assert evidence.source == "prometheus"
        assert evidence.label == "error_rate"

    def test_evidence_to_dict(self):
        evidence = Evidence(source="logs", label="recent", detail="error occurred")
        d = evidence.model_dump()
        assert d["source"] == "logs"
        assert "label" in d
        assert "detail" in d


class TestRecommendation:
    def test_valid_recommendation(self):
        rec = Recommendation(
            action=RemediationAction.CLEAR_FAULT,
            target="checkout",
            parameters={"fault": "errors"},
            reason="Test reason",
        )
        assert rec.action == RemediationAction.CLEAR_FAULT
        assert rec.target == "checkout"

    def test_invalid_target(self):
        with pytest.raises(ValidationError):
            Recommendation(
                action=RemediationAction.CLEAR_FAULT,
                target="invalid-service",
                parameters={"fault": "errors"},
            )

    def test_recommendation_to_dict(self):
        rec = Recommendation(
            action=RemediationAction.SCALE_SIMULATION,
            target="inventory",
            parameters={"replicas": 2},
        )
        d = rec.model_dump()
        assert d["action"] == "scale_simulation"
        assert d["parameters"]["replicas"] == 2


class TestAlertRule:
    def test_fires_above_threshold(self):
        rule = AlertRule(
            name="test",
            title="Test Rule",
            severity=Severity.HIGH,
            query="test_query",
            threshold=0.5,
            root_cause_key="service:test",
        )
        assert rule.fires(0.6) is True
        assert rule.fires(0.4) is False
        assert rule.fires(0.5) is False  # gt, not gte

    def test_fires_below_threshold(self):
        rule = AlertRule(
            name="test",
            title="Test Rule",
            severity=Severity.HIGH,
            query="test_query",
            threshold=0.5,
            root_cause_key="service:test",
            direction="lt",
        )
        assert rule.fires(0.4) is True
        assert rule.fires(0.6) is False
        assert rule.fires(0.5) is False  # lt, not lte

    def test_fires_none_value(self):
        rule = AlertRule(
            name="test",
            title="Test Rule",
            severity=Severity.HIGH,
            query="test_query",
            threshold=0.5,
            root_cause_key="service:test",
        )
        assert rule.fires(None) is False


class TestAnomalyResult:
    def test_anomaly_result_creation(self):
        result = AnomalyResult(
            value=1.0,
            baseline=0.5,
            z_score=2.5,
            anomalous=False,
        )
        assert result.value == 1.0
        assert result.baseline == 0.5
        assert result.z_score == 2.5
        assert result.anomalous is False


class TestChaosRequest:
    def test_valid_request(self):
        req = ChaosRequest(
            service="checkout",
            fault="latency",
            duration_seconds=60,
            intensity=1.0,
        )
        assert req.service == "checkout"
        assert req.fault == "latency"

    def test_invalid_service(self):
        with pytest.raises(ValidationError):
            ChaosRequest(service="invalid", fault="latency")

    def test_invalid_fault(self):
        with pytest.raises(ValidationError):
            ChaosRequest(service="checkout", fault="invalid")

    def test_duration_bounds(self):
        with pytest.raises(ValidationError):
            ChaosRequest(service="checkout", fault="latency", duration_seconds=0)
        with pytest.raises(ValidationError):
            ChaosRequest(service="checkout", fault="latency", duration_seconds=901)


class TestApprovalRequest:
    def test_default_approver(self):
        req = ApprovalRequest()
        assert req.approver == "human-operator"

    def test_custom_approver(self):
        req = ApprovalRequest(approver="admin")
        assert req.approver == "admin"

    def test_approver_length_bounds(self):
        with pytest.raises(ValidationError):
            ApprovalRequest(approver="a")
        with pytest.raises(ValidationError):
            ApprovalRequest(approver="x" * 81)
