"""Pydantic models for type-safe data structures in Aegis."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ─── Enums ────────────────────────────────────────────────────────────────────

class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RECOMMENDATION_PENDING = "recommendation_pending"
    APPROVED = "approved"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvestigationMode(StrEnum):
    LOCAL_FALLBACK = "local_fallback"
    LLM_TOOL_CALLING = "llm_tool_calling"


class RemediationAction(StrEnum):
    CLEAR_FAULT = "clear_fault"
    SCALE_SIMULATION = "scale_simulation"


# ─── Evidence & Investigation ─────────────────────────────────────────────────

class Evidence(BaseModel):
    source: str
    label: str
    detail: str


class Recommendation(BaseModel):
    action: RemediationAction
    target: str = Field(pattern="^(checkout|inventory)$")
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class Investigation(BaseModel):
    mode: InvestigationMode
    hypothesis: str
    confidence: str = Field(pattern="^(low|medium|high)$")
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: Recommendation
    next_checks: list[str] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    fallback_reason: str | None = None


# ─── Incident ─────────────────────────────────────────────────────────────────

class IncidentData(BaseModel):
    latest_evidence: dict[str, Any] | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    investigation: Investigation | None = None
    recommendation: Recommendation | None = None
    approval: dict[str, Any] | None = None
    remediation: dict[str, Any] | None = None


class Incident(BaseModel):
    id: str
    title: str
    severity: Severity
    status: IncidentStatus
    root_cause_key: str
    first_seen: str
    last_seen: str
    resolved_at: str | None = None
    data: IncidentData = Field(default_factory=IncidentData)


class IncidentEvent(BaseModel):
    id: int
    incident_id: str
    at: str
    kind: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


# ─── API Requests ─────────────────────────────────────────────────────────────

class ChaosRequest(BaseModel):
    service: str = Field(pattern="^(checkout|inventory)$")
    fault: str = Field(pattern="^(latency|errors|dependency|cpu)$")
    duration_seconds: float = Field(default=60, ge=1, le=900)
    intensity: float = Field(default=1, ge=0.1, le=10)


class ApprovalRequest(BaseModel):
    approver: str = Field(default="human-operator", min_length=2, max_length=80)


class FaultClearRequest(BaseModel):
    fault: str | None = Field(default=None, pattern="^(latency|errors|dependency|cpu)$")


class ScaleRequest(BaseModel):
    replicas: int = Field(default=1, ge=1, le=3)


# ─── API Responses ────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    service: str


class ServiceStatus(BaseModel):
    name: str
    available: bool
    status_code: int | None = None
    error: str | None = None


class TelemetryStatus(BaseModel):
    available: bool
    error: str | None = None
    status_code: int | None = None


class OverviewResponse(BaseModel):
    incidents: list[dict[str, Any]]
    open_incidents: int
    mttr_seconds: float | None
    resolved_incidents: int
    agent_assisted_rate: float | None
    slos: list[dict[str, Any]]
    services: list[ServiceStatus]
    telemetry: dict[str, TelemetryStatus]


class ChaosResponse(BaseModel):
    status: str = "injected"
    service: str
    result: dict[str, Any]


class InvestigateResponse(BaseModel):
    incident_id: str
    investigation: Investigation


class ApprovalResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    root_cause_key: str
    first_seen: str
    last_seen: str
    resolved_at: str | None
    data: dict[str, Any]
    events: list[dict[str, Any]]


class ExecuteResponse(BaseModel):
    status: str = "executed"
    incident_id: str
    action: str
    target: str
    result: dict[str, Any]


class MetricSnapshot(BaseModel):
    name: str
    query: str
    value: float | None
    series: list[dict[str, Any]] = Field(default_factory=list)
    source: str = "prometheus"
    error: str | None = None


class SLOSnapshot(BaseModel):
    name: str
    target: float
    actual: float | None
    error_budget_remaining: float | None
    window: str


class Runbook(BaseModel):
    slug: str
    title: str


# ─── Engine ───────────────────────────────────────────────────────────────────

class AlertRule(BaseModel):
    name: str
    title: str
    severity: Severity
    query: str
    threshold: float
    root_cause_key: str
    direction: str = "gt"

    def fires(self, value: float | None) -> bool:
        if value is None:
            return False
        return value > self.threshold if self.direction == "gt" else value < self.threshold


class AnomalyResult(BaseModel):
    value: float
    baseline: float | None
    z_score: float | None
    anomalous: bool


class EngineRunResult(BaseModel):
    fired: list[dict[str, Any]]
