"""Aegis control plane with authentication, rate limiting, and structured responses."""

from __future__ import annotations

import csv
import hmac
import io
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from statistics import mean
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from aegis.agent import AgentInvestigator
from aegis.incidents import IncidentEngine
from aegis.models import (
    ApprovalRequest,
    ApprovalResponse,
    ChaosRequest,
    ChaosResponse,
    ExecuteResponse,
    HealthResponse,
    InvestigateResponse,
    MetricSnapshot,
    OverviewResponse,
    Runbook,
    ServiceStatus,
    TelemetryStatus,
)
from aegis.remediation import RemediationError, RemediationExecutor
from aegis.settings import Settings
from aegis.storage import Store, utc_now
from aegis.telemetry import Telemetry

settings = Settings()
settings.ensure_dirs()
store = Store(settings.db_path)
telemetry = Telemetry(settings)
engine = IncidentEngine(settings, store, telemetry)
agent = AgentInvestigator(settings, store, telemetry)
remediation = RemediationExecutor(settings, store)

# ─── Audit Log ────────────────────────────────────────────────────────────────

_audit_log: list[dict[str, Any]] = []


def _audit(action: str, detail: dict[str, Any]) -> None:
    """Record an audit event."""
    _audit_log.append({"action": action, "at": utc_now(), **detail})


# ─── Rate Limiting ────────────────────────────────────────────────────────────

_rate_limits: dict[str, list[float]] = {}
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 100


def _check_rate_limit(client_ip: str) -> None:
    now = time.time()
    if client_ip not in _rate_limits:
        _rate_limits[client_ip] = []
    _rate_limits[client_ip] = [t for t in _rate_limits[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    _rate_limits[client_ip].append(now)


# ─── Authentication ───────────────────────────────────────────────────────────

API_KEY = os.getenv("AEGIS_API_KEY", "")


def verify_api_key(request: Request) -> None:
    if not API_KEY:
        return
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if hmac.compare_digest(token, API_KEY):
            return
    raise HTTPException(status_code=401, detail="Invalid or missing API key.")


# ─── App Setup ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI):
    engine.start()
    yield
    engine.stop()


app = FastAPI(title="Aegis SRE Copilot", version="0.3.0", lifespan=lifespan, docs_url="/docs", redoc_url="/redoc")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.middleware("http")
async def request_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-Id", str(uuid.uuid4())[:8])
    request.state.request_id = request_id
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)
    response = await call_next(request)
    response.headers["X-Request-Id"] = request_id
    return response


# ─── Health & Overview ────────────────────────────────────────────────────────

@app.get("/", response_class=FileResponse)
def index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    return HealthResponse(status="ok", service="aegis-control-plane")


@app.get("/api/overview", response_model=OverviewResponse)
def overview() -> OverviewResponse:
    incidents = store.list_incidents()
    durations = store.resolved_durations()
    investigated = sum(bool(item["data"].get("investigation")) for item in incidents)
    return OverviewResponse(
        incidents=incidents[:12],
        open_incidents=sum(item["status"] not in {"resolved", "closed"} for item in incidents),
        mttr_seconds=round(mean(durations), 2) if durations else None,
        resolved_incidents=len(durations),
        agent_assisted_rate=round(investigated / len(incidents), 2) if incidents else None,
        slos=[telemetry.slo_snapshot().model_dump()],
        services=[_service_status("checkout", settings.checkout_url), _service_status("inventory", settings.inventory_url)],
        telemetry={"prometheus": _prometheus_status(), "loki": telemetry.loki_status()},
    )


# ─── Incidents (list, export, and batch BEFORE /{id} routes) ──────────────────

@app.get("/api/incidents")
def list_incidents(page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200), status: str | None = None, severity: str | None = None, search: str | None = None) -> dict[str, Any]:
    all_incidents = store.list_incidents(limit=500)
    if status:
        all_incidents = [i for i in all_incidents if i["status"] == status]
    if severity:
        all_incidents = [i for i in all_incidents if i["severity"] == severity]
    if search:
        sl = search.lower()
        all_incidents = [i for i in all_incidents if sl in i["title"].lower() or sl in i["root_cause_key"].lower()]
    total = len(all_incidents)
    start = (page - 1) * limit
    return {"incidents": all_incidents[start:start + limit], "pagination": {"page": page, "limit": limit, "total": total, "pages": (total + limit - 1) // limit}}


@app.get("/api/incidents/export")
def export_incidents(format: str = Query("json", pattern="^(json|csv)$")) -> Any:
    incidents = store.list_incidents(limit=1000)
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "title", "severity", "status", "root_cause_key", "first_seen", "last_seen", "resolved_at"])
        writer.writeheader()
        for inc in incidents:
            writer.writerow({k: inc.get(k, "") for k in writer.fieldnames})
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=incidents.csv"})
    return {"incidents": incidents, "exported_at": utc_now(), "count": len(incidents)}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {**incident, "events": store.events(incident_id)}


@app.post("/api/incidents/{incident_id}/investigate", response_model=InvestigateResponse)
def investigate(incident_id: str) -> InvestigateResponse:
    try:
        result = agent.investigate(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return InvestigateResponse(incident_id=incident_id, investigation=result)


@app.post("/api/incidents/{incident_id}/approve", response_model=ApprovalResponse)
def approve(incident_id: str, request: ApprovalRequest) -> ApprovalResponse:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] != "recommendation_pending":
        raise HTTPException(status_code=409, detail="Incident has no pending recommendation")
    recommendation = incident["data"].get("recommendation") or {}
    try:
        remediation.validate_recommendation(recommendation)
    except RemediationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    data = {**incident["data"], "approval": {"approver": request.approver, "approved_at": utc_now(), "recommendation": recommendation}}
    store.update_incident(incident_id, status="approved", data=data)
    store.add_event(incident_id, "approval", f"Human approval recorded from {request.approver}", data["approval"])
    store.db.commit()
    _audit("approve", {"incident_id": incident_id, "approver": request.approver})
    return ApprovalResponse(**get_incident(incident_id))


@app.post("/api/incidents/{incident_id}/execute", response_model=ExecuteResponse)
def execute(incident_id: str, request: ApprovalRequest) -> ExecuteResponse:
    try:
        result = remediation.execute(incident_id, request.approver)
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _audit("execute", {"incident_id": incident_id, "approver": request.approver})
    return ExecuteResponse(**result)


@app.post("/api/incidents/batch/approve")
def batch_approve(request: ApprovalRequest) -> dict[str, Any]:
    incidents = store.list_incidents()
    pending = [i for i in incidents if i["status"] == "recommendation_pending"]
    approved = []
    for inc in pending:
        rec = inc["data"].get("recommendation") or {}
        try:
            remediation.validate_recommendation(rec)
        except RemediationError:
            continue
        data = {**inc["data"], "approval": {"approver": request.approver, "approved_at": utc_now(), "recommendation": rec}}
        store.update_incident(inc["id"], status="approved", data=data)
        store.add_event(inc["id"], "approval", f"Batch approval from {request.approver}", data["approval"])
        approved.append(inc["id"])
    store.db.commit()
    _audit("batch_approve", {"approver": request.approver, "count": len(approved)})
    return {"approved": approved, "count": len(approved)}


# ─── Audit Log ────────────────────────────────────────────────────────────────

@app.get("/api/audit")
def audit_log(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"entries": _audit_log[-limit:][::-1], "total": len(_audit_log)}


# ─── Chaos & Telemetry ────────────────────────────────────────────────────────

@app.post("/api/chaos", response_model=ChaosResponse)
def chaos(request: ChaosRequest) -> ChaosResponse:
    target = {"checkout": settings.checkout_url, "inventory": settings.inventory_url}[request.service]
    try:
        response = httpx.post(f"{target.rstrip('/')}/admin/faults", json=request.model_dump(exclude={"service"}), timeout=5)
        response.raise_for_status()
        _audit("chaos_inject", {"service": request.service, "fault": request.fault})
        return ChaosResponse(status="injected", service=request.service, result=response.json())
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Demo service unavailable: {exc}") from exc


@app.get("/api/metrics")
def metrics() -> list[MetricSnapshot]:
    return telemetry.metric_snapshot()


@app.get("/api/logs")
def logs(service: str | None = None, limit: int = 40) -> list[dict[str, Any]]:
    return telemetry.recent_logs(service, max(1, min(limit, 200)))


@app.get("/api/runbooks")
def runbooks() -> list[Runbook]:
    directory = Path(settings.runbook_dir)
    return [Runbook(slug=path.stem, title=path.stem.replace("-", " ").title()) for path in sorted(directory.glob("*.md"))]


@app.post("/api/engine/run-once")
def run_engine_once() -> dict[str, Any]:
    return {"fired": engine.run_once()}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _service_status(name: str, url: str) -> ServiceStatus:
    try:
        response = httpx.get(f"{url.rstrip('/')}/healthz", timeout=1)
        return ServiceStatus(name=name, available=response.is_success, status_code=response.status_code)
    except httpx.HTTPError as exc:
        return ServiceStatus(name=name, available=False, error=str(exc))


def _prometheus_status() -> TelemetryStatus:
    result = telemetry.prometheus_query("up")
    return TelemetryStatus(available=result.get("value") is not None, error=result.get("error"))
