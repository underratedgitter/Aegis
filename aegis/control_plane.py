"""Aegis control plane with authentication, rate limiting, and structured responses."""

from __future__ import annotations

import csv
import hmac
import io
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from statistics import mean
from typing import TYPE_CHECKING, Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
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
    Investigation,
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

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from starlette.responses import Response

settings = Settings()
settings.ensure_dirs()
store = Store(settings.db_path)
telemetry = Telemetry(settings)
engine = IncidentEngine(settings, store, telemetry)
agent = AgentInvestigator(settings, store, telemetry)
remediation = RemediationExecutor(settings, store)

# ─── Audit Log ────────────────────────────────────────────────────────────────

AUDIT_LOG_MAX_ENTRIES = 1000
_audit_log: deque[dict[str, Any]] = deque(maxlen=AUDIT_LOG_MAX_ENTRIES)


def _audit(action: str, detail: dict[str, Any]) -> None:
    """Record an audit event. The buffer is bounded; oldest entries are dropped."""
    _audit_log.append({"action": action, "at": utc_now(), **detail})


# ─── Rate Limiting ────────────────────────────────────────────────────────────

_rate_limits: dict[str, list[float]] = {}
_rate_limit_lock = threading.Lock()
RATE_LIMIT_WINDOW = settings.rate_limit_window
RATE_LIMIT_MAX_REQUESTS = settings.rate_limit_max


def _check_rate_limit(client_ip: str) -> None:
    """
    Allow at most RATE_LIMIT_MAX_REQUESTS per client per window.

    Buckets that fall empty are dropped so a long-running control plane does not
    accumulate one list per source address it has ever seen.
    """
    now = time.time()
    with _rate_limit_lock:
        recent = [t for t in _rate_limits.get(client_ip, []) if now - t < RATE_LIMIT_WINDOW]
        if len(recent) >= RATE_LIMIT_MAX_REQUESTS:
            _rate_limits[client_ip] = recent
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        recent.append(now)
        _rate_limits[client_ip] = recent

        # Evict clients that have gone quiet for a full window.
        if len(_rate_limits) > 1024:
            for ip in [k for k, v in _rate_limits.items() if not v or now - v[-1] >= RATE_LIMIT_WINDOW]:
                del _rate_limits[ip]


# ─── Authentication ───────────────────────────────────────────────────────────

API_KEY = settings.api_key


def verify_api_key(request: Request) -> None:
    """
    Guard state-changing endpoints with a bearer token.

    When AEGIS_API_KEY is unset the check is a no-op, which keeps the local demo
    runnable with no configuration. When it is set, every route that mutates
    incident state or injects chaos requires it.
    """
    if not API_KEY:
        return
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if hmac.compare_digest(token, API_KEY):
            return
    raise HTTPException(status_code=401, detail="Invalid or missing API key.")


# Applied to every route that changes state or triggers an action.
PROTECTED = [Depends(verify_api_key)]


# ─── App Setup ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    engine.start()
    try:
        yield
    finally:
        engine.stop()
        telemetry.close()
        remediation.close()
        store.close()


app = FastAPI(title="Aegis SRE Copilot", version="0.3.0", lifespan=lifespan, docs_url="/docs", redoc_url="/redoc")
# Credentials cannot be combined with a wildcard origin; browsers reject the pair.
# Aegis authenticates with a bearer token, not cookies, so credentials stay off.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.middleware("http")
async def request_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    request_id = request.headers.get("X-Request-Id", str(uuid.uuid4())[:8])
    request.state.request_id = request_id
    client_ip = request.client.host if request.client else "unknown"
    try:
        _check_rate_limit(client_ip)
    except HTTPException as exc:
        # Middleware runs outside FastAPI's exception handlers, so a raised
        # HTTPException here surfaced as a 500 instead of the intended 429.
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers={"X-Request-Id": request_id})
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
def export_incidents(
    export_format: str = Query("json", alias="format", pattern="^(json|csv)$"),
) -> Any:
    incidents = store.list_incidents(limit=1000)
    if export_format == "csv":
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


@app.post("/api/incidents/{incident_id}/investigate", response_model=InvestigateResponse, dependencies=PROTECTED)
def investigate(incident_id: str) -> InvestigateResponse:
    try:
        result = agent.investigate(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return InvestigateResponse(
        incident_id=incident_id, investigation=Investigation.model_validate(result)
    )


@app.post("/api/incidents/{incident_id}/approve", response_model=ApprovalResponse, dependencies=PROTECTED)
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
    _audit("approve", {"incident_id": incident_id, "approver": request.approver})
    return ApprovalResponse(**get_incident(incident_id))


@app.post("/api/incidents/{incident_id}/execute", response_model=ExecuteResponse, dependencies=PROTECTED)
def execute(incident_id: str, request: ApprovalRequest) -> ExecuteResponse:
    try:
        result = remediation.execute(incident_id, request.approver)
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _audit("execute", {"incident_id": incident_id, "approver": request.approver})
    return ExecuteResponse(**result)


@app.post("/api/incidents/batch/approve", dependencies=PROTECTED)
def batch_approve(request: ApprovalRequest) -> dict[str, Any]:
    # list_incidents sorts open/investigating first, so the default page of 50
    # could hide pending recommendations behind a burst of new incidents.
    incidents = store.list_incidents(limit=1000)
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
    _audit("batch_approve", {"approver": request.approver, "count": len(approved)})
    return {"approved": approved, "count": len(approved)}


# ─── Audit Log ────────────────────────────────────────────────────────────────

@app.get("/api/audit", dependencies=PROTECTED)
def audit_log(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"entries": list(_audit_log)[-limit:][::-1], "total": len(_audit_log)}


# ─── Chaos & Telemetry ────────────────────────────────────────────────────────

@app.post("/api/chaos", response_model=ChaosResponse, dependencies=PROTECTED)
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


@app.post("/api/engine/run-once", dependencies=PROTECTED)
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
