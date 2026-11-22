"""Aegis control plane with authentication, rate limiting, and structured responses."""

from __future__ import annotations

import csv
import io
import sqlite3
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
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest

from aegis.agent import LLM_BREAKER_COOLDOWN_SECONDS, LLM_BREAKER_FAILURES, AgentInvestigator
from aegis.auth import AuthFailureLimiter, bearer_header, presented_token, token_matches
from aegis.breaker import CircuitBreaker
from aegis.http_security import (
    DOCS_CSP,
    UI_CSP,
    BodyLimitMiddleware,
    SecurityHeadersMiddleware,
    internal_error_response,
)
from aegis.logging_utils import configure_logging
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
    ReadyResponse,
    Runbook,
    ServiceStatus,
    TelemetryStatus,
)
from aegis.remediation import RemediationError, RemediationExecutor
from aegis.selfmetrics import ControlPlaneCollector
from aegis.settings import Settings
from aegis.storage import Store, utc_now
from aegis.supervisor import EngineStatus, SupervisedEngine
from aegis.telemetry import Telemetry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

logger = configure_logging("aegis-control-plane")
settings = Settings()
settings.ensure_dirs()
store = Store(
    settings.db_path, settings.max_evidence_history, settings.signal_event_interval
)
telemetry = Telemetry(settings)
llm_breaker = CircuitBreaker("llm", LLM_BREAKER_FAILURES, LLM_BREAKER_COOLDOWN_SECONDS)
agent = AgentInvestigator(settings, store, telemetry, llm_breaker=llm_breaker)
engine = SupervisedEngine(
    settings,
    store,
    telemetry,
    breakers={
        "prometheus": telemetry.prometheus_breaker,
        "loki": telemetry.loki_breaker,
        "llm": llm_breaker,
    },
)
# One investigator for manual and automatic investigations, so they share the LLM breaker.
engine.agent = agent
REGISTRY.register(ControlPlaneCollector(store, engine))

# ─── Audit Log ────────────────────────────────────────────────────────────────

AUDIT_LOG_MAX_ENTRIES = 1000
_audit_log: deque[dict[str, Any]] = deque(maxlen=AUDIT_LOG_MAX_ENTRIES)


def _audit(action: str, detail: dict[str, Any]) -> None:
    """Record an audit event. The buffer is bounded; oldest entries are dropped."""
    _audit_log.append({"action": action, "at": utc_now(), **detail})


remediation = RemediationExecutor(settings, store, telemetry=telemetry, audit=_audit)


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
_auth_failures = AuthFailureLimiter(settings.auth_fail_max, settings.auth_fail_window)


def _warn_if_unauthenticated() -> None:
    """Make demo mode impossible to miss in the logs of a real deployment."""
    if not API_KEY:
        logger.warning(
            "SECURITY WARNING: AEGIS_API_KEY is not set. Approve, execute, investigate, "
            "run-once and audit endpoints are open to anyone who can reach this port, and "
            "fault injection is disabled. Set AEGIS_API_KEY before exposing Aegis beyond localhost."
        )


def verify_api_key(request: Request) -> None:
    """
    Guard state-changing endpoints with a bearer token.

    When AEGIS_API_KEY is unset the check is a no-op, which keeps the local demo
    runnable with no configuration. When it is set, every route that mutates
    incident state or injects chaos requires it. A client that keeps presenting
    wrong tokens is locked out with 429 for the rest of the failure window.
    """
    if not API_KEY:
        return
    client = request.client.host if request.client else "unknown"
    retry_after = _auth_failures.retry_after(client)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="Too many failed authentication attempts.",
            headers={"Retry-After": str(retry_after)},
        )
    token = presented_token(request.headers.get("Authorization", ""))
    if token is not None:
        if token_matches(token, API_KEY):
            return
        _auth_failures.record_failure(client)
    raise HTTPException(status_code=401, detail="Invalid or missing API key.")


# Applied to every route that changes state or triggers an action.
PROTECTED = [Depends(verify_api_key)]


# ─── App Setup ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    _warn_if_unauthenticated()
    store.recover_interrupted_executions()
    remediation.resume_verifications()
    engine.start()
    try:
        yield
    finally:
        # Stop the engine first so no background thread is writing when the database closes.
        try:
            engine.stop()
        finally:
            # Verification threads read telemetry and write the store, so they stop first.
            remediation.close()
            telemetry.close()
            store.close()


app = FastAPI(title="Aegis SRE Copilot", version="0.3.0", lifespan=lifespan, docs_url="/docs", redoc_url="/redoc")
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


# Innermost on purpose: a body-limit error raised while the route reads the body
# only becomes a 413 if nothing between it and FastAPI wraps the receive channel.
app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)


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


def _install_hardening(application: FastAPI, cfg: Settings) -> None:
    """
    Add the request/response guards; the last one added is the outermost.

    Security headers wrap everything, so CORS preflights and 413s carry them too.
    CORS sits outside the body limit so browsers can read a 413. With no
    AEGIS_CORS_ORIGINS there is no CORS middleware and browsers keep their
    same-origin default. Aegis authenticates with a bearer token, not cookies,
    so credentials stay off.
    """
    if cfg.cors_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(cfg.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
            expose_headers=["X-Request-Id", "Retry-After"],
            max_age=600,
        )
    application.add_middleware(
        SecurityHeadersMiddleware, csp=UI_CSP, path_csp={"/docs": DOCS_CSP, "/redoc": DOCS_CSP}
    )
    application.add_exception_handler(Exception, internal_error_response)


_install_hardening(app, settings)


# ─── Health & Overview ────────────────────────────────────────────────────────

@app.get("/", response_class=FileResponse)
def index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    return HealthResponse(status="ok", service="aegis-control-plane")


@app.get("/readyz", response_model=ReadyResponse)
def readyz() -> ReadyResponse | JSONResponse:
    """
    Readiness: 503 if the database is broken or the engine is stopped or stalled.

    A failing engine with a fresh heartbeat, and Prometheus/Loki outages, only degrade it.
    """
    engine_status = engine.status()
    checks: dict[str, str] = {"database": "ok", "engine": engine_status.state}
    if engine_status.reason:
        checks["engine_reason"] = engine_status.reason
    try:
        store.ping()
    except sqlite3.Error:
        logger.exception("readiness: database check failed")
        checks["database"] = "error"
    checks["prometheus"] = "ok" if _prometheus_status().available else "unavailable"
    checks["loki"] = "ok" if telemetry.loki_status().available else "unavailable"
    if checks["database"] != "ok" or engine_status.state in {"stopped", "stalled"}:
        status = "unavailable"
    elif "unavailable" in checks.values() or engine_status.state == "degraded":
        status = "degraded"
    else:
        status = "ok"
    body = ReadyResponse(status=status, service="aegis-control-plane", checks=checks)
    if status == "unavailable":
        return JSONResponse(status_code=503, content=body.model_dump())
    return body


@app.get("/api/engine/status", response_model=EngineStatus)
def engine_status() -> EngineStatus:
    """Engine heartbeat (last success, last error, consecutive failures) and backend breakers."""
    return engine.status()


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics() -> Response:
    """Prometheus exposition of the control plane's own health."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


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
def list_incidents(page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200), status: str | None = Query(None, max_length=64), severity: str | None = Query(None, max_length=64), search: str | None = Query(None, max_length=200)) -> dict[str, Any]:
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
            remediation.ensure_permitted(rec)
        except RemediationError:
            continue
        approval = {"approver": request.approver, "approved_at": utc_now(), "recommendation": rec}
        # Atomic: skips an incident that left recommendation_pending since the listing.
        if not store.merge_incident(
            inc["id"], {"approval": approval}, status="approved", only_if_status={"recommendation_pending"}
        ):
            continue
        store.add_event(inc["id"], "approval", f"Batch approval from {request.approver}", approval)
        approved.append(inc["id"])
    _audit("batch_approve", {"approver": request.approver, "count": len(approved)})
    return {"approved": approved, "count": len(approved)}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {**incident, "events": store.events(incident_id)}


@app.post("/api/incidents/{incident_id}/investigate", response_model=InvestigateResponse, dependencies=PROTECTED)
def investigate(incident_id: str) -> InvestigateResponse:
    incident = store.get_incident(incident_id)
    if incident and incident["status"] in {"resolved", "closed"}:
        raise HTTPException(status_code=409, detail="Incident is already resolved")
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
        remediation.ensure_permitted(recommendation)
    except RemediationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    approval = {"approver": request.approver, "approved_at": utc_now(), "recommendation": recommendation}
    # Atomic: a concurrent approval, or evidence appended since the read above, is not overwritten.
    if not store.merge_incident(
        incident_id, {"approval": approval}, status="approved", only_if_status={"recommendation_pending"}
    ):
        raise HTTPException(status_code=409, detail="Incident has no pending recommendation")
    store.add_event(incident_id, "approval", f"Human approval recorded from {request.approver}", approval)
    _audit("approve", {"incident_id": incident_id, "approver": request.approver})
    return ApprovalResponse(**get_incident(incident_id))


@app.post("/api/incidents/{incident_id}/execute", response_model=ExecuteResponse, dependencies=PROTECTED)
def execute(incident_id: str, request: ApprovalRequest) -> ExecuteResponse:
    try:
        result = remediation.execute(incident_id, request.approver)
    except RemediationError as exc:
        # 409 refused, 429 over the limit, 502 the service did not accept the action.
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        raise HTTPException(status_code=exc.status_code, detail=str(exc), headers=headers) from exc
    return ExecuteResponse(**result)


# ─── Audit Log ────────────────────────────────────────────────────────────────

@app.get("/api/audit", dependencies=PROTECTED)
def audit_log(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"entries": list(_audit_log)[-limit:][::-1], "total": len(_audit_log)}


# ─── Chaos & Telemetry ────────────────────────────────────────────────────────

@app.post("/api/chaos", response_model=ChaosResponse, dependencies=PROTECTED)
def chaos(request: ChaosRequest) -> ChaosResponse:
    if not API_KEY.strip():
        raise HTTPException(
            status_code=503,
            detail="Fault injection disabled: set AEGIS_API_KEY.",
        )
    target = {"checkout": settings.checkout_url, "inventory": settings.inventory_url}[request.service]
    try:
        response = httpx.post(
            f"{target.rstrip('/')}/admin/faults",
            json=request.model_dump(exclude={"service"}),
            headers=bearer_header(API_KEY),
            timeout=5,
        )
        response.raise_for_status()
        _audit("chaos_inject", {"service": request.service, "fault": request.fault})
        return ChaosResponse(status="injected", service=request.service, result=response.json())
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Demo service unavailable: {exc}") from exc


@app.get("/api/metrics")
def metrics() -> list[MetricSnapshot]:
    return telemetry.metric_snapshot()


@app.get("/api/logs")
def logs(service: str | None = Query(None, max_length=64), limit: int = 40) -> list[dict[str, Any]]:
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
