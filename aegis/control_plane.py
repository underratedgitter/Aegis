"""Aegis control plane with authentication, rate limiting, and structured responses."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar
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
    ResolveRequest,
    Runbook,
    ServiceStatus,
    TelemetryStatus,
)
from aegis.remediation import RemediationError, RemediationExecutor, no_remediation_reason
from aegis.selfmetrics import ControlPlaneCollector
from aegis.settings import Settings
from aegis.storage import CLOSED_STATUSES, DEFAULT_EVENT_LIMIT, Store, utc_now
from aegis.supervisor import EngineStatus, SupervisedEngine
from aegis.telemetry import Telemetry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Iterator

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

# Who is calling, for audit entries written while a protected request is handled.
_audit_origin: ContextVar[tuple[str | None, str | None]] = ContextVar(
    "audit_origin", default=(None, None)
)


async def _bind_audit_origin(request: Request) -> None:
    """Remember the caller's address and request ID for this request's audit entries.

    Async on purpose: a sync dependency runs in a copied context, so what it set would
    not reach the endpoint.
    """
    client_ip = request.client.host if request.client else None
    _audit_origin.set((client_ip, getattr(request.state, "request_id", None)))


def _audit(action: str, detail: dict[str, Any]) -> None:
    """Durably record an audit event with the caller's address and request ID when known.

    The action it records has already happened, so a database error is logged loudly
    rather than turned into a failed response.
    """
    client_ip, request_id = _audit_origin.get()
    try:
        store.add_audit(action, detail, client_ip=client_ip, request_id=request_id)
    except sqlite3.Error:
        logger.exception("audit entry %s could not be written: %s", action, detail)


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
PROTECTED = [Depends(_bind_audit_origin), Depends(verify_api_key)]


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
    recent, _ = store.query_incidents(limit=12)
    counts = store.incident_status_counts()
    total = sum(counts.values())
    durations = store.resolved_durations()
    return OverviewResponse(
        incidents=recent,
        open_incidents=sum(n for status, n in counts.items() if status not in CLOSED_STATUSES),
        mttr_seconds=round(mean(durations), 2) if durations else None,
        resolved_incidents=len(durations),
        agent_assisted_rate=round(store.investigated_count() / total, 2) if total else None,
        slos=[telemetry.slo_snapshot().model_dump()],
        services=[_service_status("checkout", settings.checkout_url), _service_status("inventory", settings.inventory_url)],
        telemetry={"prometheus": _prometheus_status(), "loki": telemetry.loki_status()},
    )


# ─── Incidents (list, export, and batch BEFORE /{id} routes) ──────────────────

CSV_CHUNK_BYTES = 64 * 1024

@app.get("/api/incidents")
def list_incidents(page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200), status: str | None = Query(None, max_length=64), severity: str | None = Query(None, max_length=64), search: str | None = Query(None, max_length=200)) -> dict[str, Any]:
    """One page of incident summaries (no evidence history); GET /api/incidents/{id} has the rest."""
    incidents, total = store.query_incidents(
        status=status, severity=severity, search=search, offset=(page - 1) * limit, limit=limit
    )
    return {"incidents": incidents, "pagination": {"page": page, "limit": limit, "total": total, "pages": (total + limit - 1) // limit}}


@app.get("/api/incidents/export")
def export_incidents(
    export_format: str = Query("json", alias="format", pattern="^(json|csv)$"),
) -> Any:
    """Every incident, streamed in batches so a large history is never held in memory."""
    if export_format == "csv":
        return StreamingResponse(_incidents_csv(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=incidents.csv"})
    return StreamingResponse(_incidents_json(), media_type="application/json")


@app.post("/api/incidents/batch/approve", dependencies=PROTECTED)
def batch_approve(request: ApprovalRequest) -> dict[str, Any]:
    pending = [i for i in store.active_incidents() if i["status"] == "recommendation_pending"]
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
def get_incident(
    incident_id: str,
    events_limit: int = Query(DEFAULT_EVENT_LIMIT, ge=1, le=1000),
    events_before: int | None = Query(None, ge=1),
) -> dict[str, Any]:
    """The incident with its latest events (`events_limit`); `events_before` pages further back."""
    return _incident_with_events(incident_id, events_limit, events_before)


@app.post("/api/incidents/{incident_id}/investigate", response_model=InvestigateResponse, dependencies=PROTECTED)
def investigate(incident_id: str) -> InvestigateResponse:
    incident = store.get_incident(incident_id)
    if incident and incident["status"] in {"resolved", "closed"}:
        raise HTTPException(status_code=409, detail="Incident is already resolved")
    try:
        result = agent.investigate(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    _audit("investigate", {"incident_id": incident_id})
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
    if reason := no_remediation_reason(incident):
        raise HTTPException(status_code=409, detail=reason)
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
    return ApprovalResponse(**_incident_with_events(incident_id))


# A remediation that is executing owns the incident until it finishes; every other
# unfinished status can be closed by an operator, who is accountable for the call.
MANUALLY_RESOLVABLE = frozenset(
    {"open", "investigating", "recommendation_pending", "approved"}
)


@app.post("/api/incidents/{incident_id}/resolve", dependencies=PROTECTED)
def resolve_incident(incident_id: str, request: ResolveRequest) -> dict[str, Any]:
    """Close an incident by hand, e.g. one stuck awaiting approval after its fault went away."""
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    previous = incident["status"]
    if previous in {"resolved", "closed"}:
        raise HTTPException(status_code=409, detail="Incident is already resolved")
    if previous not in MANUALLY_RESOLVABLE:
        raise HTTPException(
            status_code=409, detail="A remediation is executing; wait for it to finish"
        )
    resolved_at = utc_now()
    resolution = {
        "approver": request.approver,
        "note": request.note,
        "resolved_at": resolved_at,
        "previous_status": previous,
    }
    # Atomic: an execution that started since the read above is not overridden.
    if not store.merge_incident(
        incident_id,
        {"resolution": resolution},
        status="resolved",
        resolved_at=resolved_at,
        only_if_status=MANUALLY_RESOLVABLE,
    ):
        raise HTTPException(status_code=409, detail="Incident changed state; reload and retry")
    store.add_event(
        incident_id,
        "resolved",
        f"Resolved manually by {request.approver}: {request.note}",
        resolution,
    )
    _audit(
        "incident_resolve",
        {
            "incident_id": incident_id,
            "approver": request.approver,
            "note": request.note,
            "previous_status": previous,
        },
    )
    return _incident_with_events(incident_id)


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
def audit_log(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, max_length=64),
    incident_id: str | None = Query(None, max_length=64),
    approver: str | None = Query(None, max_length=80),
) -> dict[str, Any]:
    """Audit entries, newest first; `total` counts every entry that matches the filters."""
    entries, total = store.audit_entries(
        limit=limit, offset=offset, action=action, incident_id=incident_id, approver=approver
    )
    return {"entries": entries, "total": total, "limit": limit, "offset": offset}


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
    fired = engine.run_once()
    _audit("engine_run_once", {"fired": len(fired)})
    return {"fired": fired}


# ─── Helpers ──────────────────────────────────────────────────────────────────

CSV_COLUMNS = ["id", "title", "severity", "status", "root_cause_key", "first_seen", "last_seen", "resolved_at"]


def _incidents_csv() -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for incident in store.iter_incidents():
        writer.writerow({column: incident.get(column) or "" for column in CSV_COLUMNS})
        if buffer.tell() > CSV_CHUNK_BYTES:
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate()
    yield buffer.getvalue()


def _incidents_json() -> Iterator[str]:
    count = 0
    yield '{"incidents": ['
    for incident in store.iter_incidents():
        yield ("," if count else "") + json.dumps(incident)
        count += 1
    yield f'], "exported_at": {json.dumps(utc_now())}, "count": {count}}}'


def _incident_with_events(
    incident_id: str, events_limit: int = DEFAULT_EVENT_LIMIT, events_before: int | None = None
) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        **incident,
        "events": store.events(incident_id, events_limit, events_before),
        "events_total": store.count_events(incident_id),
    }


def _service_status(name: str, url: str) -> ServiceStatus:
    try:
        response = httpx.get(f"{url.rstrip('/')}/healthz", timeout=1)
        return ServiceStatus(name=name, available=response.is_success, status_code=response.status_code)
    except httpx.HTTPError as exc:
        return ServiceStatus(name=name, available=False, error=str(exc))


def _prometheus_status() -> TelemetryStatus:
    result = telemetry.prometheus_query("up")
    return TelemetryStatus(available=result.get("value") is not None, error=result.get("error"))
