from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from statistics import mean
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from aegis.agent import AgentInvestigator
from aegis.incidents import IncidentEngine
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


@asynccontextmanager
async def lifespan(_: FastAPI):
    engine.start()
    yield
    engine.stop()


app = FastAPI(title="Aegis SRE Copilot", version="0.1.0", lifespan=lifespan)
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


class ChaosRequest(BaseModel):
    service: str = Field(pattern="^(checkout|inventory)$")
    fault: str = Field(pattern="^(latency|errors|dependency|cpu)$")
    duration_seconds: float = Field(default=60, ge=1, le=900)
    intensity: float = Field(default=1, ge=0.1, le=10)


class ApprovalRequest(BaseModel):
    approver: str = Field(default="human-operator", min_length=2, max_length=80)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "aegis-control-plane"}


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    incidents = store.list_incidents()
    durations = store.resolved_durations()
    investigated = sum(bool(item["data"].get("investigation")) for item in incidents)
    return {
        "incidents": incidents[:12],
        "open_incidents": sum(item["status"] not in {"resolved", "closed"} for item in incidents),
        "mttr_seconds": round(mean(durations), 2) if durations else None,
        "resolved_incidents": len(durations),
        "agent_assisted_rate": round(investigated / len(incidents), 2) if incidents else None,
        "slos": [telemetry.slo_snapshot()],
        "services": [
            _service_status("checkout", settings.checkout_url),
            _service_status("inventory", settings.inventory_url),
        ],
        "telemetry": {"prometheus": _prometheus_status(), "loki": telemetry.loki_status()},
    }


@app.get("/api/incidents")
def list_incidents() -> list[dict[str, Any]]:
    return store.list_incidents()


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    return {**incident, "events": store.events(incident_id)}


@app.post("/api/incidents/{incident_id}/investigate")
def investigate(incident_id: str) -> dict[str, Any]:
    try:
        result = agent.investigate(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"incident_id": incident_id, "investigation": result}


@app.post("/api/incidents/{incident_id}/approve")
def approve(incident_id: str, request: ApprovalRequest) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    if incident["status"] != "recommendation_pending":
        raise HTTPException(status_code=409, detail="incident has no pending recommendation")
    recommendation = incident["data"].get("recommendation") or {}
    try:
        remediation.validate_recommendation(recommendation)
    except RemediationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    data = {
        **incident["data"],
        "approval": {
            "approver": request.approver,
            "approved_at": utc_now(),
            "recommendation": recommendation,
        },
    }
    store.update_incident(incident_id, status="approved", data=data)
    store.add_event(
        incident_id,
        "approval",
        f"Human approval recorded from {request.approver}",
        data["approval"],
    )
    store.db.commit()
    return get_incident(incident_id)


@app.post("/api/incidents/{incident_id}/execute")
def execute(incident_id: str, request: ApprovalRequest) -> dict[str, Any]:
    try:
        return remediation.execute(incident_id, request.approver)
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/chaos")
def chaos(request: ChaosRequest) -> dict[str, Any]:
    target = {"checkout": settings.checkout_url, "inventory": settings.inventory_url}[
        request.service
    ]
    try:
        response = httpx.post(
            f"{target.rstrip('/')}/admin/faults",
            json=request.model_dump(exclude={"service"}),
            timeout=5,
        )
        response.raise_for_status()
        return {"status": "injected", "service": request.service, "result": response.json()}
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"demo service unavailable: {exc}") from exc


@app.get("/api/metrics")
def metrics() -> list[dict[str, Any]]:
    return telemetry.metric_snapshot()


@app.get("/api/logs")
def logs(service: str | None = None, limit: int = 40) -> list[dict[str, Any]]:
    return telemetry.recent_logs(service, max(1, min(limit, 200)))


@app.get("/api/runbooks")
def runbooks() -> list[dict[str, str]]:
    directory = Path(settings.runbook_dir)
    return [
        {"slug": path.stem, "title": path.stem.replace("-", " ").title()}
        for path in sorted(directory.glob("*.md"))
    ]


@app.post("/api/engine/run-once")
def run_engine_once() -> dict[str, Any]:
    return {"fired": engine.run_once()}


def _service_status(name: str, url: str) -> dict[str, Any]:
    try:
        response = httpx.get(f"{url.rstrip('/')}/healthz", timeout=1)
        return {"name": name, "available": response.is_success, "status_code": response.status_code}
    except httpx.HTTPError as exc:
        return {"name": name, "available": False, "error": str(exc)}


def _prometheus_status() -> dict[str, Any]:
    result = telemetry.prometheus_query("up")
    return {"available": result.get("value") is not None, "error": result.get("error")}
