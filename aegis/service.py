from __future__ import annotations

import asyncio
import hmac
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, ClassVar

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, Field

from aegis.logging_utils import configure_logging

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

SERVICE = os.getenv("SERVICE_NAME", "checkout")
DEPENDENCY_URL = os.getenv("DEPENDENCY_URL", "")
LOG_PATH = os.getenv("LOG_PATH", f"./logs/{SERVICE}.jsonl")
logger = configure_logging(SERVICE, LOG_PATH)

HTTP_REQUESTS = Counter(
    "aegis_http_requests_total", "HTTP requests handled", ["service", "method", "route", "status"]
)
HTTP_LATENCY = Histogram(
    "aegis_http_request_duration_seconds",
    "HTTP request latency",
    ["service", "method", "route"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
DEPENDENCY_REQUESTS = Counter(
    "aegis_dependency_requests_total", "Dependency requests", ["service", "dependency", "status"]
)
DEPENDENCY_ERRORS = Counter(
    "aegis_dependency_errors_total", "Dependency errors", ["service", "dependency", "reason"]
)
DEPENDENCY_LATENCY = Histogram(
    "aegis_dependency_request_duration_seconds",
    "Dependency request latency",
    ["service", "dependency"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
FAULT_ACTIVE = Gauge("aegis_fault_active", "Whether a named fault is active", ["service", "fault"])
FAULT_EVENTS = Counter("aegis_fault_events_total", "Fault injections", ["service", "fault"])
CPU_BURN_ACTIVE = Gauge(
    "aegis_cpu_burn_active", "Whether synthetic CPU load is active", ["service"]
)
QUEUE_DEPTH = Gauge("aegis_queue_depth", "Synthetic work queue depth", ["service"])
SIMULATED_REPLICAS = Gauge("aegis_simulated_replicas", "Safe demo scaling control", ["service"])


class FaultState:
    allowed_faults: ClassVar[frozenset[str]] = frozenset(
        {"latency", "errors", "dependency", "cpu"}
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._faults: dict[str, dict[str, float]] = {}
        self._stop_events: dict[str, threading.Event] = {}

    def inject(self, fault: str, duration: float, intensity: float) -> dict[str, Any]:
        if fault not in self.allowed_faults:
            raise ValueError("unknown fault")
        duration = min(900.0, max(1.0, float(duration)))
        intensity = min(10.0, max(0.1, float(intensity)))
        until = time.time() + duration
        stop_event: threading.Event | None = None
        with self._lock:
            if fault == "cpu":
                # A new CPU injection replaces the old burner instead of adding
                # another thread that would keep loading the host.
                previous = self._stop_events.get("cpu")
                if previous:
                    previous.set()
                stop_event = threading.Event()
                self._stop_events["cpu"] = stop_event
            self._faults[fault] = {"until": until, "intensity": intensity}
        FAULT_ACTIVE.labels(SERVICE, fault).set(1)
        FAULT_EVENTS.labels(SERVICE, fault).inc()
        if fault == "cpu":
            CPU_BURN_ACTIVE.labels(SERVICE).set(1)
            threading.Thread(
                target=self._burn_cpu, args=(until, intensity, stop_event), daemon=True
            ).start()
        # Expire the state and gauge even when nobody polls the admin endpoint.
        threading.Thread(target=self._expire, args=(fault, until), daemon=True).start()
        return {
            "fault": fault,
            "duration_seconds": duration,
            "intensity": intensity,
            "until": until,
        }

    def clear(self, fault: str | None = None) -> None:
        stop_events: list[threading.Event] = []
        with self._lock:
            if fault is None:
                keys = list(self._faults)
            elif fault in self.allowed_faults:
                keys = [fault]
            else:
                keys = []
            for key in keys:
                self._faults.pop(key, None)
                FAULT_ACTIVE.labels(SERVICE, key).set(0)
                if key == "cpu":
                    event = self._stop_events.pop("cpu", None)
                    if event:
                        stop_events.append(event)
        for event in stop_events:
            event.set()
        if fault in (None, "cpu"):
            CPU_BURN_ACTIVE.labels(SERVICE).set(0)

    def get(self, fault: str) -> dict[str, float] | None:
        expired = False
        with self._lock:
            state = self._faults.get(fault)
            if state and state["until"] <= time.time():
                self._faults.pop(fault, None)
                if fault == "cpu":
                    event = self._stop_events.pop("cpu", None)
                    if event:
                        event.set()
                expired = True
                state = None
            result = state.copy() if state else None
        if expired:
            FAULT_ACTIVE.labels(SERVICE, fault).set(0)
            if fault == "cpu":
                CPU_BURN_ACTIVE.labels(SERVICE).set(0)
        return result

    def snapshot(self) -> dict[str, dict[str, float]]:
        return {
            fault: state
            for fault in ("latency", "errors", "dependency", "cpu")
            if (state := self.get(fault))
        }

    def _expire(self, fault: str, until: float) -> None:
        delay = until - time.time()
        if delay > 0:
            time.sleep(delay)
        with self._lock:
            state = self._faults.get(fault)
            if not state or state["until"] != until:
                return
            self._faults.pop(fault, None)
            if fault == "cpu":
                event = self._stop_events.pop("cpu", None)
                if event:
                    event.set()
        FAULT_ACTIVE.labels(SERVICE, fault).set(0)
        if fault == "cpu":
            CPU_BURN_ACTIVE.labels(SERVICE).set(0)

    @staticmethod
    def _burn_cpu(until: float, intensity: float, stop_event: threading.Event) -> None:
        # A bounded, intentionally boring CPU burner keeps the chaos demo self-contained.
        while time.time() < until and not stop_event.is_set():
            for iteration in range(max(1, int(50_000 * max(0.1, intensity)))):
                if iteration % 1024 == 0 and stop_event.is_set():
                    return
                _ = 17 * 31


faults = FaultState()
SIMULATED_REPLICA_COUNT = 1
SIMULATED_REPLICAS.labels(SERVICE).set(SIMULATED_REPLICA_COUNT)


class FaultRequest(BaseModel):
    fault: str = Field(pattern="^(latency|errors|dependency|cpu)$")
    duration_seconds: float = Field(default=60, ge=1, le=900)
    intensity: float = Field(default=1, ge=0.1, le=10)


class FaultClearRequest(BaseModel):
    fault: str | None = Field(default=None, pattern="^(latency|errors|dependency|cpu)$")


class ScaleRequest(BaseModel):
    replicas: int = Field(default=1, ge=1, le=3)


def _fault_latency() -> float:
    state = faults.get("latency")
    return float(state["intensity"]) if state else 0.0


def require_admin_key(request: Request) -> None:
    """Require the shared admin key before any fault or scale control."""
    expected = os.getenv("AEGIS_API_KEY", "")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Admin API disabled: set AEGIS_API_KEY to enable fault injection.",
        )
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and hmac.compare_digest(
        auth_header[7:], expected
    ):
        return
    raise HTTPException(status_code=401, detail="Invalid or missing API key.")


ADMIN = [Depends(require_admin_key)]


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    logger.info("service_started", extra={"service": SERVICE})
    yield
    faults.clear()
    logger.info("service_stopped", extra={"service": SERVICE})


app = FastAPI(title=f"Aegis demo service: {SERVICE}", lifespan=lifespan)


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.middleware("http")
async def observe(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    started = time.perf_counter()
    route = request.url.path
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers["x-request-id"] = request_id
        return response
    finally:
        elapsed = time.perf_counter() - started
        HTTP_REQUESTS.labels(SERVICE, request.method, route, str(status)).inc()
        HTTP_LATENCY.labels(SERVICE, request.method, route).observe(elapsed)
        logger.info(
            "request_completed",
            extra={
                "service": SERVICE,
                "request_id": request_id,
                "route": route,
                "status": status,
                "duration_ms": round(elapsed * 1000, 2),
            },
        )


@app.get("/")
async def root() -> dict[str, Any]:
    return {"service": SERVICE, "status": "ok", "faults": faults.snapshot()}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"service": SERVICE, "status": "ok"}


@app.get("/api/inventory", response_model=None)
async def inventory() -> dict[str, Any] | JSONResponse:
    if SERVICE != "inventory":
        return JSONResponse({"error": "not an inventory service"}, status_code=404)
    if faults.get("errors") or faults.get("dependency"):
        logger.error("inventory_failure", extra={"service": SERVICE, "fault": "dependency"})
        return JSONResponse({"error": "inventory backend unavailable"}, status_code=503)
    latency = _fault_latency()
    if latency:
        await asyncio.sleep(latency)
    return {"sku": "aegis-widget", "available": 42}


@app.get("/api/checkout", response_model=None)
async def checkout() -> dict[str, Any] | JSONResponse:
    if SERVICE != "checkout":
        return JSONResponse({"error": "not a checkout service"}, status_code=404)
    if faults.get("errors"):
        logger.error("checkout_failure", extra={"service": SERVICE, "fault": "errors"})
        return JSONResponse({"error": "checkout unavailable"}, status_code=503)
    latency = _fault_latency()
    if latency:
        await asyncio.sleep(latency)
    if DEPENDENCY_URL:
        dependency = "inventory"
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.get(f"{DEPENDENCY_URL}/api/inventory")
            DEPENDENCY_REQUESTS.labels(SERVICE, dependency, str(response.status_code)).inc()
            if response.status_code >= 500:
                DEPENDENCY_ERRORS.labels(SERVICE, dependency, "upstream_5xx").inc()
                logger.error(
                    "dependency_failure",
                    extra={
                        "service": SERVICE,
                        "dependency": dependency,
                        "status": response.status_code,
                    },
                )
                return JSONResponse({"error": "inventory dependency failed"}, status_code=502)
        except httpx.HTTPError as exc:
            DEPENDENCY_REQUESTS.labels(SERVICE, dependency, "timeout").inc()
            DEPENDENCY_ERRORS.labels(SERVICE, dependency, "timeout").inc()
            logger.error(
                "dependency_timeout",
                extra={"service": SERVICE, "dependency": dependency, "fault": type(exc).__name__},
            )
            return JSONResponse({"error": "inventory dependency timed out"}, status_code=504)
        finally:
            DEPENDENCY_LATENCY.labels(SERVICE, dependency).observe(time.perf_counter() - started)
    QUEUE_DEPTH.labels(SERVICE).set(0)
    return {"order_id": str(uuid.uuid4()), "status": "confirmed", "service": SERVICE}


@app.get("/admin/faults", dependencies=ADMIN)
async def get_faults() -> dict[str, Any]:
    return {"service": SERVICE, "faults": faults.snapshot()}


@app.post("/admin/faults", dependencies=ADMIN)
async def inject_fault(payload: FaultRequest) -> dict[str, Any]:
    return {
        "service": SERVICE,
        "injected": faults.inject(payload.fault, payload.duration_seconds, payload.intensity),
    }


@app.post("/admin/faults/clear", dependencies=ADMIN)
async def clear_fault(payload: FaultClearRequest | None = None) -> dict[str, Any]:
    fault = payload.fault if payload else None
    faults.clear(fault)
    logger.warning(
        "faults_cleared", extra={"service": SERVICE, "fault": fault or "all"}
    )
    return {"service": SERVICE, "faults": faults.snapshot(), "status": "cleared"}


@app.post("/admin/scale", dependencies=ADMIN)
async def scale_simulation(payload: ScaleRequest) -> dict[str, Any]:
    global SIMULATED_REPLICA_COUNT
    replicas = payload.replicas
    SIMULATED_REPLICA_COUNT = replicas
    SIMULATED_REPLICAS.labels(SERVICE).set(replicas)
    logger.warning("simulated_scale", extra={"service": SERVICE, "status": replicas})
    return {"service": SERVICE, "simulated_replicas": replicas, "status": "scaled"}
