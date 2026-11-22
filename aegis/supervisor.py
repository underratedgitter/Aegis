"""Supervised incident engine: a loop that survives failing and hung cycles and reports health."""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel

from aegis.breaker import BreakerStatus  # noqa: TC001 - pydantic resolves the field type at runtime
from aegis.incidents import IncidentEngine
from aegis.selfmetrics import ENGINE_CYCLE_FAILURES, ENGINE_CYCLE_SECONDS
from aegis.storage import utc_now

if TYPE_CHECKING:
    from collections.abc import Mapping

    from aegis.breaker import CircuitBreaker
    from aegis.settings import Settings
    from aegis.storage import Store
    from aegis.telemetry import Telemetry

logger = logging.getLogger(__name__)

# How often a waiting supervisor re-checks for shutdown and for its cycle timeout.
WAIT_SLICE_SECONDS = 0.1
ERROR_MAX_CHARS = 300
# Time beyond the in-flight cycle's grace period for the loop and investigations to wind down.
STOP_MARGIN_SECONDS = 5
MAX_BACKOFF_DOUBLINGS = 16

EngineState = Literal["ok", "degraded", "stalled", "stopped"]


class EngineStatus(BaseModel):
    """Heartbeat and health of the background engine."""

    state: EngineState
    reason: str | None = None
    running: bool
    poll_seconds: int
    cycle_timeout_seconds: int
    stale_after_seconds: int
    last_success_at: str | None = None
    last_success_age_seconds: float | None = None
    last_cycle_seconds: float | None = None
    last_error: str | None = None
    last_error_at: str | None = None
    consecutive_failures: int
    cycles_total: int
    failures_total: int
    breakers: dict[str, BreakerStatus]


class _Cycle:
    """Outcome of one evaluation cycle run on its own thread."""

    def __init__(self) -> None:
        self.done = threading.Event()
        self.error: Exception | None = None


class SupervisedEngine(IncidentEngine):
    """
    An IncidentEngine whose loop cannot silently die or stall.

    Each cycle runs on its own thread under a timeout. A cycle that raises or
    overruns counts as a failure and the loop carries on, pausing longer after
    each consecutive failure. A cycle that overran is abandoned, not killed, so no
    new cycle starts until it ends: two cycles never touch the engine's state at
    once. `status()` exposes the heartbeat for readiness and the UI.
    """

    def __init__(
        self,
        settings: Settings,
        store: Store,
        telemetry: Telemetry,
        breakers: Mapping[str, CircuitBreaker] | None = None,
    ):
        super().__init__(settings, store, telemetry)
        self.breakers = dict(breakers or {})
        self._health_lock = threading.Lock()
        self._started_at: float | None = None
        self._last_success_at: float | None = None
        self._last_success_iso: str | None = None
        self._last_cycle_seconds: float | None = None
        self._last_error: str | None = None
        self._last_error_iso: str | None = None
        self._consecutive_failures = 0
        self._cycles_total = 0
        self._failures_total = 0
        self._abandoned: threading.Thread | None = None

    def start(self) -> None:
        if not self.is_running:
            self._started_at = time.monotonic()
        super().start()

    def stop(self, timeout: float | None = None) -> None:
        """Stop the engine; by default wait the cycle grace period plus a margin."""
        if timeout is None:
            timeout = self.settings.shutdown_grace_seconds + STOP_MARGIN_SECONDS
        super().stop(timeout)

    def _run(self) -> None:
        """Supervision loop: a failing, hung or even mis-supervised cycle never ends it."""
        try:
            while not self._stop.is_set():
                try:
                    self._supervise_cycle()
                except Exception as exc:
                    logger.exception("Engine supervision error")
                    self._record_failure("error", exc)
                self._pause(self._next_delay())
        finally:
            if not self._stop.is_set():
                logger.critical("Incident engine loop exited unexpectedly")

    def _pause(self, seconds: float) -> None:
        self._stop.wait(seconds)

    def _next_delay(self) -> float:
        """The poll interval, doubled per consecutive failure up to the backoff cap."""
        poll = max(1, self.settings.poll_seconds)
        with self._health_lock:
            failures = self._consecutive_failures
        if failures == 0:
            return poll
        cap = max(poll, self.settings.engine_max_backoff_seconds)
        return min(cap, poll * (1 << min(failures - 1, MAX_BACKOFF_DOUBLINGS)))

    def _supervise_cycle(self) -> None:
        if self._abandoned is not None:
            if self._abandoned.is_alive():
                self._record_failure("timeout", RuntimeError("previous cycle is still running"))
                return
            self._abandoned = None
        cycle = _Cycle()
        worker = threading.Thread(
            target=self._cycle_body, args=(cycle,), name="aegis-engine-cycle", daemon=True
        )
        started = time.monotonic()
        worker.start()
        outcome = self._await(cycle, started)
        duration = time.monotonic() - started
        if outcome == "done":
            ENGINE_CYCLE_SECONDS.observe(duration)
            if cycle.error is None:
                self._record_success(duration)
            else:
                logger.error("Incident engine cycle failed", exc_info=cycle.error)
                self._record_failure("error", cycle.error, duration)
            return
        self._abandoned = worker
        if outcome == "timeout":
            ENGINE_CYCLE_SECONDS.observe(duration)
            timeout = self.settings.cycle_timeout_seconds
            logger.error("Incident engine cycle timed out after %ss; abandoning it", timeout)
            self._record_failure("timeout", TimeoutError(f"cycle timed out after {timeout}s"), duration)
        else:
            logger.warning("Shutting down with an engine cycle still running; abandoning it")

    def _cycle_body(self, cycle: _Cycle) -> None:
        try:
            self.run_once()
        except Exception as exc:
            cycle.error = exc
        finally:
            cycle.done.set()

    def _await(self, cycle: _Cycle, started: float) -> Literal["done", "timeout", "shutdown"]:
        """Wait for the cycle, giving up at its timeout or once shutdown outlasts the grace period."""
        deadline = started + self.settings.cycle_timeout_seconds
        shutdown_deadline: float | None = None
        while not cycle.done.wait(WAIT_SLICE_SECONDS):
            now = time.monotonic()
            if self._stop.is_set():
                if shutdown_deadline is None:
                    shutdown_deadline = now + self.settings.shutdown_grace_seconds
                if now >= shutdown_deadline:
                    return "shutdown"
            if now >= deadline:
                return "timeout"
        return "done"

    def _record_success(self, duration: float) -> None:
        with self._health_lock:
            self._cycles_total += 1
            self._consecutive_failures = 0
            self._last_success_at = time.monotonic()
            self._last_success_iso = utc_now()
            self._last_cycle_seconds = round(duration, 3)

    def _record_failure(self, reason: str, error: Exception, duration: float | None = None) -> None:
        ENGINE_CYCLE_FAILURES.labels(reason).inc()
        with self._health_lock:
            self._cycles_total += 1
            self._failures_total += 1
            self._consecutive_failures += 1
            self._last_error = f"{type(error).__name__}: {error}"[:ERROR_MAX_CHARS]
            self._last_error_iso = utc_now()
            if duration is not None:
                self._last_cycle_seconds = round(duration, 3)

    def status(self) -> EngineStatus:
        """Health derived from the heartbeat: ok, degraded (failing), stalled (stale) or stopped."""
        settings = self.settings
        stale_after = settings.engine_stale_intervals * settings.poll_seconds + settings.cycle_timeout_seconds
        running = self.is_running
        with self._health_lock:
            reference = self._last_success_at if self._last_success_at is not None else self._started_at
            age = None if reference is None else time.monotonic() - reference
            failures = self._consecutive_failures
            state: EngineState = "ok"
            reason: str | None = None
            if not running:
                state, reason = "stopped", "engine loop is not running"
            elif age is not None and age > stale_after:
                state = "stalled"
                reason = f"no successful cycle for {age:.0f}s (limit {stale_after}s)"
            elif failures:
                state = "degraded"
                reason = f"{failures} consecutive cycle failure{'s' if failures != 1 else ''}"
            success_age = (
                None
                if self._last_success_at is None
                else round(time.monotonic() - self._last_success_at, 1)
            )
            return EngineStatus(
                state=state,
                reason=reason,
                running=running,
                poll_seconds=settings.poll_seconds,
                cycle_timeout_seconds=settings.cycle_timeout_seconds,
                stale_after_seconds=stale_after,
                last_success_at=self._last_success_iso,
                last_success_age_seconds=success_age,
                last_cycle_seconds=self._last_cycle_seconds,
                last_error=self._last_error,
                last_error_at=self._last_error_iso,
                consecutive_failures=failures,
                cycles_total=self._cycles_total,
                failures_total=self._failures_total,
                breakers={name: item.snapshot() for name, item in self.breakers.items()},
            )
