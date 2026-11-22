"""Prometheus metrics describing the control plane itself (served at /metrics)."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, Any, Protocol

from prometheus_client import Counter, Histogram
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

if TYPE_CHECKING:
    from collections.abc import Iterator

    from prometheus_client.core import Metric

    from aegis.storage import Store
    from aegis.supervisor import EngineStatus

CYCLE_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120)

ENGINE_CYCLE_SECONDS = Histogram(
    "aegis_engine_cycle_seconds", "Duration of engine evaluation cycles", buckets=CYCLE_BUCKETS
)
ENGINE_CYCLE_FAILURES = Counter(
    "aegis_engine_cycle_failures", "Engine cycles that raised or timed out", ["reason"]
)
BACKEND_ERRORS = Counter(
    "aegis_backend_errors", "Failed calls to a telemetry or LLM backend", ["backend"]
)

# Remediation outcomes are recorded as incident events; they survive restarts.
EXECUTION_EVENTS = {
    "remediation_executed": "executed",
    "remediation_failed": "failed",
    "remediation_dry_run": "dry_run",
    "remediation_verified": "verified",
    "remediation_escalated": "escalated",
}
CLOSED_STATUSES = ("resolved", "closed")


class EngineView(Protocol):
    def status(self) -> EngineStatus: ...


class ControlPlaneCollector:
    """Reads incident, execution, engine and breaker state at scrape time."""

    def __init__(self, store: Store, engine: EngineView):
        self._store = store
        self._engine = engine

    def collect(self) -> Iterator[Metric]:
        status = self._engine.status()
        up = GaugeMetricFamily("aegis_engine_up", "1 when the engine reports ok")
        up.add_metric([], 1.0 if status.state == "ok" else 0.0)
        yield up
        failures = GaugeMetricFamily(
            "aegis_engine_consecutive_failures", "Cycle failures since the last success"
        )
        failures.add_metric([], status.consecutive_failures)
        yield failures
        age = GaugeMetricFamily(
            "aegis_engine_last_success_age_seconds", "Seconds since the last successful cycle"
        )
        if status.last_success_age_seconds is not None:
            age.add_metric([], status.last_success_age_seconds)
        yield age
        breaker = GaugeMetricFamily(
            "aegis_breaker_open", "1 when a backend circuit breaker is not closed", labels=["backend"]
        )
        for name, item in status.breakers.items():
            breaker.add_metric([name], 0.0 if item.state == "closed" else 1.0)
        yield breaker
        yield from self._store_metrics()

    def _store_metrics(self) -> Iterator[Metric]:
        try:
            statuses = self._store.incident_status_counts()
            events = self._store.event_counts(tuple(EXECUTION_EVENTS))
        except sqlite3.Error:
            return
        open_incidents = GaugeMetricFamily("aegis_incidents_open", "Incidents not yet resolved")
        open_incidents.add_metric(
            [], sum(n for status, n in statuses.items() if status not in CLOSED_STATUSES)
        )
        yield open_incidents
        executions = CounterMetricFamily(
            "aegis_remediation_executions", "Remediation executions by result", labels=["result"]
        )
        for kind, result in EXECUTION_EVENTS.items():
            executions.add_metric([result], events.get(kind, 0))
        yield executions

    def describe(self) -> list[Any]:
        return []
