from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Any

from aegis.agent import AgentInvestigator
from aegis.anomaly import RollingZScoreDetector
from aegis.settings import Settings
from aegis.storage import Store, utc_now
from aegis.telemetry import Telemetry


@dataclass(frozen=True)
class Rule:
    name: str
    title: str
    severity: str
    query: str
    threshold: float
    root_cause_key: str
    direction: str = "gt"

    def fires(self, value: float | None) -> bool:
        if value is None:
            return False
        return value > self.threshold if self.direction == "gt" else value < self.threshold


RULES = (
    Rule(
        "checkout_error_rate",
        "Checkout error rate is elevated",
        "high",
        'sum(rate(aegis_http_requests_total{service="checkout",status=~"5.."}[2m])) '
        '/ clamp_min(sum(rate(aegis_http_requests_total{service="checkout"}[2m])), 0.001)',
        0.15,
        "service:checkout",
    ),
    Rule(
        "checkout_p95_latency",
        "Checkout p95 latency is elevated",
        "medium",
        "histogram_quantile(0.95, sum(rate(aegis_http_request_duration_seconds_bucket"
        '{service="checkout"}[2m])) by (le))',
        0.75,
        "service:checkout",
    ),
    Rule(
        "inventory_dependency_errors",
        "Checkout is receiving inventory dependency failures",
        "high",
        'sum(rate(aegis_dependency_errors_total{service="checkout",dependency="inventory"}[2m]))',
        0.05,
        "dependency:inventory",
    ),
    Rule(
        "checkout_cpu_burn",
        "Checkout CPU stress is active",
        "medium",
        'aegis_cpu_burn_active{service="checkout"}',
        0.5,
        "service:checkout:cpu",
    ),
)


class IncidentEngine:
    def __init__(self, settings: Settings, store: Store, telemetry: Telemetry):
        self.settings = settings
        self.store = store
        self.telemetry = telemetry
        self.detector = RollingZScoreDetector()
        self.agent = AgentInvestigator(settings, store, telemetry)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._misses: dict[str, int] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="aegis-incident-engine", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:  # the monitor must survive a malformed telemetry response
                print(f"incident engine error: {exc}")
            self._stop.wait(self.settings.poll_seconds)

    def run_once(self) -> list[dict[str, Any]]:
        fired: list[dict[str, Any]] = []
        fired_ids: set[str] = set()
        for rule in RULES:
            result = self.telemetry.prometheus_query(rule.query)
            value = result.get("value")
            anomaly = self.detector.observe(rule.name, float(value or 0.0))
            if not rule.fires(value):
                continue
            root = rule.root_cause_key
            if rule.name in {"checkout_error_rate", "checkout_p95_latency"}:
                dependency = self.telemetry.prometheus_query(
                    'sum(rate(aegis_dependency_errors_total{service="checkout",dependency="inventory"}[2m]))'
                ).get("value")
                if dependency and dependency > 0.05:
                    root = "dependency:inventory"
            evidence = {
                "rule": rule.name,
                "query": rule.query,
                "value": value,
                "threshold": rule.threshold,
                "z_score": anomaly.z_score,
                "baseline": anomaly.baseline,
                "evaluated_at": utc_now(),
                "source": "prometheus",
            }
            # Correlation is based on the root-cause key, not the incident ID. A fresh ID
            # allows the same fault pattern to be recorded again after resolution.
            incident_id = "inc-" + uuid.uuid4().hex[:10]
            incident, created = self.store.upsert_incident(
                incident_id, rule.title, rule.severity, root, evidence
            )
            fired.append(incident)
            fired_ids.add(incident["id"])
            if created:
                self.store.update_incident(incident["id"], status="investigating")
                self.store.add_event(
                    incident["id"], "investigation_started", "Aegis is collecting evidence"
                )
                self.store.db.commit()
                threading.Thread(
                    target=self._investigate,
                    args=(incident["id"],),
                    name=f"investigate-{incident['id']}",
                    daemon=True,
                ).start()
        self._resolve_missing(fired_ids)
        return fired

    def _investigate(self, incident_id: str) -> None:
        try:
            self.agent.investigate(incident_id)
        except Exception as exc:
            self.store.add_event(incident_id, "agent_error", str(exc))
            self.store.update_incident(incident_id, status="open")
            self.store.db.commit()

    def _resolve_missing(self, fired_ids: set[str]) -> None:
        active = self.store.list_incidents()
        active_ids = {
            incident["id"]
            for incident in active
            if incident["status"] not in {"resolved", "closed"}
        }
        for incident_id in active_ids:
            if incident_id in fired_ids:
                self._misses[incident_id] = 0
                continue
            self._misses[incident_id] = self._misses.get(incident_id, 0) + 1
            if self._misses[incident_id] < 2:
                continue
            incident = self.store.get_incident(incident_id)
            if not incident or incident["status"] in {"resolved", "closed"}:
                continue
            resolved_at = utc_now()
            self.store.update_incident(incident_id, status="resolved", resolved_at=resolved_at)
            self.store.add_event(
                incident_id, "resolved", "Signals returned below the alert threshold"
            )
            self.store.db.commit()
            self._misses.pop(incident_id, None)
