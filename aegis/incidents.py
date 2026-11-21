"""Incident detection, correlation, and resolution engine."""

from __future__ import annotations

import logging
import math
import threading
import time
import uuid
from typing import TYPE_CHECKING, Any

from aegis.agent import AgentInvestigator
from aegis.anomaly import RollingZScoreDetector
from aegis.models import AlertRule, Severity
from aegis.queries import (
    CHECKOUT_CPU_BURN,
    CHECKOUT_ERROR_RATE,
    CHECKOUT_P95_LATENCY,
    DEPENDENCY_ERROR_THRESHOLD,
    INVENTORY_DEPENDENCY_ERRORS,
)
from aegis.storage import Store, utc_now

if TYPE_CHECKING:
    from collections.abc import Collection

    from aegis.settings import Settings
    from aegis.telemetry import Telemetry

logger = logging.getLogger(__name__)

SHUTDOWN_JOIN_SECONDS = 15.0

# ─── Alert Rules ──────────────────────────────────────────────────────────────

RULES = (
    AlertRule(
        name="checkout_error_rate",
        title="Checkout error rate is elevated",
        severity=Severity.HIGH,
        query=CHECKOUT_ERROR_RATE,
        threshold=0.15,
        root_cause_key="service:checkout",
    ),
    AlertRule(
        name="checkout_p95_latency",
        title="Checkout p95 latency is elevated",
        severity=Severity.MEDIUM,
        query=CHECKOUT_P95_LATENCY,
        threshold=0.75,
        root_cause_key="service:checkout",
    ),
    AlertRule(
        name="inventory_dependency_errors",
        title="Checkout is receiving inventory dependency failures",
        severity=Severity.HIGH,
        query=INVENTORY_DEPENDENCY_ERRORS,
        threshold=DEPENDENCY_ERROR_THRESHOLD,
        root_cause_key="dependency:inventory",
    ),
    AlertRule(
        name="checkout_cpu_burn",
        title="Checkout CPU stress is active",
        severity=Severity.MEDIUM,
        query=CHECKOUT_CPU_BURN,
        threshold=0.5,
        root_cause_key="service:checkout:cpu",
    ),
)


class IncidentEngine:
    """Main engine for detecting, correlating, and resolving incidents."""

    def __init__(self, settings: Settings, store: Store, telemetry: Telemetry):
        self.settings = settings
        self.store = store
        self.telemetry = telemetry
        self.detector = RollingZScoreDetector()
        self.agent = AgentInvestigator(settings, store, telemetry)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._investigations: set[threading.Thread] = set()
        self._investigations_lock = threading.Lock()
        self._misses: dict[str, int] = {}
        self._degraded: set[str] = set()

    def start(self) -> None:
        """Start the incident detection engine."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._resume_interrupted_investigations()
        self._thread = threading.Thread(
            target=self._run, name="aegis-incident-engine", daemon=True
        )
        self._thread.start()

    @property
    def is_running(self) -> bool:
        """Whether the background evaluation thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def stop(self, timeout: float = SHUTDOWN_JOIN_SECONDS) -> None:
        """Stop the engine and wait up to `timeout` seconds for its work to finish.

        Waits for the evaluation loop and any in-flight investigations so the caller
        can close the database afterwards without those threads still writing to it.
        """
        self._stop.set()
        deadline = time.monotonic() + timeout
        with self._investigations_lock:
            workers = [*self._investigations]
        if self._thread:
            workers.append(self._thread)
        for worker in workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            logger.warning("incident engine still busy after %.0fs; shutting down anyway", timeout)

    def _resume_interrupted_investigations(self) -> None:
        """Restart investigations that a crash or restart left in "investigating".

        Their worker threads died with the process, and auto-resolution never
        touches an investigating incident, so they would otherwise stay stuck.
        """
        try:
            stuck = [
                incident["id"]
                for incident in self.store.list_incidents(limit=1000)
                if incident["status"] == "investigating"
            ]
        except Exception:
            logger.exception("Could not look for interrupted investigations")
            return
        for incident_id in stuck:
            self._spawn_investigation(incident_id)

    def _run(self) -> None:
        """Main engine loop; a failing cycle is logged and the next one still runs."""
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                logger.exception("Incident engine cycle failed")
            # A non-positive interval would turn a persistent failure into a busy loop.
            self._stop.wait(max(1, self.settings.poll_seconds))

    def run_once(self) -> list[dict[str, Any]]:
        """Execute one evaluation cycle of all alert rules.

        Each rule is isolated: a failure reading or recording one signal is
        logged and does not stop the others. A signal that could not be read is
        "unverified", and the incidents it drives are never auto-resolved on the
        strength of a missing reading.
        """
        fired: list[dict[str, Any]] = []
        fired_ids: set[str] = set()
        unverified: set[str] = set()

        for rule in RULES:
            try:
                incident = self._evaluate_rule(rule, unverified)
            except Exception:
                logger.exception("Evaluating rule %s failed", rule.name)
                unverified.add(rule.root_cause_key)
                continue
            if incident:
                fired.append(incident)
                fired_ids.add(incident["id"])

        try:
            self._resolve_missing(fired_ids, unverified)
        except Exception:
            logger.exception("Resolving quiet incidents failed")
        return fired

    def _evaluate_rule(self, rule: AlertRule, unverified: set[str]) -> dict[str, Any] | None:
        """Evaluate one rule; return the incident it fired or updated, if any."""
        result = self.telemetry.prometheus_query(rule.query)
        if result.get("error"):
            # Feeding a failed read to the detector as 0.0 would corrupt its baseline.
            logger.warning("Rule %s unreadable: %s", rule.name, result["error"])
            unverified.add(rule.root_cause_key)
            return None
        value = result.get("value")
        anomaly = self.detector.observe(rule.name, float(value or 0.0))

        if not rule.fires(value):
            return None

        root = rule.root_cause_key
        # Correlation: if checkout symptoms exist with inventory dependency errors,
        # rewrite root cause to dependency:inventory
        if rule.name in {"checkout_error_rate", "checkout_p95_latency"}:
            dependency_result = self.telemetry.prometheus_query(INVENTORY_DEPENDENCY_ERRORS)
            if dependency_result.get("error"):
                # Recording under the wrong root would open a duplicate incident.
                logger.warning("Dependency check unreadable for rule %s", rule.name)
                unverified.update({root, "dependency:inventory"})
                return None
            dependency = dependency_result.get("value")
            if dependency and dependency > DEPENDENCY_ERROR_THRESHOLD:
                root = "dependency:inventory"

        evidence = {
            "rule": rule.name,
            "query": rule.query,
            "value": value,
            "threshold": rule.threshold,
            # A flat baseline yields an infinite z-score, which JSON cannot represent.
            "z_score": anomaly.z_score if anomaly.z_score is None or math.isfinite(anomaly.z_score) else None,
            "baseline": anomaly.baseline,
            "evaluated_at": utc_now(),
            "source": "prometheus",
        }

        # Correlation is based on the root-cause key, not the incident ID.
        # A fresh ID allows the same fault pattern to be recorded again after resolution.
        incident_id = "inc-" + uuid.uuid4().hex[:10]
        incident, created = self.store.upsert_incident(
            incident_id, rule.title, rule.severity.value, root, evidence
        )

        if created and self.store.transition_status(incident["id"], "open", "investigating"):
            self.store.add_event(
                incident["id"], "investigation_started", "Aegis is collecting evidence"
            )
            self._spawn_investigation(incident["id"])
        return incident

    def _spawn_investigation(self, incident_id: str) -> None:
        """Investigate in a background thread that `stop()` can wait for."""

        def work() -> None:
            try:
                self._investigate(incident_id)
            finally:
                with self._investigations_lock:
                    self._investigations.discard(threading.current_thread())

        worker = threading.Thread(target=work, name=f"investigate-{incident_id}", daemon=True)
        with self._investigations_lock:
            self._investigations.add(worker)
        worker.start()

    def _investigate(self, incident_id: str) -> None:
        """Run agent investigation in a background thread; it never dies with the incident stuck."""
        try:
            self.agent.investigate(incident_id)
        except Exception as exc:
            logger.exception("Investigation of %s failed", incident_id)
            try:
                self.store.add_event(incident_id, "agent_error", str(exc))
                # Back to open so it can resolve or be re-investigated; a status that
                # already moved on (approved, resolved) is left alone.
                self.store.transition_status(incident_id, "investigating", "open")
            except Exception:
                logger.exception("Could not record the failed investigation of %s", incident_id)

    def _resolve_missing(
        self, fired_ids: set[str], unverified_roots: Collection[str] = ()
    ) -> None:
        """Resolve incidents that haven't fired for N cycles.

        Auto-resolution only applies to incidents that are still ``open`` and
        have not entered the investigation/approval pipeline. Missing signals
        during ``investigating``, ``recommendation_pending``, or ``approved``
        do not mean remediation finished; resolving there would close the
        incident before the operator-approved action runs. An incident whose
        signal could not be read this cycle (``unverified_roots``) neither
        accumulates misses nor resolves, so a Prometheus outage cannot close it.
        """
        active = self.store.list_incidents()
        active_ids = {
            incident["id"]
            for incident in active
            if incident["status"] not in {"resolved", "closed"}
        }

        degraded = {
            incident["id"]
            for incident in active
            if incident["id"] in active_ids and incident["root_cause_key"] in unverified_roots
        }
        self._note_degraded(degraded)

        for incident_id in active_ids:
            if incident_id in degraded:
                self._misses.pop(incident_id, None)
                continue
            if incident_id in fired_ids:
                self._misses[incident_id] = 0
                continue

            incident = self.store.get_incident(incident_id)
            if not incident or incident["status"] in {"resolved", "closed"}:
                self._misses.pop(incident_id, None)
                continue

            if incident["status"] != "open":
                # Clear accumulated misses so a post-remediation incident gets
                # a full resolution window after it returns to ``open``.
                self._misses.pop(incident_id, None)
                continue

            self._misses[incident_id] = self._misses.get(incident_id, 0) + 1
            if self._misses[incident_id] < self.settings.resolution_cycles:
                continue

            # Re-check after the threshold: the status may have advanced since
            # the snapshot above (e.g. an investigation completing in another thread).
            incident = self.store.get_incident(incident_id)
            if not incident or incident["status"] != "open":
                self._misses.pop(incident_id, None)
                continue

            resolved_at = utc_now()
            self.store.update_incident(incident_id, status="resolved", resolved_at=resolved_at)
            self.store.add_event(
                incident_id, "resolved", "Signals returned below the alert threshold"
            )
            self._misses.pop(incident_id, None)

    def _note_degraded(self, degraded: set[str]) -> None:
        """Record once per outage that an incident's signal cannot be read."""
        for incident_id in degraded - self._degraded:
            self.store.add_event(
                incident_id,
                "telemetry_unavailable",
                "Aegis cannot read this incident's signal; it will not auto-resolve until it can",
            )
        self._degraded = degraded
