"""Incident detection, correlation, and resolution engine."""

from __future__ import annotations

import logging
import math
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from aegis.agent import AgentInvestigator
from aegis.anomaly import RollingZScoreDetector
from aegis.models import BLIND_ROOT, LIVENESS_RULE, AlertRule, Severity
from aegis.queries import (
    CHECKOUT_CPU_BURN,
    CHECKOUT_DOWN,
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

# How many incidents to scan for a recently resolved one to reopen.
RECENT_INCIDENT_LOOKBACK = 1000

# How often retention pruning runs; it is a bulk delete, not a per-cycle chore.
PRUNE_INTERVAL_SECONDS = 3600

# Statuses a quiet incident leaves on its own. A pending recommendation nobody approved
# expires; approved and executing incidents are an operator's committed action and never
# resolve underneath it, and investigating ones return to open or pending by themselves.
AUTO_RESOLVABLE = frozenset({"open", "recommendation_pending"})

# Fraction of the dependency threshold below which checkout symptoms stop being
# attributed to an already-open dependency incident.
ATTRIBUTION_RELEASE = 0.5


@dataclass(frozen=True)
class Reading:
    """One signal as read this cycle.

    `value` is None when nothing numeric came back. `available` says whether that
    can be trusted: False means the signal could not be read, so it must not be
    taken as healthy.
    """

    value: float | None
    available: bool
    # Unreadable for a known reason that is not a telemetry outage (checkout is down),
    # so it must not count towards Aegis being blind.
    explained: bool = False

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
    AlertRule(
        name="checkout_down",
        title="Checkout is not answering metric scrapes",
        severity=Severity.HIGH,
        query=CHECKOUT_DOWN,
        threshold=0.5,
        root_cause_key="service:checkout",
    ),
)

RULES_BY_NAME = {rule.name: rule for rule in RULES}

# LIVENESS_RULE (models.py) reads whether the checkout target is alive, which decides
# whether an empty result from the others means "quiet" or "unknown".
INVENTORY_DEPENDENCY_RULE = "inventory_dependency_errors"
DEPENDENCY_ROOT = "dependency:inventory"
DEPENDENCY_SYMPTOMS = frozenset({"checkout_error_rate", "checkout_p95_latency"})


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
        self._cycle_lock = threading.Lock()
        self._breaches: dict[str, int] = {}
        self._signal_states: dict[str, str] = {}
        self._blind_since: dict[str, float] = {}
        self._clock = time.monotonic
        self._last_prune: float | None = None

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
                for incident in self.store.active_incidents()
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

        Cycles are serialised, so a manual run cannot race the background loop into
        opening the same incident twice. Each rule is isolated: a failure reading or
        recording one signal is logged and does not stop the others. A signal that
        could not be read is "unavailable", and the incidents it drives are never
        auto-resolved on the strength of a missing reading.
        """
        with self._cycle_lock:
            return self._run_cycle()

    def _run_cycle(self) -> list[dict[str, Any]]:
        fired: list[dict[str, Any]] = []
        fired_ids: set[str] = set()
        unverified: set[str] = set()
        readings = self._read_all()

        for rule in RULES:
            try:
                incident = self._evaluate_rule(rule, readings, unverified)
            except Exception:
                logger.exception("Evaluating rule %s failed", rule.name)
                self._mark(rule, "unavailable")
                unverified.add(rule.root_cause_key)
                continue
            if incident:
                fired.append(incident)
                fired_ids.add(incident["id"])

        try:
            blind = self._check_blind()
            if blind:
                fired.append(blind)
                fired_ids.add(blind["id"])
        except Exception:
            logger.exception("Recording telemetry blindness failed")

        try:
            self._resolve_missing(fired_ids, unverified)
        except Exception:
            logger.exception("Resolving quiet incidents failed")
        self._prune_history()
        return fired

    @property
    def signal_states(self) -> dict[str, str]:
        """Each rule's latest state: "ok", "breaching" or "unavailable"."""
        return dict(self._signal_states)

    def _mark(self, rule: AlertRule, state: str, *, explained: bool = False) -> None:
        """Record a rule's state; only a breach is debounced, so any other state restarts the count."""
        self._signal_states[rule.name] = state
        if state != "breaching":
            self._breaches[rule.name] = 0
        if state == "unavailable" and not explained:
            self._blind_since.setdefault(rule.name, self._clock())
        else:
            self._blind_since.pop(rule.name, None)

    def _read(self, rule: AlertRule) -> Reading:
        """Read one rule's signal; a failed or non-numeric read is unavailable, never zero."""
        try:
            result = self.telemetry.prometheus_query(rule.query)
        except Exception:
            logger.exception("Reading rule %s failed", rule.name)
            return Reading(None, available=False)
        if result.get("error"):
            logger.warning("Rule %s unreadable: %s", rule.name, result["error"])
            return Reading(None, available=False)
        value = result.get("value")
        if value is None or not math.isfinite(value):
            return Reading(None, available=True)
        return Reading(float(value), available=True)

    def _read_all(self) -> dict[str, Reading]:
        """Read every signal once per cycle, so correlation and detection see the same numbers.

        An empty result has two meanings. While the checkout target answers scrapes it
        is a quiet service (no traffic, no error series yet), which is healthy. When
        that cannot be confirmed it is missing data, which says nothing about health.
        """
        readings = {rule.name: self._read(rule) for rule in RULES}
        liveness = readings[LIVENESS_RULE]
        live = liveness.value is not None and not RULES_BY_NAME[LIVENESS_RULE].fires(liveness.value)
        # Prometheus answered and says checkout is down: its other series are gone because
        # the service is, which is the checkout_down incident's story and not a blind spot.
        down = liveness.value is not None and not live
        resolved: dict[str, Reading] = {}
        for name, reading in readings.items():
            empty = reading.available and reading.value is None
            if empty and not (live and name != LIVENESS_RULE):
                reading = Reading(None, available=False, explained=down and name != LIVENESS_RULE)
            resolved[name] = reading
        return resolved

    def _evaluate_rule(
        self, rule: AlertRule, readings: dict[str, Reading], unverified: set[str]
    ) -> dict[str, Any] | None:
        """Evaluate one rule; return the incident it fired or updated, if any."""
        reading = readings[rule.name]
        if not reading.available:
            self._mark(rule, "unavailable", explained=reading.explained)
            unverified.add(rule.root_cause_key)
            return None
        value = reading.value
        # Feeding an empty reading to the detector as 0.0 would corrupt its baseline.
        anomaly = self.detector.observe(rule.name, value) if value is not None else None

        if not rule.fires(value):
            self._mark(rule, "ok")
            return None

        root = self._attribute(rule, readings, unverified)
        if root is None:
            self._mark(rule, "unavailable")
            return None
        self._mark(rule, "breaching")
        self._breaches[rule.name] = self._breaches.get(rule.name, 0) + 1

        # An open incident is refreshed on every breach; a new one needs K in a row.
        if (
            self.store.find_active_by_root(root) is None
            and self._breaches[rule.name] < self.settings.detection_cycles
        ):
            return None

        evidence = {
            "rule": rule.name,
            "query": rule.query,
            "value": value,
            "threshold": rule.threshold,
            # A flat baseline yields an infinite z-score, which JSON cannot represent.
            "z_score": anomaly.z_score if anomaly and anomaly.z_score is not None and math.isfinite(anomaly.z_score) else None,
            "baseline": anomaly.baseline if anomaly else None,
            "evaluated_at": utc_now(),
            "source": "prometheus",
        }
        return self._record(root, rule.title, rule.severity, evidence)

    def _attribute(
        self, rule: AlertRule, readings: dict[str, Reading], unverified: set[str]
    ) -> str | None:
        """Pick the root cause a firing rule belongs to; None when it cannot be decided.

        Checkout symptoms with inventory dependency errors are attributed to the
        dependency. Once that incident is open the attribution holds until the errors
        fall to half the threshold, so a reading hovering at the threshold cannot split
        one fault into two incidents.
        """
        root = rule.root_cause_key
        if rule.name not in DEPENDENCY_SYMPTOMS:
            return root
        dependency = readings[INVENTORY_DEPENDENCY_RULE]
        if not dependency.available:
            # Recording under the wrong root would open a duplicate incident.
            logger.warning("Dependency check unreadable for rule %s", rule.name)
            unverified.update({root, DEPENDENCY_ROOT})
            return None
        level = dependency.value or 0.0
        if level > DEPENDENCY_ERROR_THRESHOLD or (
            level > DEPENDENCY_ERROR_THRESHOLD * ATTRIBUTION_RELEASE
            and self.store.find_active_by_root(DEPENDENCY_ROOT)
        ):
            return DEPENDENCY_ROOT
        return root

    def _record(
        self,
        root: str,
        title: str,
        severity: Severity,
        evidence: dict[str, Any],
        *,
        investigate: bool = True,
    ) -> dict[str, Any]:
        """Add evidence to the root cause's active incident, opening or reopening one if needed.

        Correlation is by root-cause key, not incident ID. A recurrence soon after
        resolution reopens that incident; after the cooldown the fault is recorded
        again under a fresh ID.
        """
        reopened = self._reopen_recent(root)
        incident, created = self.store.upsert_incident(
            "inc-" + uuid.uuid4().hex[:10], title, severity.value, root, evidence
        )
        if (
            investigate
            and (created or reopened)
            and self.store.transition_status(incident["id"], "open", "investigating")
        ):
            self.store.add_event(
                incident["id"], "investigation_started", "Aegis is collecting evidence"
            )
            self._spawn_investigation(incident["id"])
        return incident

    def _reopen_recent(self, root: str) -> bool:
        """Reopen the incident for this root cause if it resolved within the cooldown."""
        cooldown = self.settings.reopen_cooldown_seconds
        if cooldown <= 0 or self.store.find_active_by_root(root):
            return False
        cutoff = datetime.now(UTC) - timedelta(seconds=cooldown)
        for incident in self.store.list_incidents(limit=RECENT_INCIDENT_LOOKBACK):
            if incident["root_cause_key"] != root or incident["status"] != "resolved":
                continue
            resolved_at = incident.get("resolved_at")
            if not resolved_at or datetime.fromisoformat(resolved_at) < cutoff:
                continue
            if self.store.transition_status(incident["id"], "resolved", "open"):
                self.store.update_incident(incident["id"], resolved_at=None)
                self.store.add_event(
                    incident["id"],
                    "reopened",
                    f"Signal returned within {cooldown}s of resolution; reopened instead of opening a new incident",
                )
                return True
        return False

    def _check_blind(self) -> dict[str, Any] | None:
        """Open one telemetry incident once any signal has been unreadable for too long.

        Without it an outage of Prometheus or of the checkout target would look like a
        healthy service forever. The incident is for the operator: there is nothing for
        the investigator to analyse, and it resolves when the signals come back.
        """
        limit = self.settings.blind_seconds
        if limit <= 0:
            return None
        now = self._clock()
        blind = sorted(name for name, since in self._blind_since.items() if now - since > limit)
        if not blind:
            return None
        evidence = {
            "rule": "telemetry_blind",
            "blind_rules": blind,
            "blind_seconds": round(now - min(self._blind_since[name] for name in blind)),
            "threshold": limit,
            "evaluated_at": utc_now(),
            "source": "aegis",
        }
        return self._record(
            BLIND_ROOT, "Aegis cannot read its telemetry", Severity.HIGH, evidence, investigate=False
        )

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

        Auto-resolution applies to ``open`` incidents and to ``recommendation_pending``
        ones: with the signal gone nobody needs to approve the recommendation, so it
        expires (a ``recommendation_expired`` event) instead of waiting forever.
        Missing signals during ``investigating``, ``approved`` or ``executing`` do not
        mean remediation finished; resolving there would close the incident before the
        operator-approved action runs. An incident whose
        signal could not be read this cycle (``unverified_roots``) neither
        accumulates misses nor resolves, so a Prometheus outage cannot close it.
        """
        active = self.store.active_incidents()
        active_ids = {incident["id"] for incident in active}

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

            if incident["status"] not in AUTO_RESOLVABLE:
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
            if not incident or incident["status"] not in AUTO_RESOLVABLE:
                self._misses.pop(incident_id, None)
                continue

            status = incident["status"]
            # Atomic: an approval that landed since the read above keeps the incident alive.
            if self.store.merge_incident(
                incident_id, status="resolved", resolved_at=utc_now(), only_if_status={status}
            ):
                if status == "open":
                    self.store.add_event(
                        incident_id, "resolved", "Signals returned below the alert threshold"
                    )
                else:
                    self.store.add_event(
                        incident_id,
                        "recommendation_expired",
                        "Signals returned below the alert threshold before the recommendation "
                        "was approved; the recommendation expired",
                    )
            self._misses.pop(incident_id, None)

    def _prune_history(self) -> None:
        """Delete resolved history older than AEGIS_RETENTION_DAYS, at most hourly.

        Never raises: a failed prune is retried next hour and must not fail a cycle.
        """
        days = self.settings.retention_days
        now = self._clock()
        if days <= 0 or (self._last_prune is not None and now - self._last_prune < PRUNE_INTERVAL_SECONDS):
            return
        self._last_prune = now
        try:
            removed = self.store.prune(older_than_days=days)
        except Exception:
            logger.exception("Pruning history older than %d days failed", days)
            return
        if removed["incidents"]:
            logger.info("Pruned history older than %d days: %s", days, removed)

    def _note_degraded(self, degraded: set[str]) -> None:
        """Record once per outage that an incident's signal cannot be read."""
        for incident_id in degraded - self._degraded:
            self.store.add_event(
                incident_id,
                "telemetry_unavailable",
                "Aegis cannot read this incident's signal; it will not auto-resolve until it can",
            )
        self._degraded = degraded
