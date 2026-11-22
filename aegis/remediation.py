"""Safe remediation executor with bounded action surface."""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from aegis.auth import bearer_header
from aegis.models import ExecutionState, RemediationAction
from aegis.storage import Store, utc_now

if TYPE_CHECKING:
    from collections.abc import Callable

    from aegis.settings import Settings
    from aegis.telemetry import Telemetry

# Connecting fails faster than the read/write/pool timeout (AEGIS_REMEDIATION_TIMEOUT_SECONDS).
ADMIN_CONNECT_TIMEOUT_SECONDS = 2.0
BACKOFF_CAP_SECONDS = 10.0
MAY_HAVE_APPLIED = "may have been applied"


class RemediationError(ValueError):
    """Raised when remediation validation or execution fails."""

    status_code: ClassVar[int] = 409
    retry_after: int | None = None

    def __init__(self, message: str, **detail: Any):
        super().__init__(message)
        self.detail = detail


class RemediationRateLimited(RemediationError):
    """The target has had its share of executions for the current window."""

    status_code = 429

    def __init__(self, message: str, retry_after: int, **detail: Any):
        super().__init__(message, **detail)
        self.retry_after = retry_after


class RemediationActionFailed(RemediationError):
    """The service's admin API did not accept the action: nothing is known to be fixed."""

    status_code = 502


@dataclass
class _Send:
    """What the admin calls for one execution did."""

    response: httpx.Response | None = None
    attempts: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    maybe_applied: bool = False


class RemediationExecutor:
    """Small, explicit action surface: no shell, Docker socket, or arbitrary URLs.

    Both actions are declarative on the service ("clear this fault", "scale to N"), so
    repeating one is harmless. Even so each approval executes at most once: it has an
    idempotency key, recorded before the call, and an attempt whose outcome is unknown
    is only repeated after the triggering signal shows that it did not take effect.
    """

    ALLOWED_FAULTS: ClassVar[frozenset[str]] = frozenset(
        {"latency", "errors", "dependency", "cpu"}
    )
    ALLOWED_FAULTS_BY_TARGET: ClassVar[dict[str, frozenset[str]]] = {
        "checkout": frozenset({"latency", "errors", "cpu"}),
        "inventory": frozenset({"latency", "errors", "dependency"}),
    }

    def __init__(
        self,
        settings: Settings,
        store: Store,
        *,
        telemetry: Telemetry | None = None,
        audit: Callable[[str, dict[str, Any]], None] | None = None,
    ):
        self.settings = settings
        self.store = store
        self.telemetry = telemetry
        self._audit = audit
        self.targets = {
            "checkout": settings.checkout_url,
            "inventory": settings.inventory_url,
        }
        self._stop = threading.Event()
        self._client = httpx.Client(
            timeout=httpx.Timeout(
                float(settings.remediation_timeout_seconds), connect=ADMIN_CONNECT_TIMEOUT_SECONDS
            )
        )

    @staticmethod
    def idempotency_key(incident_id: str, approval: dict[str, Any]) -> str:
        """Identify one approved action: the same approval always yields the same key."""
        identity = json.dumps(
            {
                "incident": incident_id,
                "approved_at": approval.get("approved_at"),
                "recommendation": approval.get("recommendation"),
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(identity.encode()).hexdigest()[:32]

    def execute(self, incident_id: str, approver: str) -> dict[str, Any]:
        """
        Execute an approved remediation action, at most once per approval.

        Args:
            incident_id: The incident to remediate.
            approver: The human approver's identifier.

        Returns:
            Execution result dictionary. `status` is "executed", "already_executed"
            (this approval ran before; nothing was called) or "dry_run".

        Raises:
            RemediationError: If validation, a guardrail, or execution fails.
                RemediationActionFailed means the action itself did not go through.
        """
        try:
            result = self._execute(incident_id, approver)
        except RemediationError as exc:
            kind = "execute_failed" if isinstance(exc, RemediationActionFailed) else "execute_refused"
            self._record(kind, incident_id=incident_id, approver=approver, reason=str(exc), **exc.detail)
            raise
        kind = {"executed": "execute", "already_executed": "execute_replayed", "dry_run": "execute_dry_run"}[
            result["status"]
        ]
        detail = {
            "incident_id": incident_id,
            "approver": approver,
            "action": result["action"],
            "target": result["target"],
        }
        detail.update({k: result[k] for k in ("idempotency_key", "attempts") if result.get(k) is not None})
        self._record(kind, **detail)
        return result

    def _record(self, kind: str, **detail: Any) -> None:
        if self._audit:
            self._audit(kind, detail)

    def _execute(self, incident_id: str, approver: str) -> dict[str, Any]:
        incident = self.store.get_incident(incident_id)
        if not incident:
            raise RemediationError("Incident not found")

        approval = incident["data"].get("approval") or {}
        # Execute the exact proposal the operator approved
        recommendation = approval.get("recommendation") or incident["data"].get("recommendation")
        key = self.idempotency_key(incident_id, {**approval, "recommendation": recommendation})
        if incident["status"] != "approved":
            replay = self._replay(incident, key)
            if replay:
                return replay
            if incident["status"] == "executing":
                raise RemediationError("Remediation is already executing")
            raise RemediationError("Remediation requires an approved recommendation")

        action, target = self.ensure_permitted(recommendation)

        if not self.settings.api_key.strip():
            raise RemediationError(
                "AEGIS_API_KEY is required before remediation can call the service admin API"
            )

        payload: dict[str, Any]
        endpoint: str
        if action == RemediationAction.CLEAR_FAULT.value:
            payload = {"fault": recommendation["parameters"]["fault"]}
            endpoint = "/admin/faults/clear"
        else:
            payload = {"replicas": self._replicas(recommendation["parameters"])}
            endpoint = "/admin/scale"
        url = f"{self.targets[target].rstrip('/')}{endpoint}"

        if self.settings.remediation_dry_run:
            self.store.add_event(
                incident_id,
                "remediation_dry_run",
                f"Dry run: would {action} on {target} via {endpoint}; nothing was changed",
                {"action": action, "target": target, "approver": approver, "payload": payload},
            )
            return {
                "status": "dry_run",
                "incident_id": incident_id,
                "action": action,
                "target": target,
                "result": {"endpoint": url, "payload": payload},
            }

        # Claim the incident atomically so concurrent calls cannot both fire the action.
        if not self.store.transition_status(incident_id, "approved", "executing"):
            raise RemediationError("Remediation is already executing or no longer approved")
        try:
            return self._run(incident, key, action, target, url, payload, approver)
        except RemediationError:
            self.store.transition_status(incident_id, "executing", "approved")
            raise

    def _replay(self, incident: dict[str, Any], key: str) -> dict[str, Any] | None:
        """The recorded result when this very approval already ran, so a repeat is harmless."""
        remediation = incident["data"].get("remediation")
        if incident["status"] not in {"open", "resolved", "closed"} or not isinstance(remediation, dict):
            return None
        if remediation.get("idempotency_key") != key:
            return None
        return {
            "status": "already_executed",
            "incident_id": incident["id"],
            "action": remediation["action"],
            "target": remediation["target"],
            "result": remediation.get("result", {}),
            "idempotency_key": key,
            "attempts": remediation.get("attempts"),
        }

    def _run(
        self,
        incident: dict[str, Any],
        key: str,
        action: str,
        target: str,
        url: str,
        payload: dict[str, Any],
        approver: str,
    ) -> dict[str, Any]:
        """Claim the key, call the service, and record the outcome. Runs with the incident "executing"."""
        incident_id = incident["id"]
        previous = self.store.get_execution(key)
        if previous and previous["state"] == ExecutionState.UNKNOWN:
            applied = self._previous_attempt_applied(incident)
            if applied is None:
                raise RemediationError(
                    "A previous attempt may have been applied and Aegis cannot check the signal "
                    "right now; retry once Prometheus is reachable",
                    action=action,
                    target=target,
                    idempotency_key=key,
                )
            if applied:
                return self._adopt(incident, key, previous, action, target, approver)
            self.store.finish_execution(
                key,
                ExecutionState.FAILED,
                previous["attempts"],
                {"error": "the signal is still firing, so the unknown attempt had no effect"},
            )

        outcome, row = self.store.claim_execution(
            key,
            incident_id,
            action,
            target,
            payload,
            approver,
            max_per_window=self.settings.remediation_max_per_window,
            window_seconds=self.settings.remediation_window_seconds,
        )
        detail = {"action": action, "target": target, "idempotency_key": key}
        if outcome == "target_busy":
            raise RemediationError(
                f"Another remediation is already running on {target}", **detail
            )
        if outcome == "rate_limited":
            retry_after = self._retry_after(row["started_at"])
            raise RemediationRateLimited(
                f"Remediation limit reached: {self.settings.remediation_max_per_window} "
                f"executions on {target} per {self.settings.remediation_window_seconds}s; "
                f"retry in {retry_after}s",
                retry_after,
                **detail,
            )
        if outcome == "existing":
            raise RemediationError(
                "This approval is already executing" if row["state"] == ExecutionState.IN_FLIGHT
                else "This approval was already executed; it will not be repeated",
                **detail,
            )

        try:
            sent = self._send(url, payload)
        except Exception:
            # Whatever happened, the target may have seen the request: keep the target
            # reconcilable instead of leaving the incident or the execution stuck.
            self.store.finish_execution(key, ExecutionState.UNKNOWN, 0, {"error": "unexpected error"})
            self.store.transition_status(incident_id, "executing", "approved")
            raise
        if sent.response is None:
            self._fail(incident_id, key, action, target, approver, sent)
        return self._succeed(incident_id, key, action, target, approver, sent)

    def _send(self, url: str, payload: dict[str, Any]) -> _Send:
        """Call the admin API, retrying failures that cannot have changed anything or are safe to repeat."""
        sent = _Send()
        for attempt in range(1, self.settings.remediation_max_attempts + 1):
            sent.attempts = attempt
            try:
                response = self._client.post(
                    url, json=payload, headers=bearer_header(self.settings.api_key)
                )
                response.raise_for_status()
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                outcome = self._failure_outcome(exc)
                sent.errors.append({"attempt": attempt, "error": str(exc), "outcome": outcome})
                sent.maybe_applied = sent.maybe_applied or MAY_HAVE_APPLIED in outcome
                if not self._retryable(exc) or attempt == self.settings.remediation_max_attempts:
                    break
                backoff = min(
                    BACKOFF_CAP_SECONDS,
                    self.settings.remediation_backoff_ms / 1000 * 2 ** (attempt - 1),
                )
                if self._stop.wait(backoff):
                    break
            else:
                sent.response = response
                break
        return sent

    def _fail(
        self, incident_id: str, key: str, action: str, target: str, approver: str, sent: _Send
    ) -> None:
        outcome = sent.errors[-1]["outcome"]
        if sent.maybe_applied and MAY_HAVE_APPLIED not in outcome:
            outcome = f"{outcome}; an earlier attempt {MAY_HAVE_APPLIED}"
        state = ExecutionState.UNKNOWN if sent.maybe_applied else ExecutionState.FAILED
        detail = {
            "action": action,
            "target": target,
            "idempotency_key": key,
            "attempts": sent.attempts,
            "outcome": outcome,
        }
        self.store.finish_execution(key, state, sent.attempts, {**detail, "errors": sent.errors})
        plural = "" if sent.attempts == 1 else "s"
        summary = f"({outcome}) after {sent.attempts} attempt{plural}: {sent.errors[-1]['error']}"
        self.store.add_event(
            incident_id,
            "remediation_failed",
            f"Remediation {action} on {target} failed {summary}",
            {**detail, "approver": approver, "errors": sent.errors},
        )
        raise RemediationActionFailed(f"Remediation request failed {summary}", **detail)

    def _succeed(
        self, incident_id: str, key: str, action: str, target: str, approver: str, sent: _Send
    ) -> dict[str, Any]:
        assert sent.response is not None
        # A 2xx means the action was applied; an unreadable body must not make it look failed.
        try:
            result = sent.response.json()
        except ValueError:
            result = {"raw": sent.response.text[:500]}
        remediation = {
            "action": action,
            "target": target,
            "approver": approver,
            "at": utc_now(),
            "result": result,
            "idempotency_key": key,
            "attempts": sent.attempts,
        }
        self._complete(incident_id, key, remediation)
        self.store.add_event(
            incident_id,
            "remediation_executed",
            f"Approved remediation executed by {approver}: {action} on {target}",
            {**remediation, "result": result},
        )
        return {
            "status": "executed",
            "incident_id": incident_id,
            "action": action,
            "target": target,
            "result": result,
            "idempotency_key": key,
            "attempts": sent.attempts,
        }

    def _complete(self, incident_id: str, key: str, remediation: dict[str, Any]) -> None:
        """Record the success on the key first, so a crash before the incident write is recoverable."""
        self.store.finish_execution(key, ExecutionState.SUCCEEDED, remediation["attempts"], remediation)
        # Merge rather than write back a snapshot: signals that arrived during the HTTP
        # call appended evidence that a stale write would erase.
        self.store.merge_incident(
            incident_id, {"remediation": remediation}, status="open", only_if_status={"executing"}
        )

    def _adopt(
        self,
        incident: dict[str, Any],
        key: str,
        previous: dict[str, Any],
        action: str,
        target: str,
        approver: str,
    ) -> dict[str, Any]:
        """Treat an interrupted attempt as applied because the signal it targets has cleared."""
        incident_id = incident["id"]
        result = {"inferred": "an interrupted attempt had applied the action: its signal is clear"}
        remediation = {
            "action": action,
            "target": target,
            "approver": approver,
            "at": utc_now(),
            "result": result,
            "idempotency_key": key,
            "attempts": previous["attempts"],
        }
        self._complete(incident_id, key, remediation)
        self.store.add_event(
            incident_id,
            "remediation_executed",
            f"Interrupted remediation {action} on {target} confirmed applied: its signal is clear",
            remediation,
        )
        return {
            "status": "already_executed",
            "incident_id": incident_id,
            "action": action,
            "target": target,
            "result": result,
            "idempotency_key": key,
            "attempts": previous["attempts"],
        }

    def _previous_attempt_applied(self, incident: dict[str, Any]) -> bool | None:
        """Whether an attempt of unknown outcome took effect: True, False, or None if unknowable."""
        if self.telemetry is None:
            return None
        return self._signals_clear(self._signal_readings(incident))

    def _signal_readings(self, incident: dict[str, Any]) -> list[dict[str, Any]]:
        """Re-read every alert rule that fired for the incident."""
        # Deferred: aegis.incidents imports aegis.agent, which imports this module.
        from aegis.incidents import RULES

        assert self.telemetry is not None
        rules = {rule.name: rule for rule in RULES}
        data = incident["data"]
        entries = [*data.get("evidence", []), data.get("latest_evidence")]
        names = dict.fromkeys(
            entry["rule"]
            for entry in entries
            if isinstance(entry, dict) and entry.get("rule") in rules
        )
        readings: list[dict[str, Any]] = []
        for name in names:
            rule = rules[name]
            result = self.telemetry.prometheus_query(rule.query)
            error = result.get("error")
            readings.append(
                {
                    "rule": name,
                    "value": result.get("value"),
                    "threshold": rule.threshold,
                    "clear": None if error else not rule.fires(result.get("value")),
                }
            )
        return readings

    @staticmethod
    def _signals_clear(readings: list[dict[str, Any]]) -> bool | None:
        """True when every signal is below its threshold, False if any still fires, else None."""
        if any(reading["clear"] is False for reading in readings):
            return False
        if not readings or any(reading["clear"] is None for reading in readings):
            return None
        return True

    def _retry_after(self, oldest_started_at: str) -> int:
        """Seconds until the oldest counted execution leaves the window."""
        elapsed = (datetime.now(UTC) - datetime.fromisoformat(oldest_started_at)).total_seconds()
        return max(1, math.ceil(self.settings.remediation_window_seconds - elapsed))

    @staticmethod
    def _retryable(exc: Exception) -> bool:
        """A 4xx or malformed URL will fail again; anything else may be transient."""
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code >= 500
        return not isinstance(exc, httpx.InvalidURL)

    @staticmethod
    def _failure_outcome(exc: Exception) -> str:
        """Say whether the target may have applied a request that did not complete cleanly."""
        if isinstance(exc, httpx.HTTPStatusError):
            if exc.response.status_code < 500:
                return "rejected, not applied"
            return f"server error, {MAY_HAVE_APPLIED}"
        if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.InvalidURL)):
            return "not sent, not applied"
        return f"no response, {MAY_HAVE_APPLIED}"

    def ensure_permitted(self, recommendation: Any) -> tuple[str, str]:
        """Validate a recommendation and check it against the configured per-target allowlist.

        Raises:
            RemediationError: If it is invalid or not permitted by AEGIS_REMEDIATION_ALLOWED_ACTIONS.
        """
        action, target = self.validate_recommendation(recommendation)
        if (target, action) not in self.settings.remediation_allowed_actions:
            raise RemediationError(
                f"{action} on {target} is not permitted by AEGIS_REMEDIATION_ALLOWED_ACTIONS"
            )
        return action, target

    @staticmethod
    def _replicas(parameters: dict[str, Any]) -> int:
        """Parse the replica count strictly: no booleans, no truncated fractions."""
        raw = parameters.get("replicas", 2)
        if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
            raise RemediationError("Simulation scale must be an integer")
        try:
            number = float(raw)
        except (ValueError, OverflowError) as exc:
            raise RemediationError("Simulation scale must be an integer") from exc
        if not number.is_integer():
            raise RemediationError("Simulation scale must be an integer")
        replicas = int(number)
        if not 1 <= replicas <= 3:
            raise RemediationError("Simulation scale must be between 1 and 3")
        return replicas

    @classmethod
    def validate_recommendation(cls, recommendation: Any) -> tuple[str, str]:
        """
        Validate a recommendation against the allowlist.

        Args:
            recommendation: The recommendation to validate.

        Returns:
            Tuple of (action, target).

        Raises:
            RemediationError: If validation fails.
        """
        if not isinstance(recommendation, dict):
            raise RemediationError("Recommendation must be an object")

        action = recommendation.get("action")
        target = recommendation.get("target")

        # An LLM can return a list or dict here, which is unhashable for the set/dict lookups.
        if not isinstance(action, str) or action not in {a.value for a in RemediationAction}:
            raise RemediationError("Action is outside the Aegis allowlist")
        if not isinstance(target, str) or target not in cls.ALLOWED_FAULTS_BY_TARGET:
            raise RemediationError("Target is outside the Aegis allowlist")

        parameters = recommendation.get("parameters")
        if not isinstance(parameters, dict):
            raise RemediationError("Recommendation parameters must be an object")

        if action == RemediationAction.CLEAR_FAULT.value:
            fault = parameters.get("fault")
            if not isinstance(fault, str) or fault not in cls.ALLOWED_FAULTS:
                raise RemediationError("Fault is outside the Aegis allowlist")
            if fault not in cls.ALLOWED_FAULTS_BY_TARGET.get(target, frozenset()):
                raise RemediationError("Fault is not valid for the selected target")
        else:
            cls._replicas(parameters)

        return action, target

    def close(self) -> None:
        """Stop retrying and close the HTTP client."""
        self._stop.set()
        self._client.close()
