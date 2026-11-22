"""Safe remediation executor with bounded action surface."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from aegis.auth import bearer_header
from aegis.models import RemediationAction
from aegis.storage import Store, utc_now

if TYPE_CHECKING:
    from aegis.settings import Settings

# Read/write/pool timeout for the services' admin API; connect fails faster.
ADMIN_TIMEOUT_SECONDS = 5.0


class RemediationError(ValueError):
    """Raised when remediation validation or execution fails."""
    pass


class RemediationExecutor:
    """Small, explicit action surface: no shell, Docker socket, or arbitrary URLs."""

    ALLOWED_FAULTS: ClassVar[frozenset[str]] = frozenset(
        {"latency", "errors", "dependency", "cpu"}
    )
    ALLOWED_FAULTS_BY_TARGET: ClassVar[dict[str, frozenset[str]]] = {
        "checkout": frozenset({"latency", "errors", "cpu"}),
        "inventory": frozenset({"latency", "errors", "dependency"}),
    }

    def __init__(self, settings: Settings, store: Store):
        self.settings = settings
        self.store = store
        self.targets = {
            "checkout": settings.checkout_url,
            "inventory": settings.inventory_url,
        }
        self._client = httpx.Client(timeout=httpx.Timeout(ADMIN_TIMEOUT_SECONDS, connect=2.0))

    def execute(self, incident_id: str, approver: str) -> dict[str, Any]:
        """
        Execute an approved remediation action.

        Args:
            incident_id: The incident to remediate.
            approver: The human approver's identifier.

        Returns:
            Execution result dictionary.

        Raises:
            RemediationError: If validation or execution fails.
        """
        incident = self.store.get_incident(incident_id)
        if not incident:
            raise RemediationError("Incident not found")
        if incident["status"] != "approved":
            raise RemediationError("Remediation requires an approved recommendation")

        approval = incident["data"].get("approval") or {}
        # Execute the exact proposal the operator approved
        recommendation = approval.get("recommendation") or incident["data"].get("recommendation")
        action, target = self.validate_recommendation(recommendation)

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
            replicas = int(recommendation["parameters"].get("replicas", 2))
            payload = {"replicas": replicas}
            endpoint = "/admin/scale"

        # Claim the incident atomically so concurrent calls cannot both fire the action.
        if not self.store.transition_status(incident_id, "approved", "executing"):
            raise RemediationError("Remediation is already executing or no longer approved")

        try:
            response = self._client.post(
                f"{self.targets[target].rstrip('/')}{endpoint}",
                json=payload,
                headers=bearer_header(self.settings.api_key),
            )
            response.raise_for_status()
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # The call is not retried here: it changes state, so a person decides after
            # checking the target. Release the claim so Execute can be pressed again.
            self.store.transition_status(incident_id, "executing", "approved")
            outcome = self._failure_outcome(exc)
            self.store.add_event(
                incident_id,
                "remediation_failed",
                f"Remediation {action} on {target} failed ({outcome}): {exc}",
                {"action": action, "target": target, "approver": approver, "error": str(exc)},
            )
            raise RemediationError(f"Remediation request failed ({outcome}): {exc}") from exc

        # A 2xx means the action was applied; an unreadable body must not make it look failed.
        try:
            result = response.json()
        except ValueError:
            result = {"raw": response.text[:500]}

        remediation = {
            "action": action,
            "target": target,
            "approver": approver,
            "at": utc_now(),
            "result": result,
        }
        # Merge rather than write back the snapshot read above: signals that arrived
        # during the HTTP call appended evidence that a stale write would erase.
        self.store.merge_incident(
            incident_id, {"remediation": remediation}, status="open", only_if_status={"executing"}
        )
        self.store.add_event(
            incident_id,
            "remediation_executed",
            f"Approved remediation executed by {approver}: {action} on {target}",
            {"action": action, "target": target, "approver": approver, "result": result},
        )
        return {
            "status": "executed",
            "incident_id": incident_id,
            "action": action,
            "target": target,
            "result": result,
        }

    @staticmethod
    def _failure_outcome(exc: Exception) -> str:
        """Say whether the target may have applied a request that did not complete cleanly."""
        if isinstance(exc, httpx.HTTPStatusError):
            if exc.response.status_code < 500:
                return "rejected, not applied"
            return "server error, may have been applied"
        if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.InvalidURL)):
            return "not sent, not applied"
        return "no response, may have been applied"

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
            try:
                replicas = int(parameters.get("replicas", 2))
            except (TypeError, ValueError) as exc:
                raise RemediationError("Simulation scale must be an integer") from exc
            if not 1 <= replicas <= 3:
                raise RemediationError("Simulation scale must be between 1 and 3")

        return action, target

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
