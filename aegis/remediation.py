"""Safe remediation executor with bounded action surface."""

from __future__ import annotations

from typing import Any

import httpx

from aegis.models import RemediationAction
from aegis.settings import Settings
from aegis.storage import Store, utc_now


class RemediationError(ValueError):
    """Raised when remediation validation or execution fails."""
    pass


class RemediationExecutor:
    """Small, explicit action surface: no shell, Docker socket, or arbitrary URLs."""

    ALLOWED_FAULTS = {"latency", "errors", "dependency", "cpu"}
    ALLOWED_FAULTS_BY_TARGET = {
        "checkout": {"latency", "errors", "cpu"},
        "inventory": {"latency", "errors", "dependency"},
    }

    def __init__(self, settings: Settings, store: Store):
        self.settings = settings
        self.store = store
        self.targets = {
            "checkout": settings.checkout_url,
            "inventory": settings.inventory_url,
        }
        self._client = httpx.Client(timeout=5.0)

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

        payload: dict[str, Any]
        endpoint: str
        if action == RemediationAction.CLEAR_FAULT.value:
            payload = {"fault": recommendation["parameters"]["fault"]}
            endpoint = "/admin/faults/clear"
        else:
            replicas = int(recommendation["parameters"].get("replicas", 2))
            payload = {"replicas": replicas}
            endpoint = "/admin/scale"

        try:
            response = self._client.post(
                f"{self.targets[target].rstrip('/')}{endpoint}",
                json=payload,
            )
            response.raise_for_status()
            result = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RemediationError(f"Remediation request failed: {exc}") from exc

        data = {
            **incident["data"],
            "remediation": {
                "action": action,
                "target": target,
                "approver": approver,
                "at": utc_now(),
                "result": result,
            },
        }
        self.store.update_incident(incident_id, status="open", data=data)
        self.store.add_event(
            incident_id,
            "remediation_executed",
            f"Approved remediation executed by {approver}: {action} on {target}",
            {"action": action, "target": target, "approver": approver, "result": result},
        )
        self.store.db.commit()
        return {
            "status": "executed",
            "incident_id": incident_id,
            "action": action,
            "target": target,
            "result": result,
        }

    def validate_recommendation(self, recommendation: Any) -> tuple[str, str]:
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

        if action not in {a.value for a in RemediationAction}:
            raise RemediationError("Action is outside the Aegis allowlist")
        if target not in self.targets:
            raise RemediationError("Target is outside the Aegis allowlist")

        parameters = recommendation.get("parameters")
        if not isinstance(parameters, dict):
            raise RemediationError("Recommendation parameters must be an object")

        if action == RemediationAction.CLEAR_FAULT.value:
            fault = parameters.get("fault")
            if fault not in self.ALLOWED_FAULTS:
                raise RemediationError("Fault is outside the Aegis allowlist")
            if fault not in self.ALLOWED_FAULTS_BY_TARGET.get(target, set()):
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
