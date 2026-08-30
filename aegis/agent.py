"""Evidence-first investigator with optional LLM tool-calling loop."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.models import (
    Evidence,
    InvestigationMode,
    Recommendation,
    RemediationAction,
)
from aegis.storage import Store, utc_now

if TYPE_CHECKING:
    from collections.abc import Callable

    from aegis.settings import Settings
    from aegis.telemetry import Telemetry


class AgentInvestigator:
    """Evidence-first investigator with an optional OpenAI tool-calling loop."""

    def __init__(self, settings: Settings, store: Store, telemetry: Telemetry):
        self.settings = settings
        self.store = store
        self.telemetry = telemetry

    def investigate(self, incident_id: str) -> dict[str, Any]:
        """
        Investigate an incident using either LLM or local fallback.

        Args:
            incident_id: The ID of the incident to investigate.

        Returns:
            Investigation result dictionary.

        Raises:
            ValueError: If incident not found.
        """
        incident = self.store.get_incident(incident_id)
        if not incident:
            raise ValueError("Incident not found")

        result: dict[str, Any]
        if os.getenv("OPENAI_API_KEY"):
            try:
                result = self._llm_investigation(incident)
                result["mode"] = InvestigationMode.LLM_TOOL_CALLING.value
            except Exception as exc:
                result = self._local_investigation(incident)
                result["mode"] = InvestigationMode.LOCAL_FALLBACK.value
                result["fallback_reason"] = str(exc)
        else:
            result = self._local_investigation(incident)
            result["mode"] = InvestigationMode.LOCAL_FALLBACK.value

        data = {
            **incident["data"],
            "investigation": result,
            "recommendation": result["recommendation"],
        }
        self.store.update_incident(incident_id, status="recommendation_pending", data=data)
        self.store.add_event(
            incident_id,
            "agent_completed",
            f"Investigation complete ({result['mode']}): {result['hypothesis']}",
            {"citations": result.get("evidence", []), "mode": result["mode"]},
        )
        return result

    def _local_investigation(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Perform investigation using local tools without LLM."""
        root = incident["root_cause_key"]
        metrics = self._call_tool("get_current_metrics", {}, incident["id"])
        logs = self._call_tool("get_recent_logs", {"limit": 12}, incident["id"])
        timeline = self._call_tool("get_incident_timeline", {}, incident["id"])
        runbook_slug = self._runbook_slug(root)
        runbook = self._call_tool("read_runbook", {"slug": runbook_slug}, incident["id"])

        evidence = [
            Evidence(
                source="prometheus",
                label=item["name"],
                detail=f"value={item.get('value')} query={item.get('query')}",
            )
            for item in metrics
            if item.get("value") is not None
        ]
        evidence += [
            Evidence(
                source="logs",
                label="recent structured logs",
                detail=item.get("message", ""),
            )
            for item in logs[:4]
        ]
        evidence += [
            Evidence(
                source="timeline",
                label=item.get("kind", "event"),
                detail=item.get("message", ""),
            )
            for item in timeline[-3:]
        ]
        evidence.append(Evidence(source="runbook", label=runbook_slug, detail=runbook[:280]))

        hypothesis, confidence, recommendation = self._generate_recommendation(root)

        return {
            "hypothesis": hypothesis,
            "confidence": confidence,
            "evidence": [e.model_dump() for e in evidence],
            "recommendation": recommendation.model_dump(),
            "next_checks": [
                "Confirm the error rate and p95 latency return below threshold",
                "Watch the incident for two healthy polling cycles",
            ],
            "tools_used": [
                "get_current_metrics",
                "get_recent_logs",
                "read_runbook",
                "get_incident_timeline",
            ],
            "generated_at": utc_now(),
        }

    def _generate_recommendation(self, root: str) -> tuple[str, str, Recommendation]:
        """Generate hypothesis, confidence, and recommendation based on root cause."""
        if root == "dependency:inventory":
            hypothesis = (
                "Inventory is failing or timing out, causing checkout errors through its "
                "upstream dependency boundary."
            )
            recommendation = Recommendation(
                action=RemediationAction.CLEAR_FAULT,
                target="inventory",
                parameters={"fault": "dependency"},
                reason=(
                    "The known-safe action clears the injected inventory dependency fault; "
                    "it does not grant arbitrary command execution."
                ),
            )
            return hypothesis, "high", recommendation

        if root == "service:checkout:cpu":
            hypothesis = (
                "Synthetic CPU stress is active on checkout and is consuming worker capacity."
            )
            recommendation = Recommendation(
                action=RemediationAction.CLEAR_FAULT,
                target="checkout",
                parameters={"fault": "cpu"},
                reason="Clear the bounded chaos fault after human approval.",
            )
            return hypothesis, "high", recommendation

        hypothesis = (
            "Checkout is unhealthy; the available telemetry points to an application-level "
            "fault that needs confirmation before broader action."
        )
        recommendation = Recommendation(
            action=RemediationAction.CLEAR_FAULT,
            target="checkout",
            parameters={"fault": "errors"},
            reason=(
                "Clear the known demo fault only after an operator confirms the evidence."
            ),
        )
        return hypothesis, "medium", recommendation

    def _llm_investigation(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Perform investigation using OpenAI tool-calling."""
        from openai import OpenAI

        client = OpenAI()
        tools = self._tool_schemas()
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": (
                    "You are Aegis, a cautious SRE investigator. Use tools to inspect evidence "
                    "before reasoning. Never invent telemetry. "
                    "Return JSON with keys hypothesis, confidence, evidence, recommendation, "
                    "and next_checks. Every evidence item must cite source and label. "
                    "recommendation.action must be clear_fault or scale_simulation. "
                    "target must be checkout or inventory; it is only a proposal and a human "
                    "approves execution."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {"incident": incident, "task": "Investigate and propose a bounded remediation."}
                ),
            },
        ]

        for _ in range(6):
            # The message/tool payloads are built as plain dicts; the SDK accepts them
            # at runtime but its overloads require the typed param classes.
            response = client.chat.completions.create(  # type: ignore[call-overload]
                model=self.settings.openai_model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
            )
            message = response.choices[0].message
            tool_calls = message.tool_calls or []

            if not tool_calls:
                content = message.content or "{}"
                parsed: dict[str, Any]
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    parsed = json.loads(
                        content.replace("```json", "").replace("```", "").strip()
                    )
                parsed.setdefault("tools_used", [])
                parsed.setdefault("generated_at", utc_now())
                return parsed

            messages.append(
                {
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": [call.model_dump() for call in tool_calls],
                }
            )

            for call in tool_calls:
                arguments = json.loads(call.function.arguments or "{}")
                result = self._call_tool(call.function.name, arguments, incident["id"])
                messages.append(
                    {"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)}
                )

        raise RuntimeError("Agent exceeded tool-call budget")

    def _call_tool(self, name: str, arguments: dict[str, Any], incident_id: str) -> Any:
        """Dispatch tool calls to the appropriate handler."""
        tools: dict[str, Callable[..., Any]] = {
            # Tool results must be plain JSON-serialisable data: the local path
            # reads them as dicts and the LLM path passes them through json.dumps.
            "get_current_metrics": lambda query=None: (
                self.telemetry.prometheus_query(query)
                if query
                else [snapshot.model_dump() for snapshot in self.telemetry.metric_snapshot()]
            ),
            "get_recent_logs": lambda service=None, limit=20: self.telemetry.recent_logs(
                service, max(1, min(int(limit or 20), 200))
            ),
            "read_runbook": lambda slug="checkout-high-error-rate": self._read_runbook(slug),
            "get_incident_timeline": lambda: self.store.events(incident_id),
        }
        if name not in tools:
            raise ValueError(f"Unknown tool: {name}")
        return tools[name](**arguments)

    def _read_runbook(self, slug: str) -> str:
        """Read a runbook by slug, with path traversal protection."""
        safe_slug = Path(slug).name
        path = Path(self.settings.runbook_dir) / (
            safe_slug if safe_slug.endswith(".md") else f"{safe_slug}.md"
        )
        if not path.exists():
            return "No matching runbook found. Treat this as ambiguous and do not broaden remediation."
        return path.read_text(encoding="utf-8")

    @staticmethod
    def _runbook_slug(root: str) -> str:
        """Map root cause key to runbook slug."""
        if root == "dependency:inventory":
            return "inventory-dependency-failure"
        if root == "service:checkout:cpu":
            return "checkout-cpu-stress"
        return "checkout-high-error-rate"

    @staticmethod
    def _tool_schemas() -> list[dict[str, Any]]:
        """Return OpenAI tool schemas for the investigator."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_current_metrics",
                    "description": "Query Prometheus or get the Aegis metric snapshot.",
                    "parameters": {"type": "object", "properties": {"query": {"type": "string"}}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_recent_logs",
                    "description": "Read recent structured JSON logs.",
                    "parameters": {
                        "type": "object",
                        "properties": {"service": {"type": "string"}, "limit": {"type": "integer"}},
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_runbook",
                    "description": "Read a known failure-pattern runbook.",
                    "parameters": {
                        "type": "object",
                        "properties": {"slug": {"type": "string"}},
                        "required": ["slug"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_incident_timeline",
                    "description": "Read the incident detection and investigation timeline.",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
        ]
