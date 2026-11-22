"""Evidence-first investigator with optional LLM tool-calling loop."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.breaker import CircuitBreaker
from aegis.models import (
    Evidence,
    Investigation,
    InvestigationMode,
    Recommendation,
    RemediationAction,
)
from aegis.remediation import RemediationExecutor, no_remediation_reason
from aegis.selfmetrics import BACKEND_ERRORS
from aegis.storage import Store, utc_now

if TYPE_CHECKING:
    from collections.abc import Callable, Collection

    from aegis.settings import Settings
    from aegis.telemetry import Telemetry

logger = logging.getLogger(__name__)

# Bounds for the OpenAI investigation. Any breach raises, and ``investigate``
# falls back to the deterministic local investigation.
LLM_REQUEST_TIMEOUT_SECONDS = 20.0
LLM_MAX_RETRIES = 1
LLM_DEADLINE_SECONDS = 60.0
LLM_MAX_TOOL_ROUNDS = 6
LLM_MAX_TOOL_CALLS_PER_ROUND = 8
# After this many consecutive failures the model is skipped (local investigation only) for
# the cooldown, so a dead or rate-limited API does not cost a full timeout per incident.
LLM_BREAKER_FAILURES = 3
LLM_BREAKER_COOLDOWN_SECONDS = 60.0
PROMPT_MAX_CHARS = 60_000
PROMPT_EVIDENCE_ITEMS = 5
TOOL_RESULT_MAX_CHARS = 8_000
RUNBOOK_MAX_CHARS = 20_000
FALLBACK_REASON_MAX_CHARS = 300

# Statuses in which a finished investigation may (re)propose a recommendation.
# Later statuses keep their status: the approved proposal is stored separately.
_REVIEWABLE_STATUSES = frozenset({"open", "investigating", "recommendation_pending"})


def _clip(text: str, limit: int) -> str:
    """Truncate text to a character budget, saying how much was cut."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[truncated {len(text) - limit} chars]"


class AgentInvestigator:
    """Evidence-first investigator with an optional OpenAI tool-calling loop."""

    def __init__(
        self,
        settings: Settings,
        store: Store,
        telemetry: Telemetry,
        llm_breaker: CircuitBreaker | None = None,
    ):
        self.settings = settings
        self.store = store
        self.telemetry = telemetry
        self.llm_breaker = llm_breaker or CircuitBreaker(
            "llm", LLM_BREAKER_FAILURES, LLM_BREAKER_COOLDOWN_SECONDS
        )

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
        advisory = no_remediation_reason(incident)
        if advisory:
            # Nothing the model could propose is safe, so it is not asked.
            result = self._advisory_investigation(incident, advisory)
            result["mode"] = InvestigationMode.LOCAL_FALLBACK.value
        elif os.getenv("OPENAI_API_KEY"):
            try:
                result = self._guarded_llm_investigation(incident)
                result["mode"] = InvestigationMode.LLM_TOOL_CALLING.value
                # Reject malformed LLM output before it is stored or proposed for approval.
                Investigation.model_validate(result)
                # A proposal the executor would refuse can never be approved; fail it here.
                RemediationExecutor.validate_recommendation(result["recommendation"])
            except Exception as exc:
                logger.warning("LLM investigation of %s failed: %s", incident_id, exc)
                result = self._local_investigation(incident)
                result["mode"] = InvestigationMode.LOCAL_FALLBACK.value
                result["fallback_reason"] = _clip(
                    f"{type(exc).__name__}: {exc}", FALLBACK_REASON_MAX_CHARS
                )
        else:
            result = self._local_investigation(incident)
            result["mode"] = InvestigationMode.LOCAL_FALLBACK.value

        # Merge under the store lock: the snapshot read above is stale by now, and
        # writing it back would drop evidence appended while the investigation ran.
        data = {"investigation": result, "recommendation": result["recommendation"]}
        updated = self.store.merge_incident(
            incident_id,
            data,
            # With nothing to approve the incident goes back to open for an operator.
            status="recommendation_pending" if result["recommendation"] else "open",
            only_if_status=_REVIEWABLE_STATUSES,
        )
        if updated is None:
            # Approved, executing or resolved while we worked: keep the status.
            self.store.merge_incident(incident_id, data)
        self.store.add_event(
            incident_id,
            "agent_completed",
            f"Investigation complete ({result['mode']}): {result['hypothesis']}",
            {"citations": result.get("evidence", []), "mode": result["mode"]},
        )
        return result

    def _guarded_llm_investigation(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Call the model unless its circuit breaker is open; report the outcome to the breaker."""
        if not self.llm_breaker.allow():
            raise RuntimeError("LLM circuit open: recent calls failed, using local investigation")
        try:
            result = self._llm_investigation(incident)
        except Exception as exc:
            BACKEND_ERRORS.labels("llm").inc()
            self.llm_breaker.record_failure(f"{type(exc).__name__}: {exc}")
            raise
        self.llm_breaker.record_success()
        return result

    def _advisory_investigation(self, incident: dict[str, Any], reason: str) -> dict[str, Any]:
        """An investigation for an incident that has no safe automated fix: findings only."""
        incident_id = incident["id"]
        timeline = self._local_tool("get_incident_timeline", {}, incident_id, [])
        evidence = [
            Evidence(source="timeline", label=item.get("kind", "event"), detail=item.get("message", ""))
            for item in timeline[-3:]
        ]
        return {
            "hypothesis": reason,
            "confidence": "high",
            "evidence": [e.model_dump() for e in evidence],
            "recommendation": None,
            "next_checks": ["Restore the failing component, then confirm the signals return"],
            "tools_used": ["get_incident_timeline"],
            "generated_at": utc_now(),
        }

    def _local_investigation(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Perform investigation using local tools without LLM."""
        root = incident["root_cause_key"]
        incident_id = incident["id"]
        metrics = self._local_tool("get_current_metrics", {}, incident_id, [])
        logs = self._local_tool("get_recent_logs", {"limit": 12}, incident_id, [])
        timeline = self._local_tool("get_incident_timeline", {}, incident_id, [])
        runbook_slug = self._runbook_slug(root)
        runbook = self._local_tool(
            "read_runbook", {"slug": runbook_slug}, incident_id, "Runbook unavailable."
        )

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

        hypothesis, confidence, recommendation = self._generate_recommendation(root, self._fired_rules(incident))

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

    def _local_tool(
        self, name: str, arguments: dict[str, Any], incident_id: str, default: Any
    ) -> Any:
        """Run a tool for the local investigation; a failing source must not block the proposal."""
        try:
            return self._call_tool(name, arguments, incident_id)
        except Exception as exc:
            logger.warning("Tool %s failed for %s: %s", name, incident_id, exc)
            return default

    @staticmethod
    def _fired_rules(incident: dict[str, Any]) -> set[str]:
        """Names of the alert rules that have fired for the incident, from its evidence."""
        data = incident["data"]
        entries = [*data.get("evidence", []), data.get("latest_evidence")]
        return {entry["rule"] for entry in entries if isinstance(entry, dict) and "rule" in entry}

    def _generate_recommendation(
        self, root: str, rules: Collection[str] = ()
    ) -> tuple[str, str, Recommendation]:
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
        # Errors outrank latency; a latency-only incident must clear the latency fault,
        # since clearing "errors" would leave it running and the fix could never verify.
        fault = "errors" if "checkout_error_rate" in rules or "checkout_p95_latency" not in rules else "latency"
        recommendation = Recommendation(
            action=RemediationAction.CLEAR_FAULT,
            target="checkout",
            parameters={"fault": fault},
            reason=(
                "Clear the known demo fault only after an operator confirms the evidence."
            ),
        )
        return hypothesis, "medium", recommendation

    def _llm_investigation(self, incident: dict[str, Any]) -> dict[str, Any]:
        """
        Perform investigation using OpenAI tool-calling.

        Time, tool rounds and prompt size are all bounded; exceeding any of them
        raises so the caller can fall back to the local investigation.
        """
        from openai import OpenAI

        # The SDK default is a 10 minute timeout with 2 retries, which would pin the
        # investigation thread (and the incident in "investigating") through an outage.
        client = OpenAI(timeout=LLM_REQUEST_TIMEOUT_SECONDS, max_retries=LLM_MAX_RETRIES)
        deadline = time.monotonic() + LLM_DEADLINE_SECONDS
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
                    {
                        "incident": self._prompt_incident(incident),
                        "task": "Investigate and propose a bounded remediation.",
                    },
                    default=str,
                ),
            },
        ]
        prompt_chars = sum(len(message["content"]) for message in messages)

        for _ in range(LLM_MAX_TOOL_ROUNDS):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Agent exceeded its {LLM_DEADLINE_SECONDS:g}s time budget")
            # The message/tool payloads are built as plain dicts; the SDK accepts them
            # at runtime but its overloads require the typed param classes.
            response = client.chat.completions.create(  # type: ignore[call-overload]
                model=self.settings.openai_model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                timeout=min(LLM_REQUEST_TIMEOUT_SECONDS, remaining),
            )
            message = response.choices[0].message
            tool_calls = message.tool_calls or []

            if not tool_calls:
                content = message.content or "{}"
                parsed: Any
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    parsed = json.loads(
                        content.replace("```json", "").replace("```", "").strip()
                    )
                if not isinstance(parsed, dict):
                    raise ValueError("Agent answer must be a JSON object")
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

            for index, call in enumerate(tool_calls):
                if index >= LLM_MAX_TOOL_CALLS_PER_ROUND:
                    result: Any = {"error": "Too many tool calls in one round; call skipped"}
                else:
                    result = self._run_llm_tool(call, incident["id"])
                content = _clip(json.dumps(result, default=str), TOOL_RESULT_MAX_CHARS)
                prompt_chars += len(content)
                messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
            if prompt_chars > PROMPT_MAX_CHARS:
                raise RuntimeError(f"Agent prompt exceeded {PROMPT_MAX_CHARS} characters")

        raise RuntimeError("Agent exceeded tool-call budget")

    def _run_llm_tool(self, call: Any, incident_id: str) -> Any:
        """Run one model-requested tool; failures go back to the model instead of aborting."""
        try:
            arguments = json.loads(call.function.arguments or "{}")
            if not isinstance(arguments, dict):
                raise ValueError("Tool arguments must be a JSON object")
            return self._call_tool(call.function.name, arguments, incident_id)
        except Exception as exc:
            logger.warning("LLM tool %s failed for %s: %s", call.function.name, incident_id, exc)
            return {"error": _clip(f"{type(exc).__name__}: {exc}", 300)}

    @staticmethod
    def _prompt_incident(incident: dict[str, Any]) -> dict[str, Any]:
        """Reduce an incident to what the model needs; evidence history can be large."""
        data = incident.get("data") or {}
        summary = {
            key: incident.get(key)
            for key in ("id", "title", "severity", "status", "root_cause_key", "first_seen")
        }
        summary["latest_evidence"] = data.get("latest_evidence")
        summary["recent_evidence"] = list(data.get("evidence") or [])[-PROMPT_EVIDENCE_ITEMS:]
        return summary

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
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                return handle.read(RUNBOOK_MAX_CHARS)
        except OSError:
            return "No matching runbook found. Treat this as ambiguous and do not broaden remediation."

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
