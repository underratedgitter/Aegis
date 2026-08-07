from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from aegis.settings import Settings


class Telemetry:
    def __init__(self, settings: Settings):
        self.settings = settings

    def prometheus_query(self, query: str) -> dict[str, Any]:
        try:
            response = httpx.get(
                f"{self.settings.prometheus_url.rstrip('/')}/api/v1/query",
                params={"query": query},
                timeout=3,
            )
            response.raise_for_status()
            payload = response.json()
            if payload.get("status") != "success":
                return {
                    "query": query,
                    "value": None,
                    "error": payload.get("error", "query failed"),
                }
            result = payload.get("data", {}).get("result", [])
            value = None
            if result:
                raw = result[0].get("value", [None, None])[1]
                value = float(raw) if raw is not None else None
            return {"query": query, "value": value, "series": result, "source": "prometheus"}
        except (httpx.HTTPError, ValueError) as exc:
            return {"query": query, "value": None, "error": str(exc), "source": "prometheus"}

    def metric_snapshot(self) -> list[dict[str, Any]]:
        queries = {
            "checkout_error_rate": (
                'sum(rate(aegis_http_requests_total{service="checkout",status=~"5.."}[2m])) '
                '/ clamp_min(sum(rate(aegis_http_requests_total{service="checkout"}[2m])), 0.001)'
            ),
            "checkout_p95_latency": (
                "histogram_quantile(0.95, sum(rate(aegis_http_request_duration_seconds_bucket"
                '{service="checkout"}[2m])) by (le))'
            ),
            "inventory_dependency_errors": (
                'sum(rate(aegis_dependency_errors_total{service="checkout",dependency="inventory"}[2m]))'
            ),
            "checkout_cpu_burn": 'aegis_cpu_burn_active{service="checkout"}',
        }
        return [{"name": name, **self.prometheus_query(query)} for name, query in queries.items()]

    def slo_snapshot(self) -> dict[str, Any]:
        total = self.prometheus_query(
            'sum(increase(aegis_http_requests_total{service="checkout"}[30m]))'
        ).get("value")
        errors = self.prometheus_query(
            'sum(increase(aegis_http_requests_total{service="checkout",status=~"5.."}[30m]))'
        ).get("value")
        target = 0.995
        if not total:
            return {
                "name": "checkout availability",
                "target": target,
                "actual": None,
                "error_budget_remaining": None,
                "window": "30m",
            }
        error_rate = (errors or 0.0) / total
        actual = max(0.0, 1.0 - error_rate)
        budget_consumed = error_rate / (1.0 - target)
        return {
            "name": "checkout availability",
            "target": target,
            "actual": actual,
            "error_budget_remaining": max(0.0, 1.0 - budget_consumed),
            "window": "30m",
        }

    def recent_logs(self, service: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
        files = sorted(
            Path(self.settings.log_dir).glob("*.jsonl"), key=lambda path: path.stat().st_mtime
        )
        logs: list[dict[str, Any]] = []
        for path in files:
            if service and path.stem != service:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
            except OSError:
                continue
            for line in lines:
                try:
                    item = json.loads(line)
                    if not service or item.get("service") == service:
                        logs.append(item)
                except json.JSONDecodeError:
                    continue
        logs.sort(key=lambda item: item.get("ts", ""), reverse=True)
        return logs[:limit]

    def loki_status(self) -> dict[str, Any]:
        try:
            response = httpx.get(f"{self.settings.loki_url.rstrip('/')}/ready", timeout=1)
            return {"available": response.is_success, "status_code": response.status_code}
        except httpx.HTTPError as exc:
            return {"available": False, "error": str(exc)}
