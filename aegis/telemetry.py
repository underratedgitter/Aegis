"""Telemetry collection from Prometheus, Loki, and local logs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from aegis.models import MetricSnapshot, SLOSnapshot, TelemetryStatus
from aegis.queries import CHECKOUT_ERRORS_30M, CHECKOUT_REQUESTS_30M, SNAPSHOT_QUERIES

if TYPE_CHECKING:
    from aegis.settings import Settings


class Telemetry:
    """Collects and queries telemetry data from various sources."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._client = httpx.Client(
            timeout=httpx.Timeout(3.0, connect=1.0),
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=5,
                keepalive_expiry=30,
            ),
        )

    def prometheus_query(self, query: str) -> dict[str, Any]:
        """Execute a PromQL query against Prometheus."""
        try:
            response = self._client.get(
                f"{self.settings.prometheus_url.rstrip('/')}/api/v1/query",
                params={"query": query},
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
        except httpx.HTTPError as exc:
            return {"query": query, "value": None, "error": f"HTTP error: {exc}", "source": "prometheus"}
        except (ValueError, KeyError) as exc:
            return {"query": query, "value": None, "error": f"Parse error: {exc}", "source": "prometheus"}

    def metric_snapshot(self) -> list[MetricSnapshot]:
        """Get a snapshot of all key metrics."""
        return [
            MetricSnapshot(name=name, **self.prometheus_query(query))
            for name, query in SNAPSHOT_QUERIES.items()
        ]

    def slo_snapshot(self) -> SLOSnapshot:
        """Calculate the current SLO status for checkout service."""
        total = self.prometheus_query(CHECKOUT_REQUESTS_30M).get("value")
        errors = self.prometheus_query(CHECKOUT_ERRORS_30M).get("value")
        target = 0.995
        if not total:
            return SLOSnapshot(
                name="checkout availability",
                target=target,
                actual=None,
                error_budget_remaining=None,
                window="30m",
            )
        error_rate = (errors or 0.0) / total
        actual = max(0.0, 1.0 - error_rate)
        budget_consumed = error_rate / (1.0 - target)
        return SLOSnapshot(
            name="checkout availability",
            target=target,
            actual=actual,
            error_budget_remaining=max(0.0, 1.0 - budget_consumed),
            window="30m",
        )

    @staticmethod
    def _tail_lines(path: Path, limit: int, chunk_size: int = 65536) -> list[str]:
        """
        Read the last `limit` lines of a file without loading the whole file.

        Log files grow for as long as the demo runs, so reading the tail keeps
        memory flat regardless of file size.
        """
        try:
            with path.open("rb") as handle:
                handle.seek(0, 2)
                end = handle.tell()
                buffer = b""
                # Read backwards until enough newlines are buffered, or the file starts.
                while end > 0 and buffer.count(b"\n") <= limit:
                    step = min(chunk_size, end)
                    end -= step
                    handle.seek(end)
                    buffer = handle.read(step) + buffer
        except OSError:
            return []
        return buffer.decode("utf-8", errors="replace").splitlines()[-limit:]

    def recent_logs(self, service: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
        """Read recent structured JSON logs from local files."""
        try:
            files = sorted(
                Path(self.settings.log_dir).glob("*.jsonl"),
                key=lambda path: path.stat().st_mtime,
            )
        except OSError:
            return []
        logs: list[dict[str, Any]] = []
        for path in files:
            if service and path.stem != service:
                continue
            lines = self._tail_lines(path, limit)
            for line in lines:
                try:
                    item = json.loads(line)
                    if not service or item.get("service") == service:
                        logs.append(item)
                except json.JSONDecodeError:
                    continue
        logs.sort(key=lambda item: item.get("ts", ""), reverse=True)
        return logs[:limit]

    def loki_status(self) -> TelemetryStatus:
        """Check if Loki is available and ready."""
        try:
            response = self._client.get(
                f"{self.settings.loki_url.rstrip('/')}/ready",
                timeout=httpx.Timeout(1.0),
            )
            return TelemetryStatus(
                available=response.is_success,
                status_code=response.status_code,
            )
        except httpx.HTTPError as exc:
            return TelemetryStatus(available=False, error=str(exc))

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
