"""Telemetry collection from Prometheus, Loki, and local logs."""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from aegis.models import MetricSnapshot, SLOSnapshot, TelemetryStatus
from aegis.queries import CHECKOUT_ERRORS_30M, CHECKOUT_REQUESTS_30M, SNAPSHOT_QUERIES

if TYPE_CHECKING:
    from aegis.settings import Settings

# Every outbound call has explicit connect and read timeouts.
CONNECT_TIMEOUT_SECONDS = 1.0
READ_TIMEOUT_SECONDS = 3.0
LOKI_TIMEOUT_SECONDS = 1.0

# Prometheus queries are idempotent reads, so transient failures are retried with
# exponential backoff. Attempts are bounded so a hung server cannot stall callers.
QUERY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 0.25
RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})

# After a query exhausts its retries, further queries fail fast for this long instead of
# each spending the full retry budget on a server that is down.
BREAKER_COOLDOWN_SECONDS = 10.0


class Telemetry:
    """Collects and queries telemetry data from various sources."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._client = httpx.Client(
            timeout=httpx.Timeout(READ_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS),
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=5,
                keepalive_expiry=30,
            ),
        )
        self._breaker_open_until = 0.0

    def _get_once(self, url: str, params: dict[str, str]) -> httpx.Response:
        response = self._client.get(url, params=params)
        response.raise_for_status()
        return response

    def _get_with_retry(self, url: str, params: dict[str, str]) -> httpx.Response:
        """GET with bounded retries for transport errors and transient HTTP statuses."""
        for attempt in range(QUERY_ATTEMPTS - 1):
            try:
                return self._get_once(url, params)
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                if not self._is_outage(exc):
                    raise
            time.sleep(RETRY_BACKOFF_SECONDS * 2**attempt)
        return self._get_once(url, params)

    def prometheus_query(self, query: str) -> dict[str, Any]:
        """Execute a PromQL query against Prometheus."""
        if time.monotonic() < self._breaker_open_until:
            return {
                "query": query,
                "value": None,
                "error": "Prometheus unavailable: recent queries failed, retrying shortly",
                "source": "prometheus",
            }
        try:
            response = self._get_with_retry(
                f"{self.settings.prometheus_url.rstrip('/')}/api/v1/query", {"query": query}
            )
            self._breaker_open_until = 0.0
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
                # NaN/Inf (e.g. histogram_quantile with no traffic) mean "no data" and are not JSON-safe.
                if value is not None and not math.isfinite(value):
                    value = None
            return {"query": query, "value": value, "series": result, "source": "prometheus"}
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            if self._is_outage(exc):
                self._breaker_open_until = time.monotonic() + BREAKER_COOLDOWN_SECONDS
            return {"query": query, "value": None, "error": f"HTTP error: {exc}", "source": "prometheus"}
        except (ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
            return {"query": query, "value": None, "error": f"Parse error: {exc}", "source": "prometheus"}

    @staticmethod
    def _is_outage(exc: Exception) -> bool:
        """True for failures that say the server is unreachable or unhealthy, not that the query is bad."""
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in RETRYABLE_STATUS_CODES
        return isinstance(exc, httpx.TransportError)

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
                timeout=httpx.Timeout(LOKI_TIMEOUT_SECONDS),
            )
            return TelemetryStatus(
                available=response.is_success,
                status_code=response.status_code,
            )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            return TelemetryStatus(available=False, error=str(exc))

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
