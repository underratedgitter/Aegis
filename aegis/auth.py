"""Shared bearer-token handling: outbound headers, constant-time checks, brute-force limits."""

from __future__ import annotations

import hmac
import math
import threading
import time


def bearer_header(key: str) -> dict[str, str]:
    """
    Build the Authorization header for a configured API key.

    Args:
        key: The shared API key. Must not be empty or whitespace-only.

    Returns:
        A header mapping suitable for httpx or urllib.

    Raises:
        ValueError: If the key is empty or whitespace-only. Callers should
            surface a configuration error instead of sending a bare
            ``Bearer `` header that the receiving service will reject with 401.
    """
    if not isinstance(key, str) or not key.strip():
        raise ValueError("API key must be a non-empty string")
    return {"Authorization": f"Bearer {key}"}


def presented_token(authorization: str) -> str | None:
    """Return the token from an ``Authorization: Bearer`` header, or None when none was offered."""
    if authorization.startswith("Bearer ") and authorization[7:]:
        return authorization[7:]
    return None


def token_matches(token: str, expected: str) -> bool:
    """Compare a presented token with the configured key in constant time."""
    return hmac.compare_digest(token.encode(), expected.encode())


class AuthFailureLimiter:
    """
    Per-client lockout after repeated failed bearer-token attempts.

    A client that fails ``max_failures`` times within ``window_seconds`` is refused
    until its oldest failure ages out, even when it then presents the right key;
    otherwise an attacker could keep guessing at full speed. State is in memory
    and per process, and is bounded: idle clients are evicted.
    """

    MAX_TRACKED_CLIENTS = 1024

    def __init__(self, max_failures: int, window_seconds: float) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def retry_after(self, client: str) -> int:
        """Seconds until ``client`` may try again; 0 when it is not locked out."""
        now = time.monotonic()
        with self._lock:
            recent = self._recent(client, now)
            if len(recent) < self.max_failures:
                return 0
            return max(1, math.ceil(recent[0] + self.window_seconds - now))

    def record_failure(self, client: str) -> None:
        now = time.monotonic()
        with self._lock:
            recent = self._recent(client, now)
            recent.append(now)
            self._failures[client] = recent
            if len(self._failures) > self.MAX_TRACKED_CLIENTS:
                for name in [k for k in self._failures if not self._recent(k, now)]:
                    del self._failures[name]

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()

    def _recent(self, client: str, now: float) -> list[float]:
        return [t for t in self._failures.get(client, []) if now - t < self.window_seconds]
