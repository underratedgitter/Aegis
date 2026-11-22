"""A small thread-safe circuit breaker for outbound dependencies."""

from __future__ import annotations

import threading
import time
from typing import Literal

from pydantic import BaseModel

BreakerState = Literal["closed", "open", "half_open"]
ERROR_MAX_CHARS = 300


class BreakerStatus(BaseModel):
    """Point-in-time view of a breaker, safe to serialise."""

    state: BreakerState
    consecutive_failures: int
    retry_in_seconds: float | None = None
    last_error: str | None = None


class CircuitBreaker:
    """
    Fail fast against a dependency that keeps failing.

    Closed: calls pass. After `failure_threshold` consecutive failures it opens and
    `allow()` is False for `cooldown_seconds`. Then one probe is let through
    (half-open); its success closes the breaker, its failure reopens it for another
    full cooldown. Callers report each outcome with `record_success` or
    `record_failure` after a call that `allow()` permitted.
    """

    def __init__(self, name: str, failure_threshold: int, cooldown_seconds: float):
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if cooldown_seconds <= 0:
            raise ValueError("cooldown_seconds must be at least 1 millisecond")
        self.name = name
        self._threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._lock = threading.Lock()
        self._failures = 0
        self._opened_at: float | None = None
        self._probing = False
        self._last_error: str | None = None

    def allow(self) -> bool:
        """Whether a call may go out now; claims the single probe once the cooldown is over."""
        with self._lock:
            if self._opened_at is None:
                return True
            now = time.monotonic()
            if now - self._opened_at < self._cooldown:
                return False
            # Claiming the probe restarts the clock, so a probe whose outcome is never
            # reported (a crashed caller) is replaced after another cooldown, not never.
            self._opened_at = now
            self._probing = True
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probing = False

    def record_failure(self, error: str) -> None:
        with self._lock:
            self._failures += 1
            self._last_error = error[:ERROR_MAX_CHARS]
            self._probing = False
            if self._failures >= self._threshold:
                self._opened_at = time.monotonic()

    def snapshot(self) -> BreakerStatus:
        with self._lock:
            state: BreakerState = "closed"
            retry_in: float | None = None
            if self._opened_at is not None and self._probing:
                state = "half_open"
            elif self._opened_at is not None:
                state = "open"
                retry_in = round(max(0.0, self._cooldown - (time.monotonic() - self._opened_at)), 1)
            return BreakerStatus(
                state=state,
                consecutive_failures=self._failures,
                retry_in_seconds=retry_in,
                last_error=self._last_error,
            )
