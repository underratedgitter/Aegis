"""Application settings with validation and environment variable support."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aegis.models import RemediationAction

MAX_PORT = 65535
# The engine's stop() waits grace + 5 s; with uvicorn's 10 s drain that must fit Compose's 30 s.
MAX_SHUTDOWN_GRACE_SECONDS = 15
MAX_REMEDIATION_ATTEMPTS = 10
REMEDIATION_TARGETS = frozenset({"checkout", "inventory"})
DEFAULT_REMEDIATION_ALLOWED = ",".join(
    f"{target}:{action.value}" for target in sorted(REMEDIATION_TARGETS) for action in RemediationAction
)
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


class SettingsError(ValueError):
    """Raised at startup when the environment holds an unusable configuration."""


def _env(name: str, default: str) -> Any:
    """Read an environment variable when a Settings instance is built, not at import time."""
    return field(default_factory=lambda: os.getenv(name, default))


def _env_int(name: str, default: int) -> Any:
    """
    Read an integer environment variable.

    A value that is not an integer is kept as the raw string so that validation
    can report it by name; silently using the default would hide a typo such as
    AEGIS_RATE_LIMIT_MAX=1O0 behind a weaker limit than the operator intended.
    """

    def parse() -> int | str:
        raw = os.getenv(name)
        if raw is None or not raw.strip():
            return default
        try:
            return int(raw)
        except ValueError:
            return raw

    return field(default_factory=parse)


def _env_bool(name: str, default: bool) -> Any:
    """Read a boolean environment variable; an unrecognised value is kept so validation names it."""

    def parse() -> bool | str:
        raw = os.getenv(name)
        if raw is None or not raw.strip():
            return default
        lowered = raw.strip().lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
        return raw

    return field(default_factory=parse)


def _origin_problem(origin: str) -> str | None:
    """Describe why a CORS origin is unusable, or return None when it is a bare origin."""
    if origin == "*":
        return "wildcard origins are not allowed; list each origin explicitly"
    try:
        parts = urlsplit(origin)
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return "is not a valid URL"
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return "must look like https://host[:port]"
    if parts.path or parts.query or parts.fragment or parts.username:
        return "must not include a path, query, fragment, or credentials"
    return None


@dataclass(frozen=True)
class Settings:
    """
    Application settings loaded from environment variables.

    Values are resolved when a Settings instance is created, so tests and callers
    that adjust the environment first see the change. Construction validates every
    value and raises SettingsError listing all problems, so a bad deployment fails
    at startup instead of misbehaving later.
    """

    # Prometheus
    prometheus_url: str = _env("PROMETHEUS_URL", "http://localhost:9090")

    # Loki
    loki_url: str = _env("LOKI_URL", "http://localhost:3100")

    # Service URLs
    checkout_url: str = _env("CHECKOUT_URL", "http://localhost:8080")
    inventory_url: str = _env("INVENTORY_URL", "http://localhost:8081")

    # Listener
    port: int = _env_int("PORT", 8000)

    # Storage
    db_path: str = _env("AEGIS_DB_PATH", "./data/aegis.db")
    log_dir: str = _env("AEGIS_LOG_DIR", "./logs")
    runbook_dir: str = _env("AEGIS_RUNBOOK_DIR", "./runbooks")

    # Engine
    poll_seconds: int = _env_int("AEGIS_POLL_SECONDS", 5)
    max_evidence_history: int = _env_int("AEGIS_MAX_EVIDENCE", 100)
    resolution_cycles: int = _env_int("AEGIS_RESOLUTION_CYCLES", 2)
    signal_event_interval: int = _env_int("AEGIS_SIGNAL_EVENT_INTERVAL", 60)
    # Resolved incidents (with their events and executions) older than this many days are pruned; 0 keeps all.
    retention_days: int = _env_int("AEGIS_RETENTION_DAYS", 30)
    # Supervision: a cycle longer than the timeout is abandoned and counted as a failure;
    # no success for stale_intervals polls (plus one cycle timeout) marks the engine stalled.
    cycle_timeout_seconds: int = _env_int("AEGIS_CYCLE_TIMEOUT_SECONDS", 60)
    engine_stale_intervals: int = _env_int("AEGIS_ENGINE_STALE_INTERVALS", 3)
    engine_max_backoff_seconds: int = _env_int("AEGIS_ENGINE_MAX_BACKOFF_SECONDS", 60)
    shutdown_grace_seconds: int = _env_int("AEGIS_SHUTDOWN_GRACE_SECONDS", 10)

    # LLM
    openai_model: str = _env("OPENAI_MODEL", "gpt-4.1-mini")

    # Security
    api_key: str = _env("AEGIS_API_KEY", "")
    rate_limit_window: int = _env_int("AEGIS_RATE_LIMIT_WINDOW", 60)
    rate_limit_max: int = _env_int("AEGIS_RATE_LIMIT_MAX", 100)
    auth_fail_window: int = _env_int("AEGIS_AUTH_FAIL_WINDOW", 60)
    auth_fail_max: int = _env_int("AEGIS_AUTH_FAIL_MAX", 10)
    max_body_bytes: int = _env_int("AEGIS_MAX_BODY_BYTES", 65536)
    cors_origins_raw: str = _env("AEGIS_CORS_ORIGINS", "")

    # Detection
    detection_cycles: int = _env_int("AEGIS_DETECTION_CYCLES", 2)
    blind_seconds: int = _env_int("AEGIS_BLIND_SECONDS", 300)
    reopen_cooldown_seconds: int = _env_int("AEGIS_REOPEN_COOLDOWN_SECONDS", 300)
    # Remediation safety
    remediation_dry_run: bool = _env_bool("AEGIS_REMEDIATION_DRY_RUN", False)
    remediation_max_attempts: int = _env_int("AEGIS_REMEDIATION_MAX_ATTEMPTS", 3)
    remediation_backoff_ms: int = _env_int("AEGIS_REMEDIATION_BACKOFF_MS", 500)
    remediation_timeout_seconds: int = _env_int("AEGIS_REMEDIATION_TIMEOUT_SECONDS", 5)
    remediation_max_per_window: int = _env_int("AEGIS_REMEDIATION_MAX_PER_WINDOW", 5)
    remediation_window_seconds: int = _env_int("AEGIS_REMEDIATION_WINDOW_SECONDS", 300)
    remediation_verify_seconds: int = _env_int("AEGIS_REMEDIATION_VERIFY_SECONDS", 180)
    remediation_verify_interval: int = _env_int("AEGIS_REMEDIATION_VERIFY_INTERVAL", 5)
    remediation_allowed_actions_raw: str = _env(
        "AEGIS_REMEDIATION_ALLOWED_ACTIONS", DEFAULT_REMEDIATION_ALLOWED
    )

    def __post_init__(self) -> None:
        problems: list[str] = []
        for name in ("prometheus_url", "loki_url", "checkout_url", "inventory_url"):
            problem = self._url_problem(getattr(self, name))
            if problem:
                problems.append(f"{name.upper()} {problem}")
        minimums = {
            "PORT": ("port", 1),
            "AEGIS_POLL_SECONDS": ("poll_seconds", 1),
            "AEGIS_MAX_EVIDENCE": ("max_evidence_history", 1),
            "AEGIS_RESOLUTION_CYCLES": ("resolution_cycles", 1),
            "AEGIS_SIGNAL_EVENT_INTERVAL": ("signal_event_interval", 0),
            "AEGIS_RETENTION_DAYS": ("retention_days", 0),
            "AEGIS_CYCLE_TIMEOUT_SECONDS": ("cycle_timeout_seconds", 1),
            "AEGIS_ENGINE_STALE_INTERVALS": ("engine_stale_intervals", 1),
            "AEGIS_ENGINE_MAX_BACKOFF_SECONDS": ("engine_max_backoff_seconds", 1),
            "AEGIS_SHUTDOWN_GRACE_SECONDS": ("shutdown_grace_seconds", 0),
            "AEGIS_RATE_LIMIT_WINDOW": ("rate_limit_window", 1),
            "AEGIS_RATE_LIMIT_MAX": ("rate_limit_max", 1),
            "AEGIS_AUTH_FAIL_WINDOW": ("auth_fail_window", 1),
            "AEGIS_AUTH_FAIL_MAX": ("auth_fail_max", 1),
            "AEGIS_MAX_BODY_BYTES": ("max_body_bytes", 1),
            "AEGIS_DETECTION_CYCLES": ("detection_cycles", 1),
            "AEGIS_BLIND_SECONDS": ("blind_seconds", 0),
            "AEGIS_REOPEN_COOLDOWN_SECONDS": ("reopen_cooldown_seconds", 0),
            "AEGIS_REMEDIATION_MAX_ATTEMPTS": ("remediation_max_attempts", 1),
            "AEGIS_REMEDIATION_BACKOFF_MS": ("remediation_backoff_ms", 0),
            "AEGIS_REMEDIATION_TIMEOUT_SECONDS": ("remediation_timeout_seconds", 1),
            "AEGIS_REMEDIATION_MAX_PER_WINDOW": ("remediation_max_per_window", 1),
            "AEGIS_REMEDIATION_WINDOW_SECONDS": ("remediation_window_seconds", 1),
            "AEGIS_REMEDIATION_VERIFY_SECONDS": ("remediation_verify_seconds", 0),
            "AEGIS_REMEDIATION_VERIFY_INTERVAL": ("remediation_verify_interval", 1),
        }
        for env_name, (attr, minimum) in minimums.items():
            value = getattr(self, attr)
            if not isinstance(value, int) or isinstance(value, bool):
                problems.append(f"{env_name} must be an integer, got {value!r}")
            elif value < minimum:
                problems.append(f"{env_name} must be at least {minimum}, got {value}")
            elif attr == "port" and value > MAX_PORT:
                problems.append(f"{env_name} must be at most {MAX_PORT}, got {value}")
            elif attr == "shutdown_grace_seconds" and value > MAX_SHUTDOWN_GRACE_SECONDS:
                problems.append(
                    f"{env_name} must be at most {MAX_SHUTDOWN_GRACE_SECONDS}, got {value}"
                )
            elif attr == "remediation_max_attempts" and value > MAX_REMEDIATION_ATTEMPTS:
                problems.append(
                    f"{env_name} must be at most {MAX_REMEDIATION_ATTEMPTS}, got {value}"
                )
        if not isinstance(self.remediation_dry_run, bool):
            problems.append(
                f"AEGIS_REMEDIATION_DRY_RUN must be true or false, got {self.remediation_dry_run!r}"
            )
        problems.extend(self._allowed_actions_problems())
        for origin in self.cors_origins:
            problem = _origin_problem(origin)
            if problem:
                problems.append(f"AEGIS_CORS_ORIGINS entry {origin!r} {problem}")
        if problems:
            raise SettingsError(
                "Invalid configuration:\n" + "\n".join(f"  - {item}" for item in problems)
            )

    def _allowed_actions_problems(self) -> list[str]:
        entries = [item.strip() for item in self.remediation_allowed_actions_raw.split(",") if item.strip()]
        if not entries:
            return ["AEGIS_REMEDIATION_ALLOWED_ACTIONS must list at least one target:action pair"]
        actions = {action.value for action in RemediationAction}
        problems = []
        for entry in entries:
            target, _, action = entry.partition(":")
            if target not in REMEDIATION_TARGETS or action not in actions:
                problems.append(
                    f"AEGIS_REMEDIATION_ALLOWED_ACTIONS entry {entry!r} must be "
                    f"target:action with target in {sorted(REMEDIATION_TARGETS)} and "
                    f"action in {sorted(actions)}"
                )
        return problems

    @staticmethod
    def _url_problem(value: str) -> str | None:
        try:
            parts = urlsplit(value)
            parts.port  # noqa: B018 - raises ValueError on a malformed port
        except ValueError:
            return f"must be a valid http(s) URL, got {value!r}"
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return f"must be an http(s) URL such as http://host:9090, got {value!r}"
        return None

    @property
    def cors_origins(self) -> tuple[str, ...]:
        """Browser origins allowed to call the API cross-origin; empty means same-origin only."""
        return tuple(item.strip().rstrip("/") for item in self.cors_origins_raw.split(",") if item.strip())

    @property
    def remediation_allowed_actions(self) -> frozenset[tuple[str, str]]:
        """The (target, action) pairs the executor may run."""
        pairs = (
            item.strip().partition(":")
            for item in self.remediation_allowed_actions_raw.split(",")
            if item.strip()
        )
        return frozenset((target, action) for target, _, action in pairs)

    def ensure_dirs(self) -> None:
        """Create required directories if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.runbook_dir).mkdir(parents=True, exist_ok=True)
