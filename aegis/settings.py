"""Application settings with validation and environment variable support."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_PORT = 65535


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
            "AEGIS_RATE_LIMIT_WINDOW": ("rate_limit_window", 1),
            "AEGIS_RATE_LIMIT_MAX": ("rate_limit_max", 1),
            "AEGIS_AUTH_FAIL_WINDOW": ("auth_fail_window", 1),
            "AEGIS_AUTH_FAIL_MAX": ("auth_fail_max", 1),
            "AEGIS_MAX_BODY_BYTES": ("max_body_bytes", 1),
        }
        for env_name, (attr, minimum) in minimums.items():
            value = getattr(self, attr)
            if not isinstance(value, int) or isinstance(value, bool):
                problems.append(f"{env_name} must be an integer, got {value!r}")
            elif value < minimum:
                problems.append(f"{env_name} must be at least {minimum}, got {value}")
            elif attr == "port" and value > MAX_PORT:
                problems.append(f"{env_name} must be at most {MAX_PORT}, got {value}")
        for origin in self.cors_origins:
            problem = _origin_problem(origin)
            if problem:
                problems.append(f"AEGIS_CORS_ORIGINS entry {origin!r} {problem}")
        if problems:
            raise SettingsError(
                "Invalid configuration:\n" + "\n".join(f"  - {item}" for item in problems)
            )

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

    def ensure_dirs(self) -> None:
        """Create required directories if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.runbook_dir).mkdir(parents=True, exist_ok=True)
