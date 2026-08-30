"""Application settings with validation and environment variable support."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _env(name: str, default: str) -> Any:
    """Read an environment variable when a Settings instance is built, not at import time."""
    return field(default_factory=lambda: os.getenv(name, default))


def _env_int(name: str, default: int) -> Any:
    """Read an integer environment variable, falling back to the default when unparseable."""

    def parse() -> int:
        raw = os.getenv(name)
        if raw is None:
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    return field(default_factory=parse)


@dataclass(frozen=True)
class Settings:
    """
    Application settings loaded from environment variables.

    Values are resolved when a Settings instance is created, so tests and callers
    that adjust the environment first see the change.
    """

    # Prometheus
    prometheus_url: str = _env("PROMETHEUS_URL", "http://localhost:9090")

    # Loki
    loki_url: str = _env("LOKI_URL", "http://localhost:3100")

    # Service URLs
    checkout_url: str = _env("CHECKOUT_URL", "http://localhost:8080")
    inventory_url: str = _env("INVENTORY_URL", "http://localhost:8081")

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

    def ensure_dirs(self) -> None:
        """Create required directories if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.runbook_dir).mkdir(parents=True, exist_ok=True)
