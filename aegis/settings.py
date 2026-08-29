"""Application settings with validation and environment variable support."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Application settings loaded from environment variables."""

    # Prometheus
    prometheus_url: str = os.getenv("PROMETHEUS_URL", "http://localhost:9090")

    # Loki
    loki_url: str = os.getenv("LOKI_URL", "http://localhost:3100")

    # Service URLs
    checkout_url: str = os.getenv("CHECKOUT_URL", "http://localhost:8080")
    inventory_url: str = os.getenv("INVENTORY_URL", "http://localhost:8081")

    # Storage
    db_path: str = os.getenv("AEGIS_DB_PATH", "./data/aegis.db")
    log_dir: str = os.getenv("AEGIS_LOG_DIR", "./logs")
    runbook_dir: str = os.getenv("AEGIS_RUNBOOK_DIR", "./runbooks")

    # Engine
    poll_seconds: int = int(os.getenv("AEGIS_POLL_SECONDS", "5"))
    max_evidence_history: int = int(os.getenv("AEGIS_MAX_EVIDENCE", "100"))
    resolution_cycles: int = int(os.getenv("AEGIS_RESOLUTION_CYCLES", "2"))

    # LLM
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

    # Security
    api_key: str = os.getenv("AEGIS_API_KEY", "")
    rate_limit_window: int = int(os.getenv("AEGIS_RATE_LIMIT_WINDOW", "60"))
    rate_limit_max: int = int(os.getenv("AEGIS_RATE_LIMIT_MAX", "100"))

    def ensure_dirs(self) -> None:
        """Create required directories if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.runbook_dir).mkdir(parents=True, exist_ok=True)
