import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    prometheus_url: str = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
    loki_url: str = os.getenv("LOKI_URL", "http://localhost:3100")
    checkout_url: str = os.getenv("CHECKOUT_URL", "http://localhost:8080")
    inventory_url: str = os.getenv("INVENTORY_URL", "http://localhost:8081")
    db_path: str = os.getenv("AEGIS_DB_PATH", "./data/aegis.db")
    log_dir: str = os.getenv("AEGIS_LOG_DIR", "./logs")
    runbook_dir: str = os.getenv("AEGIS_RUNBOOK_DIR", "./runbooks")
    poll_seconds: int = int(os.getenv("AEGIS_POLL_SECONDS", "5"))
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

    def ensure_dirs(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
