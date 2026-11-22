from __future__ import annotations

import json
import logging
import logging.handlers
import socket
import sys
import time
from pathlib import Path
from typing import Any

from aegis.errors import redact_urls

# Module loggers are named aegis.<module>; configuring this parent gives all of them
# the same JSON handlers and level.
PACKAGE_LOGGER = "aegis"
LOG_FILE_MAX_BYTES = 10 * 1024 * 1024
LOG_FILE_BACKUPS = 3


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str = "aegis") -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "service": getattr(record, "service", self.service),
            "host": socket.gethostname(),
            "message": redact_urls(record.getMessage()),
        }
        for key in ("request_id", "route", "status", "duration_ms", "fault", "dependency"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = redact_urls(self.formatException(record.exc_info))
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(service: str, log_path: str | None = None) -> logging.Logger:
    """
    Log JSON to stdout, and to a rotating file when a path is given.

    Returns the logger named after the service. The same handlers are attached to the
    "aegis" parent logger, so module loggers (incidents, supervisor, remediation,
    agent) are formatted, labelled with this service and written at INFO too.
    """
    formatter = JsonFormatter(service)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_path:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            logging.handlers.RotatingFileHandler(
                log_path, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUPS
            )
        )
    logger = logging.getLogger(service)
    for target in (logger, logging.getLogger(PACKAGE_LOGGER)):
        target.setLevel(logging.INFO)
        target.handlers.clear()
        for handler in handlers:
            handler.setFormatter(formatter)
            target.addHandler(handler)
    logger.propagate = False
    return logger
