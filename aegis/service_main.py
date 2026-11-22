import os

import uvicorn

from aegis.settings import Settings, SettingsError

# Time to drain open connections on SIGTERM; with the engine join (15s) it must stay
# below the orchestrator's stop timeout (docker compose: stop_grace_period 30s).
SHUTDOWN_TIMEOUT_SECONDS = 10

if __name__ == "__main__":
    try:
        port = Settings().port
    except SettingsError as exc:
        raise SystemExit(str(exc)) from exc
    uvicorn.run(
        "aegis.service:app",
        host=os.getenv("AEGIS_HOST", "0.0.0.0"),
        port=port,
        timeout_graceful_shutdown=SHUTDOWN_TIMEOUT_SECONDS,
    )
