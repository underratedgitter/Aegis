import os

import uvicorn

# Time to drain open connections on SIGTERM; with the engine join (15s) it must stay
# below the orchestrator's stop timeout (docker compose: stop_grace_period 30s).
SHUTDOWN_TIMEOUT_SECONDS = 10

if __name__ == "__main__":
    uvicorn.run(
        "aegis.service:app",
        host=os.getenv("AEGIS_HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        timeout_graceful_shutdown=SHUTDOWN_TIMEOUT_SECONDS,
    )
