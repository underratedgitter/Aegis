import os

import uvicorn

# Must stay below the orchestrator's stop timeout (docker compose: stop_grace_period).
SHUTDOWN_TIMEOUT_SECONDS = 20

if __name__ == "__main__":
    uvicorn.run(
        "aegis.control_plane:app",
        host=os.getenv("AEGIS_HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        timeout_graceful_shutdown=SHUTDOWN_TIMEOUT_SECONDS,
    )
