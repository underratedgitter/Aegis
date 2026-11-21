import uvicorn

from aegis.settings import Settings, SettingsError

if __name__ == "__main__":
    try:
        port = Settings().port
    except SettingsError as exc:
        raise SystemExit(str(exc)) from exc
    uvicorn.run("aegis.service:app", host="0.0.0.0", port=port)
