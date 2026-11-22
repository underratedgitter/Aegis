"""Operational behaviour: SQLite durability, backups, readiness probes and shutdown."""

import os
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis import control_plane, service
from aegis.incidents import IncidentEngine
from aegis.settings import Settings
from aegis.storage import Store, backup_database


class TestSqliteConfiguration:
    def test_database_uses_wal_with_a_busy_timeout(self, tmp_path):
        store = Store(str(tmp_path / "aegis.db"))
        try:
            assert store.db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert store.db.execute("PRAGMA busy_timeout").fetchone()[0] == 10_000
            assert store.db.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
        finally:
            store.close()

    def test_close_checkpoints_the_wal_file(self, tmp_path):
        path = tmp_path / "aegis.db"
        store = Store(str(path))
        store.upsert_incident("inc-1", "errors", "high", "service:x", {"value": 1})
        store.close()

        assert not Path(f"{path}-wal").exists()
        reopened = Store(str(path))
        try:
            assert reopened.get_incident("inc-1") is not None
        finally:
            reopened.close()

    def test_ping_succeeds_and_fails_once_closed(self, tmp_path):
        store = Store(str(tmp_path / "aegis.db"))
        store.ping()
        store.close()
        with pytest.raises(sqlite3.Error):
            store.ping()


class TestBackup:
    def test_backup_is_a_complete_copy_of_a_live_database(self, tmp_path):
        store = Store(str(tmp_path / "aegis.db"))
        store.upsert_incident("inc-1", "errors", "high", "service:x", {"value": 1})
        try:
            dest = backup_database(str(tmp_path / "aegis.db"), str(tmp_path / "out" / "copy.db"))
            store.upsert_incident("inc-2", "later", "low", "service:y", {"value": 2})
        finally:
            store.close()

        copy = Store(dest)
        try:
            assert [i["id"] for i in copy.list_incidents()] == ["inc-1"]
            assert len(copy.events("inc-1")) == 1
        finally:
            copy.close()

    def test_backup_refuses_to_overwrite_an_existing_file(self, tmp_path):
        Store(str(tmp_path / "aegis.db")).close()
        dest = tmp_path / "copy.db"
        dest.write_bytes(b"keep me")
        with pytest.raises(FileExistsError):
            backup_database(str(tmp_path / "aegis.db"), str(dest))
        assert dest.read_bytes() == b"keep me"

    def test_backup_of_a_missing_database_fails_without_creating_one(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            backup_database(str(tmp_path / "missing.db"), str(tmp_path / "copy.db"))
        assert not (tmp_path / "missing.db").exists()
        assert not (tmp_path / "copy.db").exists()

    def test_backup_command_writes_a_restorable_copy(self, tmp_path):
        db = tmp_path / "aegis.db"
        store = Store(str(db))
        store.upsert_incident("inc-1", "errors", "high", "service:x", {"value": 1})
        store.close()
        env = {**os.environ, "AEGIS_DB_PATH": str(db)}

        result = subprocess.run(
            [sys.executable, "-m", "aegis.backup_main", str(tmp_path / "b" / "x.db")],
            env=env, capture_output=True, text=True, timeout=30, check=False,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == str(tmp_path / "b" / "x.db")
        check = sqlite3.connect(tmp_path / "b" / "x.db")
        try:
            assert check.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
        finally:
            check.close()

    def test_backup_command_defaults_to_a_timestamped_file_beside_the_database(self, tmp_path):
        db = tmp_path / "aegis.db"
        Store(str(db)).close()

        result = subprocess.run(
            [sys.executable, "-m", "aegis.backup_main"],
            env={**os.environ, "AEGIS_DB_PATH": str(db)},
            capture_output=True, text=True, timeout=30, check=False,
        )

        assert result.returncode == 0, result.stderr
        written = Path(result.stdout.strip())
        assert written.parent == tmp_path / "backups"
        assert written.name.startswith("aegis-") and written.suffix == ".db"
        assert written.exists()

    def test_backup_command_reports_failure_with_a_nonzero_exit(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "aegis.backup_main"],
            env={**os.environ, "AEGIS_DB_PATH": str(tmp_path / "missing.db")},
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode == 1
        assert "missing.db" in result.stderr


class TestControlPlaneReadiness:
    @pytest.fixture
    def client(self, monkeypatch):
        # The lifespan would start the real engine and close the shared store on exit.
        monkeypatch.setattr(control_plane.engine, "start", lambda: None)
        monkeypatch.setattr(control_plane.engine, "stop", lambda: None)
        monkeypatch.setattr(control_plane.store, "close", lambda: None)
        monkeypatch.setattr(
            control_plane.telemetry, "prometheus_query", lambda q: {"value": 1.0}
        )
        monkeypatch.setattr(
            control_plane.telemetry, "loki_status", lambda: control_plane.TelemetryStatus(available=True)
        )
        monkeypatch.setattr(type(control_plane.engine), "is_running", True)
        # Signal states left by tests that ran the shared engine against no Prometheus.
        monkeypatch.setattr(control_plane.engine, "_signal_states", {})
        return TestClient(control_plane.app)

    def test_ready_when_everything_is_up(self, client):
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "service": "aegis-control-plane",
            "checks": {"database": "ok", "engine": "ok", "prometheus": "ok", "loki": "ok"},
        }

    def test_degraded_but_ready_when_telemetry_backends_are_down(self, client, monkeypatch):
        monkeypatch.setattr(
            control_plane.telemetry, "prometheus_query", lambda q: {"value": None, "error": "down"}
        )
        response = client.get("/readyz")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"]["prometheus"] == "unavailable"
        assert body["checks"]["database"] == "ok"

    def test_unavailable_when_the_database_fails(self, client, monkeypatch):
        def broken() -> None:
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(control_plane.store, "ping", broken)
        response = client.get("/readyz")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "unavailable"
        assert body["checks"]["database"] == "error"
        assert "disk I/O error" not in response.text

    def test_unavailable_when_the_engine_thread_is_not_running(self, client, monkeypatch):
        monkeypatch.setattr(type(control_plane.engine), "is_running", False)
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["checks"]["engine"] == "stopped"

    def test_liveness_does_not_touch_the_database(self, client, monkeypatch):
        def broken() -> None:
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(control_plane.store, "ping", broken)
        assert client.get("/healthz").status_code == 200


class TestServiceReadiness:
    def test_ready_without_a_dependency(self, monkeypatch):
        monkeypatch.setattr(service, "DEPENDENCY_URL", "")
        body = TestClient(service.app).get("/readyz").json()
        assert body == {"status": "ok", "service": service.SERVICE, "checks": {}}

    def test_reports_dependency_status_without_failing_readiness(self, monkeypatch):
        monkeypatch.setattr(service, "DEPENDENCY_URL", "http://127.0.0.1:9")
        response = TestClient(service.app).get("/readyz")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "degraded"
        assert body["checks"] == {"dependency": "unavailable"}


class FakeTelemetry:
    def prometheus_query(self, query):
        return {"value": 0.0}


class TestEngineShutdown:
    def test_stop_ends_the_background_thread(self, tmp_path):
        settings = Settings(db_path=str(tmp_path / "db"), poll_seconds=3600)
        store = Store(settings.db_path)
        engine = IncidentEngine(settings, store, FakeTelemetry())
        engine.start()
        assert engine.is_running

        started = time.monotonic()
        engine.stop()

        assert not engine.is_running
        assert time.monotonic() - started < 5  # did not wait out the poll interval
        store.close()

    def test_stop_waits_for_in_flight_investigations(self, tmp_path):
        settings = Settings(db_path=str(tmp_path / "db"))
        store = Store(settings.db_path)
        engine = IncidentEngine(settings, store, FakeTelemetry())
        release = threading.Event()
        finished = threading.Event()

        def slow(_: str) -> None:
            release.wait(5)
            finished.set()

        engine._investigate = slow  # type: ignore[method-assign]
        engine._spawn_investigation("inc-1")
        threading.Timer(0.2, release.set).start()

        engine.stop()

        assert finished.is_set()
        store.close()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for(url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.2)
    raise AssertionError(f"{url} did not come up")


@pytest.mark.slow
@pytest.mark.parametrize("module", ["aegis.control_main", "aegis.service_main"])
def test_sigterm_shuts_the_process_down_cleanly(tmp_path, module):
    port = _free_port()
    env = {
        **os.environ,
        "AEGIS_HOST": "127.0.0.1",
        "PORT": str(port),
        "AEGIS_DB_PATH": str(tmp_path / "aegis.db"),
        "AEGIS_LOG_DIR": str(tmp_path / "logs"),
        "AEGIS_RUNBOOK_DIR": "runbooks",
        "LOG_PATH": str(tmp_path / "svc.jsonl"),
        "PROMETHEUS_URL": "http://127.0.0.1:9",
        "LOKI_URL": "http://127.0.0.1:9",
    }
    proc = subprocess.Popen([sys.executable, "-m", module], env=env, stderr=subprocess.PIPE, text=True)
    try:
        _wait_for(f"http://127.0.0.1:{port}/readyz")
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    stderr = proc.stderr.read() if proc.stderr else ""
    assert proc.returncode in (0, -signal.SIGTERM), stderr
    assert "Traceback" not in stderr
    if module == "aegis.control_main":
        assert not (tmp_path / "aegis.db-wal").exists()  # connection closed and checkpointed
