"""Tests for environment-driven settings resolution."""

import os

from aegis.settings import Settings


class TestEnvironmentResolution:
    def test_env_is_read_when_the_instance_is_built(self, monkeypatch):
        """Settings must not freeze environment values at import time."""
        monkeypatch.setenv("PROMETHEUS_URL", "http://prom.example:9090")
        assert Settings().prometheus_url == "http://prom.example:9090"

        monkeypatch.setenv("PROMETHEUS_URL", "http://prom-two.example:9090")
        assert Settings().prometheus_url == "http://prom-two.example:9090"

    def test_defaults_apply_when_unset(self, monkeypatch):
        monkeypatch.delenv("PROMETHEUS_URL", raising=False)
        assert Settings().prometheus_url == "http://localhost:9090"

    def test_explicit_arguments_win_over_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_DB_PATH", "/from/env.db")
        assert Settings(db_path="/explicit.db").db_path == "/explicit.db"

    def test_integer_env_is_parsed(self, monkeypatch):
        monkeypatch.setenv("AEGIS_POLL_SECONDS", "17")
        assert Settings().poll_seconds == 17

    def test_unparseable_integer_falls_back_to_default(self, monkeypatch):
        """A malformed value must not crash startup."""
        monkeypatch.setenv("AEGIS_POLL_SECONDS", "soon")
        assert Settings().poll_seconds == 5

    def test_security_settings_are_exposed(self, monkeypatch):
        monkeypatch.setenv("AEGIS_API_KEY", "s3cret")
        monkeypatch.setenv("AEGIS_RATE_LIMIT_MAX", "5")
        settings = Settings()
        assert settings.api_key == "s3cret"
        assert settings.rate_limit_max == 5

    def test_api_key_defaults_to_empty(self, monkeypatch):
        monkeypatch.delenv("AEGIS_API_KEY", raising=False)
        assert Settings().api_key == ""

    def test_settings_are_frozen(self):
        settings = Settings()
        try:
            settings.prometheus_url = "http://nope"  # type: ignore[misc]
        except Exception as exc:
            assert "frozen" in str(exc).lower() or isinstance(exc, AttributeError)
        else:
            raise AssertionError("Settings should be immutable")

    def test_ensure_dirs_creates_paths(self, tmp_path):
        settings = Settings(
            db_path=str(tmp_path / "db" / "aegis.db"),
            log_dir=str(tmp_path / "logs"),
            runbook_dir=str(tmp_path / "runbooks"),
        )
        settings.ensure_dirs()
        assert (tmp_path / "db").is_dir()
        assert (tmp_path / "logs").is_dir()
        assert (tmp_path / "runbooks").is_dir()

    def test_os_environ_is_not_mutated(self, monkeypatch):
        monkeypatch.delenv("LOKI_URL", raising=False)
        Settings()
        assert "LOKI_URL" not in os.environ
