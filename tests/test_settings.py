"""Tests for environment-driven settings resolution."""

import os

import pytest

from aegis.settings import Settings, SettingsError


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

    def test_blank_integer_uses_the_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_POLL_SECONDS", "  ")
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


class TestAllowedHosts:
    def test_defaults_cover_localhost_and_the_compose_services(self, monkeypatch):
        monkeypatch.delenv("AEGIS_ALLOWED_HOSTS", raising=False)
        assert set(Settings().allowed_hosts) == {"localhost", "127.0.0.1", "control", "checkout", "inventory"}

    def test_configured_hosts_extend_the_defaults(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ALLOWED_HOSTS", "ops.example.com, *.internal.example")
        hosts = Settings().allowed_hosts
        assert {"ops.example.com", "*.internal.example", "localhost"} <= set(hosts)

    @pytest.mark.parametrize("entry", ["*", "https://ops.example.com", "ops.example.com:8000", "ops/example", "bad host", "-x"])
    def test_malformed_entries_name_the_variable(self, monkeypatch, entry):
        monkeypatch.setenv("AEGIS_ALLOWED_HOSTS", entry)
        with pytest.raises(SettingsError, match="AEGIS_ALLOWED_HOSTS entry"):
            Settings()


class TestFailFastValidation:
    @pytest.mark.parametrize(
        "name",
        [
            "AEGIS_POLL_SECONDS",
            "AEGIS_MAX_EVIDENCE",
            "AEGIS_RESOLUTION_CYCLES",
            "AEGIS_SIGNAL_EVENT_INTERVAL",
            "AEGIS_RATE_LIMIT_MAX",
            "AEGIS_RATE_LIMIT_WINDOW",
            "AEGIS_RATE_LIMIT_MUTATION_MAX",
            "AEGIS_AUTH_FAIL_MAX",
            "AEGIS_AUTH_FAIL_WINDOW",
            "AEGIS_MAX_BODY_BYTES",
            "PORT",
        ],
    )
    def test_malformed_integer_names_the_variable(self, monkeypatch, name):
        monkeypatch.setenv(name, "soon")
        with pytest.raises(SettingsError, match=f"{name} must be an integer, got 'soon'"):
            Settings()

    def test_signal_event_interval_defaults_to_a_minute_and_allows_zero(self, monkeypatch):
        monkeypatch.delenv("AEGIS_SIGNAL_EVENT_INTERVAL", raising=False)
        assert Settings().signal_event_interval == 60
        monkeypatch.setenv("AEGIS_SIGNAL_EVENT_INTERVAL", "0")
        assert Settings().signal_event_interval == 0

    def test_negative_signal_event_interval_is_rejected(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SIGNAL_EVENT_INTERVAL", "-1")
        with pytest.raises(SettingsError, match="AEGIS_SIGNAL_EVENT_INTERVAL must be at least 0"):
            Settings()

    @pytest.mark.parametrize("value", ["0", "-5"])
    def test_non_positive_values_are_rejected(self, monkeypatch, value):
        monkeypatch.setenv("AEGIS_RATE_LIMIT_MAX", value)
        with pytest.raises(SettingsError, match="AEGIS_RATE_LIMIT_MAX must be at least 1"):
            Settings()

    @pytest.mark.parametrize("value", ["0", "65536", "-1"])
    def test_port_must_be_a_valid_tcp_port(self, monkeypatch, value):
        monkeypatch.setenv("PORT", value)
        with pytest.raises(SettingsError, match="PORT"):
            Settings()

    @pytest.mark.parametrize("value", ["65535", "1"])
    def test_port_bounds_are_inclusive(self, monkeypatch, value):
        monkeypatch.setenv("PORT", value)
        assert Settings().port == int(value)

    @pytest.mark.parametrize(
        "value", ["localhost:9090", "ftp://host", "http://", "http://host:notaport", "http://host:99999", ""]
    )
    def test_bad_urls_are_rejected(self, monkeypatch, value):
        monkeypatch.setenv("PROMETHEUS_URL", value)
        with pytest.raises(SettingsError, match="PROMETHEUS_URL"):
            Settings()

    def test_every_problem_is_reported_at_once(self, monkeypatch):
        monkeypatch.setenv("LOKI_URL", "nope")
        monkeypatch.setenv("PORT", "x")
        with pytest.raises(SettingsError) as exc:
            Settings()
        assert "LOKI_URL" in str(exc.value)
        assert "PORT" in str(exc.value)

    def test_explicit_arguments_are_validated_too(self):
        with pytest.raises(SettingsError, match="CHECKOUT_URL"):
            Settings(checkout_url="not a url")

    def test_compose_service_urls_are_accepted(self, monkeypatch):
        monkeypatch.setenv("PROMETHEUS_URL", "http://prometheus:9090")
        monkeypatch.setenv("LOKI_URL", "https://loki.internal.example:3100/")
        assert Settings().prometheus_url == "http://prometheus:9090"

    def test_missing_api_key_is_allowed_for_demo_mode(self, monkeypatch):
        monkeypatch.delenv("AEGIS_API_KEY", raising=False)
        assert Settings().api_key == ""


class TestCorsOrigins:
    def test_default_is_no_cross_origin_access(self, monkeypatch):
        monkeypatch.delenv("AEGIS_CORS_ORIGINS", raising=False)
        assert Settings().cors_origins == ()

    def test_comma_separated_origins_are_parsed_and_normalised(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CORS_ORIGINS", " https://ops.example.com/ ,http://localhost:3000,, ")
        assert Settings().cors_origins == ("https://ops.example.com", "http://localhost:3000")

    @pytest.mark.parametrize(
        "value", ["*", "ops.example.com", "https://ops.example.com/app", "javascript:alert(1)", "https://h:bad"]
    )
    def test_unusable_origins_are_rejected(self, monkeypatch, value):
        monkeypatch.setenv("AEGIS_CORS_ORIGINS", value)
        with pytest.raises(SettingsError, match="AEGIS_CORS_ORIGINS"):
            Settings()


class TestEngineSupervisionSettings:
    DEFAULTS = (
        ("AEGIS_CYCLE_TIMEOUT_SECONDS", "cycle_timeout_seconds", 60),
        ("AEGIS_ENGINE_STALE_INTERVALS", "engine_stale_intervals", 3),
        ("AEGIS_ENGINE_MAX_BACKOFF_SECONDS", "engine_max_backoff_seconds", 60),
        ("AEGIS_SHUTDOWN_GRACE_SECONDS", "shutdown_grace_seconds", 10),
    )

    @pytest.mark.parametrize(("name", "attribute", "default"), DEFAULTS)
    def test_defaults_and_overrides(self, monkeypatch, name, attribute, default):
        monkeypatch.delenv(name, raising=False)
        assert getattr(Settings(), attribute) == default
        monkeypatch.setenv(name, "7")
        assert getattr(Settings(), attribute) == 7

    @pytest.mark.parametrize(("name", "attribute", "default"), DEFAULTS)
    def test_malformed_values_name_the_variable(self, monkeypatch, name, attribute, default):
        monkeypatch.setenv(name, "soon")
        with pytest.raises(SettingsError, match=f"{name} must be an integer, got 'soon'"):
            Settings()

    @pytest.mark.parametrize(
        "name",
        ["AEGIS_CYCLE_TIMEOUT_SECONDS", "AEGIS_ENGINE_STALE_INTERVALS", "AEGIS_ENGINE_MAX_BACKOFF_SECONDS"],
    )
    def test_zero_is_rejected(self, monkeypatch, name):
        monkeypatch.setenv(name, "0")
        with pytest.raises(SettingsError, match=f"{name} must be at least 1"):
            Settings()

    def test_shutdown_grace_may_be_zero_but_must_fit_the_stop_timeout(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SHUTDOWN_GRACE_SECONDS", "0")
        assert Settings().shutdown_grace_seconds == 0
        monkeypatch.setenv("AEGIS_SHUTDOWN_GRACE_SECONDS", "16")
        with pytest.raises(SettingsError, match="AEGIS_SHUTDOWN_GRACE_SECONDS must be at most 15"):
            Settings()
