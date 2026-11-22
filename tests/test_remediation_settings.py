"""Remediation safety settings: safe defaults, parsing, and fail-fast validation."""

import pytest

from aegis.settings import Settings, SettingsError

NAMES = (
    "AEGIS_REMEDIATION_DRY_RUN",
    "AEGIS_REMEDIATION_MAX_ATTEMPTS",
    "AEGIS_REMEDIATION_BACKOFF_MS",
    "AEGIS_REMEDIATION_TIMEOUT_SECONDS",
    "AEGIS_REMEDIATION_MAX_PER_WINDOW",
    "AEGIS_REMEDIATION_WINDOW_SECONDS",
    "AEGIS_REMEDIATION_VERIFY_SECONDS",
    "AEGIS_REMEDIATION_VERIFY_INTERVAL",
    "AEGIS_REMEDIATION_ALLOWED_ACTIONS",
)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)


def test_defaults_are_safe_and_live():
    settings = Settings()

    assert settings.remediation_dry_run is False
    assert settings.remediation_max_attempts == 3
    assert settings.remediation_backoff_ms == 500
    assert settings.remediation_timeout_seconds == 5
    assert settings.remediation_max_per_window == 5
    assert settings.remediation_window_seconds == 300
    assert settings.remediation_verify_seconds == 180
    assert settings.remediation_verify_interval == 5
    assert settings.remediation_allowed_actions == frozenset(
        {
            ("checkout", "clear_fault"),
            ("checkout", "scale_simulation"),
            ("inventory", "clear_fault"),
            ("inventory", "scale_simulation"),
        }
    )


def test_values_are_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("AEGIS_REMEDIATION_DRY_RUN", "TRUE")
    monkeypatch.setenv("AEGIS_REMEDIATION_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("AEGIS_REMEDIATION_BACKOFF_MS", "0")
    monkeypatch.setenv("AEGIS_REMEDIATION_VERIFY_SECONDS", "0")
    monkeypatch.setenv("AEGIS_REMEDIATION_ALLOWED_ACTIONS", " inventory:clear_fault , checkout:clear_fault")

    settings = Settings()

    assert settings.remediation_dry_run is True
    assert settings.remediation_max_attempts == 2
    assert settings.remediation_backoff_ms == 0
    assert settings.remediation_verify_seconds == 0
    assert settings.remediation_allowed_actions == frozenset(
        {("inventory", "clear_fault"), ("checkout", "clear_fault")}
    )


@pytest.mark.parametrize(
    ("name", "value", "fragment"),
    [
        ("AEGIS_REMEDIATION_DRY_RUN", "maybe", "AEGIS_REMEDIATION_DRY_RUN must be true or false"),
        ("AEGIS_REMEDIATION_MAX_ATTEMPTS", "0", "AEGIS_REMEDIATION_MAX_ATTEMPTS must be at least 1"),
        ("AEGIS_REMEDIATION_MAX_ATTEMPTS", "11", "AEGIS_REMEDIATION_MAX_ATTEMPTS must be at most 10"),
        ("AEGIS_REMEDIATION_MAX_ATTEMPTS", "x", "AEGIS_REMEDIATION_MAX_ATTEMPTS must be an integer"),
        ("AEGIS_REMEDIATION_BACKOFF_MS", "-1", "AEGIS_REMEDIATION_BACKOFF_MS must be at least 0"),
        ("AEGIS_REMEDIATION_TIMEOUT_SECONDS", "0", "AEGIS_REMEDIATION_TIMEOUT_SECONDS must be at least 1"),
        ("AEGIS_REMEDIATION_MAX_PER_WINDOW", "0", "AEGIS_REMEDIATION_MAX_PER_WINDOW must be at least 1"),
        ("AEGIS_REMEDIATION_WINDOW_SECONDS", "0", "AEGIS_REMEDIATION_WINDOW_SECONDS must be at least 1"),
        ("AEGIS_REMEDIATION_VERIFY_SECONDS", "-5", "AEGIS_REMEDIATION_VERIFY_SECONDS must be at least 0"),
        ("AEGIS_REMEDIATION_VERIFY_INTERVAL", "0", "AEGIS_REMEDIATION_VERIFY_INTERVAL must be at least 1"),
        ("AEGIS_REMEDIATION_ALLOWED_ACTIONS", "", "AEGIS_REMEDIATION_ALLOWED_ACTIONS must list at least one"),
        ("AEGIS_REMEDIATION_ALLOWED_ACTIONS", "checkout", "AEGIS_REMEDIATION_ALLOWED_ACTIONS entry 'checkout'"),
        ("AEGIS_REMEDIATION_ALLOWED_ACTIONS", "payments:clear_fault", "AEGIS_REMEDIATION_ALLOWED_ACTIONS entry 'payments:clear_fault'"),
        ("AEGIS_REMEDIATION_ALLOWED_ACTIONS", "checkout:reboot", "AEGIS_REMEDIATION_ALLOWED_ACTIONS entry 'checkout:reboot'"),
    ],
)
def test_invalid_values_fail_fast_naming_the_variable(monkeypatch, name, value, fragment):
    monkeypatch.setenv(name, value)

    with pytest.raises(SettingsError, match=fragment):
        Settings()
