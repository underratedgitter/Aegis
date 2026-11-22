"""docker-compose.yml passes the hardening settings through with the same defaults as Settings."""

import re
from pathlib import Path

import pytest
import yaml

from aegis.settings import Settings

COMPOSE = yaml.safe_load((Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text())

# Variable -> (Settings attribute, services that read it)
PASSTHROUGH = {
    "AEGIS_CORS_ORIGINS": ("cors_origins_raw", ("control", "checkout", "inventory")),
    "AEGIS_AUTH_FAIL_MAX": ("auth_fail_max", ("control", "checkout", "inventory")),
    "AEGIS_AUTH_FAIL_WINDOW": ("auth_fail_window", ("control", "checkout", "inventory")),
    "AEGIS_MAX_BODY_BYTES": ("max_body_bytes", ("control", "checkout", "inventory")),
    "AEGIS_SIGNAL_EVENT_INTERVAL": ("signal_event_interval", ("control",)),
    "AEGIS_DETECTION_CYCLES": ("detection_cycles", ("control",)),
    "AEGIS_BLIND_SECONDS": ("blind_seconds", ("control",)),
    "AEGIS_REOPEN_COOLDOWN_SECONDS": ("reopen_cooldown_seconds", ("control",)),
    "AEGIS_CYCLE_TIMEOUT_SECONDS": ("cycle_timeout_seconds", ("control",)),
    "AEGIS_ENGINE_STALE_INTERVALS": ("engine_stale_intervals", ("control",)),
    "AEGIS_ENGINE_MAX_BACKOFF_SECONDS": ("engine_max_backoff_seconds", ("control",)),
    "AEGIS_SHUTDOWN_GRACE_SECONDS": ("shutdown_grace_seconds", ("control",)),
    "AEGIS_REMEDIATION_MAX_ATTEMPTS": ("remediation_max_attempts", ("control",)),
    "AEGIS_REMEDIATION_BACKOFF_MS": ("remediation_backoff_ms", ("control",)),
    "AEGIS_REMEDIATION_TIMEOUT_SECONDS": ("remediation_timeout_seconds", ("control",)),
    "AEGIS_REMEDIATION_MAX_PER_WINDOW": ("remediation_max_per_window", ("control",)),
    "AEGIS_REMEDIATION_WINDOW_SECONDS": ("remediation_window_seconds", ("control",)),
    "AEGIS_REMEDIATION_VERIFY_SECONDS": ("remediation_verify_seconds", ("control",)),
    "AEGIS_REMEDIATION_VERIFY_INTERVAL": ("remediation_verify_interval", ("control",)),
    "AEGIS_REMEDIATION_ALLOWED_ACTIONS": ("remediation_allowed_actions_raw", ("control",)),
}


@pytest.fixture(autouse=True)
def _default_environment(monkeypatch):
    for name in PASSTHROUGH:
        monkeypatch.delenv(name, raising=False)


CASES = [
    pytest.param(name, attribute, service, id=f"{service}-{name}")
    for name, (attribute, services) in PASSTHROUGH.items()
    for service in services
]


@pytest.mark.parametrize(("name", "attribute", "service"), CASES)
def test_variable_is_passed_with_the_settings_default(name, attribute, service):
    value = COMPOSE["services"][service]["environment"][name]

    match = re.fullmatch(r"\$\{" + name + r":-(.*)\}", str(value))
    assert match, f"{service} must pass {name} as ${{{name}:-default}}, got {value!r}"
    assert match.group(1) == str(getattr(Settings(), attribute))


def test_dry_run_is_passed_with_the_settings_default(monkeypatch):
    monkeypatch.delenv("AEGIS_REMEDIATION_DRY_RUN", raising=False)
    value = COMPOSE["services"]["control"]["environment"]["AEGIS_REMEDIATION_DRY_RUN"]

    assert value == "${AEGIS_REMEDIATION_DRY_RUN:-" + str(Settings().remediation_dry_run).lower() + "}"
