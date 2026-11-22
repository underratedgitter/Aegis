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
