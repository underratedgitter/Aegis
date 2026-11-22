"""docker-compose.yml passes the hardening settings through with the same defaults as Settings."""

import re
from pathlib import Path

import pytest
import yaml

from aegis.settings import Settings

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

# Variable -> (Settings attribute, services that read it)
PASSTHROUGH = {
    "AEGIS_CORS_ORIGINS": ("cors_origins_raw", ("control", "checkout", "inventory")),
    "AEGIS_ALLOWED_HOSTS": ("allowed_hosts_raw", ("control", "checkout", "inventory")),
    "AEGIS_AUTH_FAIL_MAX": ("auth_fail_max", ("control", "checkout", "inventory")),
    "AEGIS_AUTH_FAIL_WINDOW": ("auth_fail_window", ("control", "checkout", "inventory")),
    "AEGIS_MAX_BODY_BYTES": ("max_body_bytes", ("control", "checkout", "inventory")),
    "AEGIS_POLL_SECONDS": ("poll_seconds", ("control",)),
    "AEGIS_RESOLUTION_CYCLES": ("resolution_cycles", ("control",)),
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


def test_prometheus_does_not_expose_unauthenticated_lifecycle_endpoints():
    # --web.enable-lifecycle serves /-/quit and /-/reload to anyone who can reach the port.
    command = COMPOSE["services"]["prometheus"]["command"]

    assert not any("enable-lifecycle" in str(argument) for argument in command)
    assert not any("enable-admin-api" in str(argument) for argument in command)


def test_promtail_keeps_its_read_positions_on_a_volume():
    # In /tmp the positions vanish with the container, so every recreate re-ships all logs to Loki.
    config = yaml.safe_load((ROOT / "observability/promtail.yml").read_text())
    positions = Path(config["positions"]["filename"])
    writable_volumes = []
    for mount in COMPOSE["services"]["promtail"]["volumes"]:
        source, target, *mode = mount.split(":")
        if not source.startswith((".", "/")) and "ro" not in mode:
            writable_volumes.append((source, Path(target)))

    assert any(target in positions.parents and source in COMPOSE["volumes"] for source, target in writable_volumes)


def test_dry_run_is_passed_with_the_settings_default(monkeypatch):
    monkeypatch.delenv("AEGIS_REMEDIATION_DRY_RUN", raising=False)
    value = COMPOSE["services"]["control"]["environment"]["AEGIS_REMEDIATION_DRY_RUN"]

    assert value == "${AEGIS_REMEDIATION_DRY_RUN:-" + str(Settings().remediation_dry_run).lower() + "}"


@pytest.mark.parametrize("service", ["checkout", "inventory"])
def test_demo_services_get_enough_cpu_for_a_healthy_latency_baseline(service):
    # At 0.25 CPU a healthy checkout's p95 crossed the 750 ms alert and opened false latency incidents.
    cpus = float(COMPOSE["services"][service]["deploy"]["resources"]["limits"]["cpus"])
    assert cpus >= 1.0
