"""docker-compose.yml passes the hardening settings through with the same defaults as Settings."""

import dataclasses
import re
from pathlib import Path

import pytest
import yaml

from aegis.settings import Settings

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

# Settings the control plane does not take from the environment of the host: Compose pins them to
# the service names and container paths of its own network.
NOT_PASSED_THROUGH = frozenset(
    {
        "PROMETHEUS_URL",
        "LOKI_URL",
        "CHECKOUT_URL",
        "INVENTORY_URL",
        "PORT",
        "AEGIS_DB_PATH",
        "AEGIS_LOG_DIR",
        "AEGIS_RUNBOOK_DIR",
    }
)
# The Aegis settings the demo services read as well (the aegis-security-env anchor).
ALL_AEGIS_SERVICES = ("control", "checkout", "inventory")
SHARED = frozenset(
    {
        "AEGIS_CORS_ORIGINS",
        "AEGIS_ALLOWED_HOSTS",
        "AEGIS_AUTH_FAIL_MAX",
        "AEGIS_AUTH_FAIL_WINDOW",
        "AEGIS_MAX_BODY_BYTES",
    }
)

# Derived from Settings, so a new setting without a Compose passthrough fails here.
ENVIRONMENT = {field.metadata["env"]: field.name for field in dataclasses.fields(Settings) if "env" in field.metadata}
PASSTHROUGH = {
    name: (attribute, ALL_AEGIS_SERVICES if name in SHARED else ("control",))
    for name, attribute in ENVIRONMENT.items()
    if name not in NOT_PASSED_THROUGH
}


def test_every_setting_names_its_environment_variable():
    assert [field.name for field in dataclasses.fields(Settings) if "env" not in field.metadata] == []


def test_the_exclusion_and_shared_lists_name_real_settings():
    assert set(ENVIRONMENT) >= (NOT_PASSED_THROUGH | SHARED)


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
    default = getattr(Settings(), attribute)
    assert match.group(1) == (str(default).lower() if isinstance(default, bool) else str(default))


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
