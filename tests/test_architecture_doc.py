"""ARCHITECTURE.md describes the code that exists: its tables are checked against it."""

import re
import tomllib
from importlib.metadata import version
from pathlib import Path

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from aegis import control_plane
from aegis.incidents import RULES

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "ARCHITECTURE.md").read_text()


def _section(heading: str) -> str:
    return DOC.split(heading, 1)[1].split("\n## ", 1)[0]


def _documented_endpoints() -> dict[tuple[str, str], str]:
    rows = re.findall(r"^\| `(GET|POST)` \| `([^`]+)` \|.*\| ([^|]+) \|$", _section("API Endpoints"), re.MULTILINE)
    return {(method, path): auth.strip() for method, path, auth in rows}


def _actual_endpoints() -> dict[tuple[str, str], bool]:
    """Every (method, path) the control plane serves, mapped to whether it needs the API key."""
    endpoints = {}
    for route in control_plane.app.routes:
        if isinstance(route, APIRoute):
            protected = any(d.call is control_plane.verify_api_key for d in route.dependant.dependencies)
            for method in route.methods - {"HEAD"}:
                endpoints[(method, route.path)] = protected
    return endpoints


def test_the_endpoint_table_lists_exactly_the_routes_that_exist():
    assert set(_documented_endpoints()) == set(_actual_endpoints())


def test_the_endpoint_table_marks_which_routes_need_the_api_key():
    documented = _documented_endpoints()

    for endpoint, protected in _actual_endpoints().items():
        assert documented[endpoint].startswith("Yes" if protected else "No"), endpoint


def test_the_alert_rule_table_lists_the_engine_rules():
    documented = set(re.findall(r"^\| `(\w+)` \|", _section("Alert Rules"), re.MULTILINE))

    assert documented == {rule.name for rule in RULES}


def test_the_api_version_is_the_package_version():
    openapi = TestClient(control_plane.app).get("/openapi.json").json()

    assert openapi["info"]["version"] == version("aegis")
    assert version("aegis") == tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_the_doc_does_not_claim_a_version():
    assert not re.search(r"v\d+\.\d+\.\d+", DOC)
