"""The Makefile and the CI workflow are part of the contract: tested like code."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = (ROOT / "Makefile").read_text()
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/tests.yml").read_text())


def _targets() -> set[str]:
    return set(re.findall(r"^([a-z][a-z0-9-]*):", MAKEFILE, flags=re.MULTILINE))


def test_every_target_is_phony():
    phony = set(re.search(r"^\.PHONY:(.*)$", MAKEFILE, flags=re.MULTILINE).group(1).split())

    assert _targets() <= phony


def test_every_target_is_listed_in_help():
    help_text = MAKEFILE.split("help:")[1].split("\nstart:")[0]

    assert {target for target in _targets() if f"make {target} " not in help_text} == {"help"}


def test_clean_removes_the_real_mypy_cache_directory():
    clean = MAKEFILE.split("\nclean:")[1]

    assert re.search(r"(^|\s)\.mypy_cache(\s|$)", clean)
    assert not re.search(r"(^|\s)mypy_cache(\s|$)", clean)


def test_ci_runs_on_every_push_not_just_main():
    triggers = WORKFLOW.get("on", WORKFLOW.get(True))

    assert "push" in triggers
    assert "branches" not in (triggers["push"] or {})
    assert "pull_request" in triggers


def test_ci_validates_the_compose_file_and_builds_the_image():
    commands = " ".join(
        step.get("run", "") for job in WORKFLOW["jobs"].values() for step in job["steps"]
    )

    assert "docker compose config -q" in commands
    assert "docker build" in commands
