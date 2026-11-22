"""The fault-injection script must never be able to touch the live stack."""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "e2e_reliability.sh"


def run(**env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT)],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_the_script_is_valid_bash():
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("project", ["aegis", "societyos", "societyos-prod"])
def test_the_script_refuses_projects_that_are_not_dedicated_to_it(project):
    result = run(E2E_PROJECT=project)

    assert result.returncode == 2
    assert "refusing" in result.stderr


def test_the_makefile_target_runs_the_script():
    makefile = (SCRIPT.parents[1] / "Makefile").read_text()

    assert "e2e-reliability:\n\t./scripts/e2e_reliability.sh" in makefile
