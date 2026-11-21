"""scripts/ports.sh: host ports chosen by start.sh persist so plain `docker compose up` agrees."""

import subprocess
from pathlib import Path

import pytest

PORTS_SH = Path(__file__).resolve().parent.parent / "scripts" / "ports.sh"
START_SH = Path(__file__).resolve().parent.parent / "scripts" / "start.sh"


def _select(tmp_path, call, busy=(), own=""):
    """Run a ports.sh call in tmp_path with fake busy ports; returns (stdout, env file text)."""
    script = f"""
set -euo pipefail
source "{PORTS_SH}"
port_in_use() {{ [[ " {" ".join(busy)} " == *" $1 "* ]]; }}
OWN="{own}"
{call}
"""
    result = subprocess.run(
        ["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True, check=True
    )
    env_file = tmp_path / ".env"
    return result.stdout.strip(), env_file.read_text() if env_file.exists() else ""


CHECKOUT = 'select_port CHECKOUT_PORT 8080 "$OWN" 8000 8081 9091 3100'


def test_a_free_default_is_used_and_nothing_is_written(tmp_path):
    port, env = _select(tmp_path, CHECKOUT)

    assert port == "8080"
    assert "CHECKOUT_PORT" not in env


def test_a_busy_default_picks_the_next_free_port_and_persists_it(tmp_path):
    port, env = _select(tmp_path, CHECKOUT, busy=["8080"])

    assert port == "8082"  # 8081 belongs to the inventory service
    assert env.count("CHECKOUT_PORT=8082") == 1


def test_a_rerun_reuses_the_persisted_port_when_it_is_free(tmp_path):
    _select(tmp_path, CHECKOUT, busy=["8080"])

    port, env = _select(tmp_path, CHECKOUT, busy=["8080"])

    assert port == "8082"
    assert env.count("CHECKOUT_PORT=") == 1


def test_the_persisted_port_held_by_our_own_stack_counts_as_free(tmp_path):
    _select(tmp_path, CHECKOUT, busy=["8080"])

    port, _ = _select(tmp_path, CHECKOUT, busy=["8080", "8082"], own="8082")

    assert port == "8082"


def test_a_taken_persisted_port_is_replaced_and_the_file_updated_in_place(tmp_path):
    _select(tmp_path, CHECKOUT, busy=["8080"])

    port, env = _select(tmp_path, CHECKOUT, busy=["8080", "8082"])

    assert port == "8083"
    assert env.count("CHECKOUT_PORT=") == 1
    assert "CHECKOUT_PORT=8083" in env


def test_going_back_to_the_default_overwrites_a_stale_persisted_port(tmp_path):
    _select(tmp_path, CHECKOUT, busy=["8080"])

    # 8082 is taken by something else and 8080 has become free again.
    port, env = _select(tmp_path, CHECKOUT, busy=["8082"])

    assert port == "8080"
    assert "CHECKOUT_PORT=8080" in env


def test_other_lines_in_the_env_file_are_preserved(tmp_path):
    (tmp_path / ".env").write_text("AEGIS_API_KEY=abc\nOTHER=1\nCHECKOUT_PORT=9999\nTAIL=2\n")

    port, env = _select(tmp_path, CHECKOUT, busy=["9999", "8080"])

    assert port == "8082"
    assert env == "AEGIS_API_KEY=abc\nOTHER=1\nCHECKOUT_PORT=8082\nTAIL=2\n"


def test_a_garbage_persisted_value_is_ignored(tmp_path):
    (tmp_path / ".env").write_text("CHECKOUT_PORT=banana\n")

    port, env = _select(tmp_path, CHECKOUT)

    assert port == "8080"
    assert "CHECKOUT_PORT=8080" in env


def test_grafana_gets_the_same_treatment(tmp_path):
    grafana = 'select_port GRAFANA_PORT 3001 "$OWN" 8000 8080 8081 9091 3100'

    port, env = _select(tmp_path, grafana, busy=["3001"])
    again, _ = _select(tmp_path, grafana, busy=["3001"])

    assert port == again == "3002"
    assert "GRAFANA_PORT=3002" in env


def test_a_scan_with_no_free_port_fails_instead_of_looping(tmp_path):
    script = f"""
source "{PORTS_SH}"
port_in_use() {{ return 0; }}
select_port CHECKOUT_PORT 65534 ""
"""
    result = subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True)

    assert result.returncode != 0


@pytest.mark.parametrize("name", ["CHECKOUT_PORT", "GRAFANA_PORT"])
def test_start_script_uses_the_shared_selection(name):
    text = START_SH.read_text()

    assert "scripts/ports.sh" in text
    assert f"select_port {name}" in text
