"""The backup command: python -m aegis.backup_main [DEST]."""

import sqlite3

import pytest

from aegis.backup_main import main
from aegis.storage import Store


@pytest.fixture
def database(tmp_path, monkeypatch):
    """A live database with one incident, wired up as AEGIS_DB_PATH."""
    path = tmp_path / "data" / "aegis.db"
    store = Store(str(path))
    store.upsert_incident("inc-1", "Checkout errors", "high", "service:checkout", {"value": 1})
    monkeypatch.setenv("AEGIS_DB_PATH", str(path))
    yield path
    store.close()


def incident_ids(path):
    db = sqlite3.connect(path)
    try:
        return [row[0] for row in db.execute("SELECT id FROM incidents")]
    finally:
        db.close()


def test_writes_an_integrity_checked_copy_to_the_given_destination(database, tmp_path, capsys):
    dest = tmp_path / "out" / "copy.db"

    assert main([str(dest)]) == 0

    assert capsys.readouterr().out.strip() == str(dest)
    assert incident_ids(dest) == ["inc-1"]


def test_defaults_to_a_timestamped_file_in_backups_next_to_the_database(database, capsys):
    assert main([]) == 0

    written = capsys.readouterr().out.strip()
    assert written.startswith(str(database.parent / "backups" / "aegis-"))
    assert written.endswith("Z.db")
    assert incident_ids(written) == ["inc-1"]


def test_a_missing_database_is_reported_and_exits_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_DB_PATH", str(tmp_path / "nowhere.db"))

    assert main([str(tmp_path / "copy.db")]) == 1

    captured = capsys.readouterr()
    assert "backup failed: database not found" in captured.err
    assert captured.out == ""
    assert not (tmp_path / "copy.db").exists()


def test_an_existing_destination_is_never_overwritten(database, tmp_path, capsys):
    dest = tmp_path / "existing.db"
    dest.write_text("precious")

    assert main([str(dest)]) == 1

    assert "refusing to overwrite" in capsys.readouterr().err
    assert dest.read_text() == "precious"


def test_a_source_that_is_not_a_database_fails_cleanly_and_leaves_no_partial_copy(
    tmp_path, monkeypatch, capsys
):
    broken = tmp_path / "broken.db"
    broken.write_text("this is not sqlite")
    monkeypatch.setenv("AEGIS_DB_PATH", str(broken))
    dest = tmp_path / "copy.db"

    assert main([str(dest)]) == 1

    assert "backup failed" in capsys.readouterr().err
    assert not dest.exists()


def test_extra_arguments_print_usage_and_exit_2(capsys):
    assert main(["one", "two"]) == 2

    captured = capsys.readouterr()
    assert "usage: python -m aegis.backup_main [DEST]" in captured.err
    assert captured.out == ""
