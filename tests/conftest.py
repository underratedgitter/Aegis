"""
Shared test configuration.

The control plane builds its Store at import time from AEGIS_DB_PATH. Without
this, the suite wrote into the real ./data/aegis.db, so a run's outcome depended
on rows left behind by earlier runs (a resolved incident would turn the fixture's
insert into a UNIQUE violation). Pointing the tests at a throwaway database keeps
them reproducible and leaves the demo's own data untouched.

This must run before any test module imports aegis.control_plane; pytest imports
conftest.py first, so setting the environment here is early enough.
"""

import os
import tempfile
from pathlib import Path

import pytest

_TMP_DIR = tempfile.mkdtemp(prefix="aegis-tests-")

os.environ["AEGIS_DB_PATH"] = str(Path(_TMP_DIR) / "aegis.db")
os.environ.setdefault("AEGIS_LOG_DIR", str(Path(_TMP_DIR) / "logs"))
# Remediation retries must not make failure-path tests sleep.
os.environ.setdefault("AEGIS_REMEDIATION_BACKOFF_MS", "0")

# The suite must never authenticate by accident against a developer's real key.
os.environ.pop("AEGIS_API_KEY", None)


@pytest.fixture(autouse=True)
def _close_stores(monkeypatch):
    """Close every Store a test opens, so no SQLite connection outlives its test.

    The control plane's own module-level store is built at import, before this runs,
    and is left alone.
    """
    from aegis.storage import Store

    opened: list[Store] = []
    original = Store.__init__

    def tracking(self, *args, **kwargs):
        original(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(Store, "__init__", tracking)
    yield
    for store in opened:
        store.close()  # closing twice is harmless
