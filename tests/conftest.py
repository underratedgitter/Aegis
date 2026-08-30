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

_TMP_DIR = tempfile.mkdtemp(prefix="aegis-tests-")

os.environ["AEGIS_DB_PATH"] = str(Path(_TMP_DIR) / "aegis.db")
os.environ.setdefault("AEGIS_LOG_DIR", str(Path(_TMP_DIR) / "logs"))

# The suite must never authenticate by accident against a developer's real key.
os.environ.pop("AEGIS_API_KEY", None)
