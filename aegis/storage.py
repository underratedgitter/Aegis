"""SQLite storage with proper type hints and connection management."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Collection

BUSY_TIMEOUT_MS = 10_000
# Recent detected/signal events inspected when deciding whether another one is due.
SIGNAL_LOOKBACK = 200


def utc_now() -> str:
    """Return current UTC time as ISO format string."""
    return datetime.now(UTC).isoformat()


class Store:
    """Thread-safe SQLite storage for incidents and events."""

    def __init__(
        self, path: str, max_evidence: int = 100, signal_event_interval: float = 60.0
    ):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.max_evidence = max(1, max_evidence)  # [-0:] would keep everything
        self.signal_event_interval = max(0.0, signal_event_interval)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(
            path, check_same_thread=False, timeout=BUSY_TIMEOUT_MS / 1000
        )
        self.db.row_factory = sqlite3.Row
        self._configure()
        self._initialize_schema()

    def _configure(self) -> None:
        """Enable WAL so readers do not block the writer, and wait out brief lock contention.

        WAL with synchronous=NORMAL cannot corrupt the database on a crash; at worst the
        last transactions before a power loss are rolled back.
        """
        self.db.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.execute("PRAGMA synchronous = NORMAL")

    def ping(self) -> None:
        """Raise sqlite3.Error if the database cannot be queried."""
        with self.lock:
            self.db.execute("SELECT 1").fetchone()

    def _initialize_schema(self) -> None:
        """Create database tables if they don't exist."""
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
              id TEXT PRIMARY KEY,
              title TEXT NOT NULL,
              severity TEXT NOT NULL,
              status TEXT NOT NULL,
              root_cause_key TEXT NOT NULL,
              first_seen TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              resolved_at TEXT,
              data_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              incident_id TEXT NOT NULL,
              at TEXT NOT NULL,
              kind TEXT NOT NULL,
              message TEXT NOT NULL,
              data_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS events_incident_idx ON events(incident_id, id);
            """
        )
        self.db.commit()

    def _row(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        """Convert a database row to a dictionary."""
        if row is None:
            return None
        result = dict(row)
        result["data"] = json.loads(result.pop("data_json") or "{}")
        return result

    def _rows(self, rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        """Convert multiple database rows to dictionaries."""
        converted = (self._row(row) for row in rows)
        return [row for row in converted if row is not None]

    def list_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        """List incidents ordered by status priority and recency."""
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM incidents ORDER BY CASE status WHEN 'open' THEN 0 "
                "WHEN 'investigating' THEN 1 WHEN 'recommendation_pending' THEN 2 "
                "WHEN 'approved' THEN 3 WHEN 'executing' THEN 3 ELSE 4 END, last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return self._rows(rows)

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Get a single incident by ID."""
        with self.lock:
            return self._row(
                self.db.execute(
                    "SELECT * FROM incidents WHERE id = ?", (incident_id,)
                ).fetchone()
            )

    def find_active_by_root(self, root_cause_key: str) -> dict[str, Any] | None:
        """Find the most recent active incident with a given root cause key."""
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM incidents WHERE root_cause_key = ? "
                "AND status NOT IN ('resolved', 'closed') "
                "ORDER BY last_seen DESC LIMIT 1",
                (root_cause_key,),
            ).fetchone()
            return self._row(row)

    def upsert_incident(
        self,
        incident_id: str,
        title: str,
        severity: str,
        root_cause_key: str,
        evidence: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        """
        Insert a new incident or update an existing active one.

        Returns:
            Tuple of (incident_dict, created_flag)
        """
        with self.lock:
            now = utc_now()
            existing = self.find_active_by_root(root_cause_key)
            if existing:
                evidence_history = [*existing["data"].get("evidence", []), evidence]
                merged = {
                    **existing["data"],
                    "latest_evidence": evidence,
                    "evidence": evidence_history[-self.max_evidence :],
                }
                self.db.execute(
                    "UPDATE incidents SET last_seen = ?, data_json = ? WHERE id = ?",
                    (now, json.dumps(merged), existing["id"]),
                )
                if self._signal_event_due(existing["id"], evidence, now):
                    self.add_event(
                        existing["id"], "signal", f"Signal still active: {title}", evidence,
                        commit=False,
                    )
                self.db.commit()
                return self.get_incident(existing["id"]) or existing, False

            data = {"latest_evidence": evidence, "evidence": [evidence]}
            self.db.execute(
                "INSERT INTO incidents(id,title,severity,status,root_cause_key,"
                "first_seen,last_seen,data_json) VALUES(?,?,?,?,?,?,?,?)",
                (incident_id, title, severity, "open", root_cause_key, now, now, json.dumps(data)),
            )
            self.add_event(
                incident_id, "detected", f"Incident detected: {title}", evidence, commit=False
            )
            self.db.commit()
            return self.get_incident(incident_id) or {}, True

    def _signal_event_due(self, incident_id: str, evidence: dict[str, Any], now: str) -> bool:
        """Whether a still-active signal deserves a timeline event.

        Evidence is appended on every poll, but the timeline only gets an event when
        this rule has not been recorded for the incident yet (a state change) or its
        last event is at least `signal_event_interval` seconds old. The check reads
        the stored events, so it holds across restarts.
        """
        rule = evidence.get("rule")
        rows = self.db.execute(
            "SELECT at, data_json FROM events WHERE incident_id = ? "
            "AND kind IN ('detected', 'signal') ORDER BY id DESC LIMIT ?",
            (incident_id, SIGNAL_LOOKBACK),
        ).fetchall()
        for row in rows:
            if json.loads(row["data_json"] or "{}").get("rule") != rule:
                continue
            elapsed = datetime.fromisoformat(now) - datetime.fromisoformat(row["at"])
            return elapsed.total_seconds() >= self.signal_event_interval
        return True

    def update_incident(self, incident_id: str, **fields: Any) -> dict[str, Any] | None:
        """Update incident fields."""
        allowed = {"title", "severity", "status", "last_seen", "resolved_at", "data_json"}
        updates = {key: value for key, value in fields.items() if key in allowed}
        if "data" in fields:
            updates["data_json"] = json.dumps(fields["data"])
        if not updates:
            return self.get_incident(incident_id)
        sql = ", ".join(f"{key} = ?" for key in updates)
        with self.lock:
            self.db.execute(
                f"UPDATE incidents SET {sql} WHERE id = ?",
                (*updates.values(), incident_id),
            )
            self.db.commit()
            return self.get_incident(incident_id)

    def merge_incident(
        self,
        incident_id: str,
        data: dict[str, Any] | None = None,
        *,
        status: str | None = None,
        resolved_at: str | None = None,
        only_if_status: Collection[str] | None = None,
    ) -> dict[str, Any] | None:
        """Atomically merge top-level keys into an incident's data and optionally set its status.

        The read-modify-write runs under the store lock, so it cannot overwrite
        evidence appended by ``upsert_incident`` between a caller's read and write.
        Prefer this over ``update_incident(data=...)`` with a previously read snapshot.

        Args:
            data: Top-level keys to set; keys not named here are left untouched.
            status: New status, if it should change.
            resolved_at: New resolution timestamp, if it should change.
            only_if_status: Apply the change only when the incident currently has
                one of these statuses.

        Returns:
            The updated incident, or None if it is missing or its status is not allowed.
        """
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            current = self._row(row)
            if current is None:
                return None
            if only_if_status is not None and current["status"] not in only_if_status:
                return None
            merged = {**current["data"], **(data or {})}
            updates: dict[str, Any] = {"data_json": json.dumps(merged)}
            if status is not None:
                updates["status"] = status
            if resolved_at is not None:
                updates["resolved_at"] = resolved_at
            sql = ", ".join(f"{key} = ?" for key in updates)
            self.db.execute(
                f"UPDATE incidents SET {sql} WHERE id = ?",
                (*updates.values(), incident_id),
            )
            self.db.commit()
            return self.get_incident(incident_id)

    def transition_status(self, incident_id: str, expected: str, new: str) -> bool:
        """Atomically move an incident from the expected status to a new one.

        Returns:
            True if this call made the transition, False if the incident was
            missing or no longer in the expected status.
        """
        with self.lock:
            cursor = self.db.execute(
                "UPDATE incidents SET status = ? WHERE id = ? AND status = ?",
                (new, incident_id, expected),
            )
            self.db.commit()
            return cursor.rowcount == 1

    def recover_interrupted_executions(self) -> list[str]:
        """Return incidents left in "executing" by a crash to "approved" so they can be retried.

        Only call this at startup, before anything can start a new execution.

        Returns:
            IDs of the incidents that were recovered.
        """
        with self.lock:
            rows = self.db.execute("SELECT id FROM incidents WHERE status = 'executing'").fetchall()
            recovered = [row["id"] for row in rows]
            for incident_id in recovered:
                self.db.execute(
                    "UPDATE incidents SET status = 'approved' WHERE id = ?", (incident_id,)
                )
                self.add_event(
                    incident_id,
                    "recovery",
                    "Remediation was interrupted by a control-plane restart; the action may or "
                    "may not have been applied. Check the target, then retry Execute if needed.",
                    commit=False,
                )
            self.db.commit()
            return recovered

    def add_event(
        self,
        incident_id: str,
        kind: str,
        message: str,
        data: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> None:
        """
        Add an event to an incident's timeline.

        Args:
            commit: Persist immediately. Pass False only when the caller already
                holds an open transaction that it commits itself.
        """
        with self.lock:
            self.db.execute(
                "INSERT INTO events(incident_id,at,kind,message,data_json) VALUES(?,?,?,?,?)",
                (incident_id, utc_now(), kind, message, json.dumps(data or {})),
            )
            if commit:
                self.db.commit()

    def events(self, incident_id: str) -> list[dict[str, Any]]:
        """Get all events for an incident, ordered by time."""
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM events WHERE incident_id = ? ORDER BY id",
                (incident_id,),
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["data"] = json.loads(item.pop("data_json") or "{}")
                result.append(item)
            return result

    def incident_status_counts(self) -> dict[str, int]:
        """Number of incidents in each status."""
        with self.lock:
            rows = self.db.execute(
                "SELECT status, COUNT(*) AS n FROM incidents GROUP BY status"
            ).fetchall()
        return {row["status"]: row["n"] for row in rows}

    def event_counts(self, kinds: Collection[str]) -> dict[str, int]:
        """Number of timeline events of each of the given kinds, across all incidents."""
        marks = ",".join("?" * len(kinds))
        with self.lock:
            rows = self.db.execute(
                f"SELECT kind, COUNT(*) AS n FROM events WHERE kind IN ({marks}) GROUP BY kind",
                tuple(kinds),
            ).fetchall()
        return {row["kind"]: row["n"] for row in rows}

    def resolved_durations(self) -> list[float]:
        """Get durations (in seconds) for all resolved incidents."""
        with self.lock:
            rows = self.db.execute(
                "SELECT first_seen, resolved_at FROM incidents "
                "WHERE resolved_at IS NOT NULL"
            ).fetchall()
            durations = []
            for row in rows:
                start = datetime.fromisoformat(row["first_seen"])
                end = datetime.fromisoformat(row["resolved_at"])
                durations.append(max(0.0, (end - start).total_seconds()))
            return durations

    def close(self) -> None:
        """Close the database connection, checkpointing the WAL into the main file."""
        with self.lock:
            self.db.close()


def backup_database(source: str, dest: str) -> str:
    """Write a consistent copy of a live database using SQLite's online backup API.

    Unlike copying the file, this is safe while the control plane is writing and
    includes uncheckpointed WAL content. The copy is integrity-checked before returning.

    Raises:
        FileNotFoundError: the source database does not exist.
        FileExistsError: the destination already exists (it is never overwritten).
        sqlite3.Error: the copy failed or did not pass the integrity check.
    """
    if not Path(source).is_file():
        raise FileNotFoundError(f"database not found: {source}")
    if Path(dest).exists():
        raise FileExistsError(f"refusing to overwrite existing file: {dest}")
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(source, timeout=BUSY_TIMEOUT_MS / 1000)
    try:
        copy = sqlite3.connect(dest)
        try:
            src.backup(copy)
            result = copy.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise sqlite3.DatabaseError(f"backup failed integrity check: {result}")
        except sqlite3.Error:
            copy.close()
            Path(dest).unlink(missing_ok=True)
            raise
        finally:
            copy.close()
    finally:
        src.close()
    return dest
