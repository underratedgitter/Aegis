from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
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
        if row is None:
            return None
        result = dict(row)
        result["data"] = json.loads(result.pop("data_json") or "{}")
        return result

    def list_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM incidents ORDER BY CASE status WHEN 'open' THEN 0 "
                "WHEN 'investigating' THEN 1 WHEN 'recommendation_pending' THEN 2 ELSE 3 END, "
                "last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row(row) for row in rows if row is not None]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.lock:
            return self._row(
                self.db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            )

    def find_active_by_root(self, root_cause_key: str) -> dict[str, Any] | None:
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
        with self.lock:
            now = utc_now()
            existing = self.find_active_by_root(root_cause_key)
            if existing:
                evidence_history = [*existing["data"].get("evidence", []), evidence]
                merged = {
                    **existing["data"],
                    "latest_evidence": evidence,
                    "evidence": evidence_history[-100:],
                }
                self.db.execute(
                    "UPDATE incidents SET last_seen = ?, data_json = ? WHERE id = ?",
                    (now, json.dumps(merged), existing["id"]),
                )
                self.add_event(existing["id"], "signal", f"Signal still active: {title}", evidence)
                self.db.commit()
                return self.get_incident(existing["id"]) or existing, False
            data = {"latest_evidence": evidence, "evidence": [evidence]}
            self.db.execute(
                "INSERT INTO incidents(id,title,severity,status,root_cause_key,first_seen,"
                "last_seen,data_json) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (incident_id, title, severity, "open", root_cause_key, now, now, json.dumps(data)),
            )
            self.add_event(incident_id, "detected", f"Incident detected: {title}", evidence)
            self.db.commit()
            return self.get_incident(incident_id) or {}, True

    def update_incident(self, incident_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = {"title", "severity", "status", "last_seen", "resolved_at", "data_json"}
        updates = {key: value for key, value in fields.items() if key in allowed}
        if "data" in fields:
            updates["data_json"] = json.dumps(fields["data"])
        if not updates:
            return self.get_incident(incident_id)
        sql = ", ".join(f"{key} = ?" for key in updates)
        with self.lock:
            self.db.execute(
                f"UPDATE incidents SET {sql} WHERE id = ?", tuple(updates.values()) + (incident_id,)
            )
            self.db.commit()
            return self.get_incident(incident_id)

    def add_event(
        self, incident_id: str, kind: str, message: str, data: dict[str, Any] | None = None
    ) -> None:
        with self.lock:
            self.db.execute(
                "INSERT INTO events(incident_id,at,kind,message,data_json) VALUES(?,?,?,?,?)",
                (incident_id, utc_now(), kind, message, json.dumps(data or {})),
            )

    def events(self, incident_id: str) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM events WHERE incident_id = ? ORDER BY id", (incident_id,)
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["data"] = json.loads(item.pop("data_json") or "{}")
                result.append(item)
            return result

    def resolved_durations(self) -> list[float]:
        with self.lock:
            rows = self.db.execute(
                "SELECT first_seen, resolved_at FROM incidents WHERE resolved_at IS NOT NULL"
            ).fetchall()
            durations = []
            for row in rows:
                start = datetime.fromisoformat(row["first_seen"])
                end = datetime.fromisoformat(row["resolved_at"])
                durations.append(max(0.0, (end - start).total_seconds()))
            return durations
