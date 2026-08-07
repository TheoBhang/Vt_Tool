import json
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS cached_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value_type TEXT NOT NULL,
    value TEXT NOT NULL,
    report_json TEXT NOT NULL,
    cached_at TEXT NOT NULL,
    UNIQUE(value_type, value)
);
"""


class SQLiteCacheBackend:
    """SQLite implementation of the report-cache backend: stores an already-shaped
    report dict as a JSON blob, keyed by (value_type, value). No report-shaping
    logic lives here - that is VirusTotalService's job alone."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def get(self, value_type: str, value: str) -> dict | None:
        row = self._conn.execute(
            "SELECT report_json FROM cached_reports WHERE value_type = ? AND value = ?",
            (value_type, value),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def set(self, value_type: str, value: str, report: dict) -> None:
        cached_at = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            INSERT INTO cached_reports (value_type, value, report_json, cached_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(value_type, value) DO UPDATE SET
                report_json = excluded.report_json,
                cached_at = excluded.cached_at
            """,
            (value_type, value, json.dumps(report), cached_at),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
