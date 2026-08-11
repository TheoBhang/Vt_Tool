import json
import sqlite3
import threading
from collections.abc import Mapping
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
    logic lives here - that is VirusTotalService's job alone.

    check_same_thread=False plus an internal lock make this safe to call from
    multiple threads - needed because the API/worker (sub-project B4) call this
    from a thread-pool executor, potentially concurrently across several jobs."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def get(self, value_type: str, value: str) -> tuple[dict, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT report_json, cached_at FROM cached_reports WHERE value_type = ? AND value = ?",
                (value_type, value),
            ).fetchone()
        if row is None:
            return None
        report_json, cached_at = row
        return json.loads(report_json), cached_at

    def set(self, value_type: str, value: str, report: dict) -> None:
        cached_at = datetime.now(timezone.utc).isoformat()
        report_json = json.dumps(
            report,
            default=lambda o: dict(o) if isinstance(o, Mapping) else str(o),
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO cached_reports (value_type, value, report_json, cached_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(value_type, value) DO UPDATE SET
                    report_json = excluded.report_json,
                    cached_at = excluded.cached_at
                """,
                (value_type, value, report_json, cached_at),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
