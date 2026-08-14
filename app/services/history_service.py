import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    case_label TEXT,
    created_at TEXT NOT NULL,
    items_json TEXT NOT NULL,
    misp_event_id TEXT
);
"""


class HistoryService:
    """Stores and retrieves finished analysis batches for the history
    feature. Deliberately independent of the report cache's pluggable SQL
    backend (VT_CACHE_DB_URL/SQLAlchemyCacheBackend) - always a raw sqlite3
    connection to its own local file, the same simplicity tradeoff the
    cache itself made before SQLAlchemy support was added later as its own
    separate concern.

    check_same_thread=False plus an internal lock, same pattern as
    SQLiteCacheBackend - needed because the API calls this from concurrent
    request handlers."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def save(self, items: list[dict], case_label: str | None = None) -> dict:
        analysis_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO analyses (id, case_label, created_at, items_json, misp_event_id) "
                "VALUES (?, ?, ?, ?, NULL)",
                (analysis_id, case_label, created_at, json.dumps(items)),
            )
            self._conn.commit()
        return {"id": analysis_id, "created_at": created_at, "case_label": case_label}

    def list(self, limit: int, offset: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, case_label, created_at, items_json, misp_event_id "
                "FROM analyses ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [
            {
                "id": row[0],
                "case_label": row[1],
                "created_at": row[2],
                "item_count": len(json.loads(row[3])),
                "misp_event_id": row[4],
            }
            for row in rows
        ]

    def get(self, analysis_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, case_label, created_at, items_json, misp_event_id "
                "FROM analyses WHERE id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "case_label": row[1],
            "created_at": row[2],
            "items": json.loads(row[3]),
            "misp_event_id": row[4],
        }

    def set_misp_event_id(self, analysis_id: str, event_id: str, case_label: str | None) -> None:
        with self._lock:
            if case_label:
                self._conn.execute(
                    "UPDATE analyses SET misp_event_id = ?, case_label = ? WHERE id = ?",
                    (event_id, case_label, analysis_id),
                )
            else:
                self._conn.execute(
                    "UPDATE analyses SET misp_event_id = ? WHERE id = ?",
                    (event_id, analysis_id),
                )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()
