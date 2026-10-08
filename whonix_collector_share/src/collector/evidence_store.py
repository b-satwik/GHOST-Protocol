"""
Evidence Store for DarkWatch Collector (SQLite Implementation).
Persists verification attempt history, tracks content SHA-256 hashes across observations,
and records content change flags.
"""

import sqlite3
import os
from typing import Dict, Any, Optional, List


class EvidenceStore:
    """
    SQLite persistence layer for collector verification attempts.
    """

    def __init__(self, db_path: str = "data/collector_evidence.db"):
        self.db_path = db_path
        self._persistent_conn: Optional[sqlite3.Connection] = None
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        else:
            self._persistent_conn = sqlite3.connect(":memory:")
            self._persistent_conn.row_factory = sqlite3.Row
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self.db_path == ":memory:" and self._persistent_conn:
            return self._persistent_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initializes SQLite schema if table does not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS verification_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    onion_address TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    http_status INTEGER,
                    response_time_ms INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    text_length INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT,
                    previous_sha256 TEXT,
                    content_changed INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    sanitized_text TEXT
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_onion_address 
                ON verification_attempts(onion_address);
            """)
            conn.commit()

    def get_latest_attempt(self, onion_address: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the most recent verification attempt for an onion address.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM verification_attempts
                WHERE onion_address = ?
                ORDER BY id DESC LIMIT 1;
            """, (onion_address,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def save_attempt(self, attempt_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates content change relative to previous record, stores attempt in SQLite,
        and returns updated attempt dictionary.
        """
        onion_address = attempt_data["onion_address"]
        current_sha256 = attempt_data.get("sha256")

        # Query previous record for this onion address
        latest = self.get_latest_attempt(onion_address)
        previous_sha256 = latest.get("sha256") if latest else None

        # Determine content change
        content_changed = False
        if previous_sha256 and current_sha256:
            content_changed = (current_sha256 != previous_sha256)
        elif not previous_sha256 and current_sha256:
            # First observation with valid content
            content_changed = False

        attempt_data["previous_sha256"] = previous_sha256
        attempt_data["content_changed"] = content_changed

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO verification_attempts (
                    source_id, onion_address, timestamp, http_status,
                    response_time_ms, state, text_length, sha256,
                    previous_sha256, content_changed, error, sanitized_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                attempt_data["source_id"],
                attempt_data["onion_address"],
                attempt_data["timestamp"],
                attempt_data.get("http_status"),
                attempt_data.get("response_time_ms", 0),
                attempt_data["state"],
                attempt_data.get("text_length", 0),
                attempt_data.get("sha256"),
                attempt_data.get("previous_sha256"),
                1 if attempt_data["content_changed"] else 0,
                attempt_data.get("error"),
                attempt_data.get("sanitized_text")
            ))
            attempt_data["id"] = cursor.lastrowid
            conn.commit()

        return attempt_data

    def get_history(self, onion_address: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieves verification history for an onion address.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM verification_attempts
                WHERE onion_address = ?
                ORDER BY id DESC LIMIT ?;
            """, (onion_address, limit))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_all_attempts(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Retrieves all verification attempts across all sources.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM verification_attempts
                ORDER BY id ASC LIMIT ?;
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

