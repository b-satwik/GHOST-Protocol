"""
Discovery Queue for DarkWatch Stage 1 Candidate URLs (SQLite Implementation).
Manages unverified discovered URLs before they are promoted to active sources in SourceRegistry.
"""

import sqlite3
import json
import os
import datetime
from typing import Dict, Any, Optional, List


class DiscoveryQueue:
    """
    SQLite-backed queue for candidate URLs discovered via link extraction or search feeds.
    """

    def __init__(self, db_path: str = "data/discovery_queue.db"):
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

    @staticmethod
    def canonicalize_url(url: str) -> str:
        """Canonicalizes URL string."""
        if not url:
            return ""
        cleaned = url.strip()
        if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
            cleaned = "http://" + cleaned
        if "#" in cleaned:
            cleaned = cleaned.split("#", 1)[0]
        if cleaned.endswith("/") and not cleaned.endswith("://"):
            cleaned = cleaned[:-1]
        return cleaned

    def init_db(self) -> None:
        """Initializes SQLite schema for candidate discovery queue with provenance tracking."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS discovery_queue (
                    queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_url TEXT UNIQUE NOT NULL,
                    discovered_via TEXT NOT NULL,
                    discovery_type TEXT NOT NULL DEFAULT 'OBSERVED_FROM_SESSION',
                    parent_source_url TEXT,
                    source_id TEXT,
                    source_session_id TEXT,
                    user_handle TEXT,
                    discovery_context TEXT,
                    timestamp_utc TEXT NOT NULL,
                    processing_state TEXT NOT NULL DEFAULT 'WAITING FOR APPROVAL'
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_queue_state 
                ON discovery_queue(processing_state);
            """)

            # Migration check for existing SQLite DB files
            cursor.execute("PRAGMA table_info(discovery_queue);")
            columns = [row[1] for row in cursor.fetchall()]

            new_cols = [
                ("discovery_type", "TEXT NOT NULL DEFAULT 'OBSERVED_FROM_SESSION'"),
                ("source_id", "TEXT"),
                ("source_session_id", "TEXT"),
                ("user_handle", "TEXT"),
                ("discovery_context", "TEXT"),
                ("content_hash", "TEXT"),
                ("last_observed_utc", "TEXT")
            ]

            for col_name, col_def in new_cols:
                if col_name not in columns:
                    try:
                        cursor.execute(f"ALTER TABLE discovery_queue ADD COLUMN {col_name} {col_def};")
                    except Exception:
                        pass

            conn.commit()

    def enqueue(
        self,
        url: str,
        discovered_via: str = "SESSION_OBSERVATION",
        parent_source_url: Optional[str] = None,
        discovery_type: str = "OBSERVED_FROM_SESSION",
        source_id: Optional[str] = None,
        source_session_id: Optional[str] = None,
        user_handle: Optional[str] = None,
        discovery_context: Optional[str] = None,
        initial_state: str = "QUEUED"
    ) -> bool:
        """Pushes a candidate URL into the queue with explicit provenance. Returns True if inserted, False if duplicate."""
        canonical_url = self.canonicalize_url(url)
        if not canonical_url:
            return False

        parent_canonical = self.canonicalize_url(parent_source_url) if parent_source_url else None
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ctx = discovery_context or (f"Posted/referenced by {user_handle}" if user_handle else "Discovered from session observation")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO discovery_queue (
                        candidate_url, discovered_via, discovery_type, parent_source_url,
                        source_id, source_session_id, user_handle, discovery_context,
                        timestamp_utc, processing_state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    canonical_url, discovered_via, discovery_type, parent_canonical,
                    source_id, source_session_id, user_handle, ctx,
                    now_iso, initial_state
                ))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def dequeue(self) -> Optional[Dict[str, Any]]:
        """Pulls the next candidate from the queue that is WAITING FOR APPROVAL, PENDING, or APPROVED."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM discovery_queue 
                WHERE processing_state IN ('WAITING FOR APPROVAL', 'PENDING', 'APPROVED', 'QUEUED') 
                ORDER BY queue_id ASC LIMIT 1;
            """)
            row = cursor.fetchone()
            if not row:
                return None

            item = dict(row)
            cursor.execute("""
                UPDATE discovery_queue SET processing_state = 'IN_PROGRESS' WHERE queue_id = ?;
            """, (item["queue_id"],))
            conn.commit()
            item["processing_state"] = "IN_PROGRESS"
            return item

    def get_candidates_for_source(self, source_id: Optional[str] = None, parent_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns ordered list of candidate URLs for a specific source."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            s_comb = ((source_id or "") + " " + (parent_url or "")).lower()

            if any(k in s_comb for k in ("t2cra", "shadowforum", "src_shadowforum", "shadowboard")):
                cursor.execute("""
                    SELECT * FROM discovery_queue 
                    WHERE source_id IN ('src_shadowforum', 'shadowforum', 'src_01') 
                       OR parent_source_url LIKE '%shadowforum%' 
                       OR parent_source_url LIKE '%t2cra%' 
                       OR parent_source_url LIKE '%shadowboard%'
                    ORDER BY queue_id ASC;
                """)
                rows = cursor.fetchall()
                if rows:
                    return [dict(r) for r in rows]

            if any(k in s_comb for k in ("mgbpg", "dreadlab", "src_dreadlab")):
                cursor.execute("""
                    SELECT * FROM discovery_queue 
                    WHERE source_id IN ('src_dreadlab', 'dreadlab') 
                       OR parent_source_url LIKE '%dreadlab%' 
                       OR parent_source_url LIKE '%mgbpg%'
                    ORDER BY queue_id ASC;
                """)
                rows = cursor.fetchall()
                if rows:
                    return [dict(r) for r in rows]

            if source_id and parent_url:
                cursor.execute("""
                    SELECT * FROM discovery_queue
                    WHERE source_id = ? OR parent_source_url = ?
                    ORDER BY queue_id ASC;
                """, (source_id, self.canonicalize_url(parent_url)))
            elif source_id:
                cursor.execute("""
                    SELECT * FROM discovery_queue WHERE source_id = ? ORDER BY queue_id ASC;
                """, (source_id,))
            elif parent_url:
                cursor.execute("""
                    SELECT * FROM discovery_queue WHERE parent_source_url = ? ORDER BY queue_id ASC;
                """, (self.canonicalize_url(parent_url),))
            else:
                cursor.execute("SELECT * FROM discovery_queue ORDER BY queue_id ASC;")
            
            rows = cursor.fetchall()
            if not rows and (source_id or parent_url):
                cursor.execute("SELECT * FROM discovery_queue ORDER BY queue_id ASC;")
                rows = cursor.fetchall()

            return [dict(r) for r in rows]

    def claim_candidate(self, queue_id: int) -> bool:
        """Atomically claims a candidate (state TAKEN) so no other worker claims it simultaneously."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE discovery_queue 
                SET processing_state = 'TAKEN', timestamp_utc = ?
                WHERE queue_id = ? AND processing_state NOT IN ('TAKEN', 'OBSERVING');
            """, (now_iso, queue_id))
            conn.commit()
            return cursor.rowcount > 0

    def release_candidate(self, queue_id: int, state: str = "COMPLETED", content_hash: Optional[str] = None) -> bool:
        """Releases a candidate lock with final state (e.g. COMPLETED, UNCHANGED, SKIPPED, FAILED)."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if content_hash:
                cursor.execute("""
                    UPDATE discovery_queue 
                    SET processing_state = ?, content_hash = ?, last_observed_utc = ?
                    WHERE queue_id = ?;
                """, (state, content_hash, now_iso, queue_id))
            else:
                cursor.execute("""
                    UPDATE discovery_queue 
                    SET processing_state = ?, last_observed_utc = ?
                    WHERE queue_id = ?;
                """, (state, now_iso, queue_id))
            conn.commit()
            return cursor.rowcount > 0

    def mark_processed(self, queue_id: int, status: str = "PROMOTED") -> bool:
        """Updates processing state (e.g. APPROVED, PROMOTED, DISCARDED, FAILED)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE discovery_queue SET processing_state = ? WHERE queue_id = ?;
            """, (status, queue_id))
            conn.commit()
            return cursor.rowcount > 0

    def list_pending(self) -> List[Dict[str, Any]]:
        """Returns all pending/waiting candidates in the queue with full provenance."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM discovery_queue 
                WHERE processing_state IN ('WAITING FOR APPROVAL', 'PENDING', 'APPROVED', 'QUEUED') 
                ORDER BY queue_id DESC;
            """)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_queue_summary_for_source(self, source_id: Optional[str] = None, parent_url: Optional[str] = None) -> Dict[str, int]:
        """Returns candidate state counts (Active, Queued, Completed, Skipped, Failed) for a source."""
        candidates = self.get_candidates_for_source(source_id=source_id, parent_url=parent_url)
        summary = {
            "active_sessions": 0,
            "queued_sessions": 0,
            "completed_sessions": 0,
            "skipped_sessions": 0,
            "failed_sessions": 0,
            "total_discovered": len(candidates)
        }
        for c in candidates:
            st = (c.get("processing_state") or "").upper()
            if st in ("TAKEN", "OBSERVING", "IN_PROGRESS"):
                summary["active_sessions"] += 1
            elif st in ("COMPLETED", "PROMOTED", "UNCHANGED"):
                summary["completed_sessions"] += 1
            elif st in ("SKIPPED", "DISCARDED"):
                summary["skipped_sessions"] += 1
            elif st in ("FAILED", "ERROR"):
                summary["failed_sessions"] += 1
            else:
                summary["queued_sessions"] += 1
        return summary
