"""
Source Registry for DarkWatch Stage 1 Discovery Layer (SQLite Implementation).
Manages target sources, validation status, scheduling, collector types, content hash state, and provenance.
"""

import sqlite3
import json
import os
import datetime
from typing import Dict, Any, Optional, List


class SourceRegistry:
    """
    SQLite-backed source registry enforcing URL canonicalization, schedule tracking, and provenance.
    """

    def __init__(self, db_path: str = "data/source_registry.db"):
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
        """Canonicalizes URL by normalizing scheme, removing fragment, and stripping trailing slash."""
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
        """Initializes SQLite schema for sources_registry with extended live operation fields."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sources_registry (
                    source_id TEXT PRIMARY KEY,
                    canonical_url TEXT UNIQUE NOT NULL,
                    source_type TEXT NOT NULL,
                    collector_type TEXT NOT NULL DEFAULT 'HTTP_CLEARNET',
                    validation_status TEXT NOT NULL DEFAULT 'ACTIVE',
                    polling_interval_mins INTEGER NOT NULL DEFAULT 30,
                    discovery_timestamp_utc TEXT NOT NULL,
                    discovered_via TEXT NOT NULL,
                    last_checked_utc TEXT,
                    last_successful_utc TEXT,
                    last_change_utc TEXT,
                    next_scheduled_utc TEXT,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    raw_html_sha256 TEXT,
                    clean_text_sha256 TEXT,
                    minhash_signature TEXT,
                    metadata_json TEXT
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_source_url 
                ON sources_registry(canonical_url);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_source_status 
                ON sources_registry(validation_status);
            """)
            
            # Migration check for existing SQLite DB files
            cursor.execute("PRAGMA table_info(sources_registry);")
            columns = [row[1] for row in cursor.fetchall()]

            new_cols = [
                ("collector_type", "TEXT NOT NULL DEFAULT 'HTTP_CLEARNET'"),
                ("polling_interval_mins", "INTEGER NOT NULL DEFAULT 30"),
                ("last_successful_utc", "TEXT"),
                ("last_change_utc", "TEXT"),
                ("next_scheduled_utc", "TEXT"),
                ("failure_count", "INTEGER NOT NULL DEFAULT 0"),
                ("first_seen", "TEXT"),
                ("last_seen", "TEXT"),
                ("access_requirement", "TEXT DEFAULT 'PUBLIC'"),
                ("parent_source", "TEXT"),
                ("observation_count", "INTEGER DEFAULT 0"),
                ("change_count", "INTEGER DEFAULT 0"),
                ("previous_content_hash", "TEXT"),
                ("agent_state", "TEXT DEFAULT 'WAITING'"),
                ("connection_state", "TEXT DEFAULT 'INACTIVE'"),
                ("access_method", "TEXT DEFAULT 'HTTP_DIRECT'"),
                ("human_action_state", "TEXT DEFAULT 'NOT REQUIRED'"),
                ("last_health_check_utc", "TEXT"),
                ("failure_reason", "TEXT"),
                ("candidate_cursor", "INTEGER DEFAULT 0")
            ]

            for col_name, col_def in new_cols:
                if col_name not in columns:
                    try:
                        cursor.execute(f"ALTER TABLE sources_registry ADD COLUMN {col_name} {col_def};")
                    except Exception:
                        pass

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    source_id TEXT,
                    timestamp_utc TEXT NOT NULL,
                    message TEXT,
                    metadata_json TEXT
                );
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_source_next_sched 
                ON sources_registry(next_scheduled_utc);
            """)
            conn.commit()
        self.clean_duplicate_sources()
        self.purge_stale_synthetic_sources()

    def purge_stale_synthetic_sources(self) -> int:
        """
        Deletes stale synthetic 127.0.0.1 test sources (e.g. idempotent_test, synthetic_test_feed)
        from sources_registry so they are not continuously polled.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM sources_registry
                WHERE canonical_url LIKE '%idempotent_test%'
                   OR canonical_url LIKE '%synthetic_test_feed%';
            """)
            conn.commit()
            return cursor.rowcount

    def clean_duplicate_sources(self) -> int:
        """
        Safely cleans up duplicate source records by canonical_url.
        Preserves the earliest registered canonical source row
        and deletes duplicate rows from sources_registry.
        Does NOT touch observation history, alerts, or CTI evidence.
        Returns the number of deleted duplicate rows.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM sources_registry
                WHERE rowid NOT IN (
                    SELECT MIN(rowid)
                    FROM sources_registry
                    GROUP BY canonical_url
                );
            """)
            conn.commit()
            return cursor.rowcount

    def add_source(
        self,
        source_id: str,
        url: str,
        source_type: str,
        collector_type: str = "HTTP_CLEARNET",
        polling_interval_mins: int = 30,
        discovered_via: str = "MANUAL",
        metadata: Optional[Dict[str, Any]] = None,
        initial_status: str = "WAITING_FOR_APPROVAL"
    ) -> bool:
        """Adds a new source to the registry with scheduling metadata (defaults to WAITING_FOR_APPROVAL)."""
        canonical_url = self.canonicalize_url(url)
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()
        meta_json = json.dumps(metadata or {})

        agent_st = "WAITING" if initial_status == "WAITING_FOR_APPROVAL" else "RUNNING"
        conn_st = "INACTIVE" if initial_status == "WAITING_FOR_APPROVAL" else "CONNECTING"
        access_mth = "SOCKS5_TOR" if ".onion" in canonical_url else ("TELEGRAM_PUBLIC_CHANNEL" if "t.me" in canonical_url else "HTTP_DIRECT")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO sources_registry (
                        source_id, canonical_url, source_type, collector_type, validation_status,
                        polling_interval_mins, discovery_timestamp_utc, discovered_via,
                        next_scheduled_utc, metadata_json, agent_state, connection_state, access_method
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    source_id,
                    canonical_url,
                    source_type,
                    collector_type,
                    initial_status,
                    polling_interval_mins,
                    now_iso,
                    discovered_via,
                    now_iso,
                    meta_json,
                    agent_st,
                    conn_st,
                    access_mth
                ))
                conn.commit()
                self.record_event("SOURCE_ADDED", source_id=source_id, message=f"New source registered: {canonical_url} (Status: {initial_status})")
                return True
            except sqlite3.IntegrityError:
                return False

    def approve_source(self, source_id: str) -> bool:
        """Approves a pending source, transitioning it to APPROVED / CONNECTING for live agent observation."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sources_registry 
                SET validation_status = 'APPROVED',
                    agent_state = 'RUNNING',
                    connection_state = 'CONNECTING',
                    next_scheduled_utc = ?
                WHERE source_id = ?;
            """, (now_iso, source_id))
            conn.commit()
            success = cursor.rowcount > 0

        if success:
            self.record_event("SOURCE_APPROVED", source_id=source_id, message=f"Analyst approved source {source_id}. Observation job dispatched.")
        return success

    def mark_human_verified(self, source_id: str) -> bool:
        """Marks a source as HUMAN VERIFIED / CONNECTED after analyst completes human verification action."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sources_registry 
                SET validation_status = 'LIVE',
                    agent_state = 'RUNNING',
                    connection_state = 'ACTIVE',
                    human_action_state = 'HUMAN VERIFIED',
                    failure_reason = NULL,
                    last_successful_utc = ?,
                    last_health_check_utc = ?
                WHERE source_id = ?;
            """, (now_iso, now_iso, source_id))
            conn.commit()
            success = cursor.rowcount > 0

        if success:
            self.record_event("HUMAN_VERIFIED", source_id=source_id, message=f"Analyst confirmed human verification for {source_id}. Verification: HUMAN VERIFIED / CONNECTED.")
            self.record_event("SOURCE_LIVE", source_id=source_id, message=f"Source {source_id} is now LIVE and observing data.")
        return success

    def get_candidate_cursor(self, source_id: str) -> int:
        """Retrieves persistent candidate rotation cursor index for a source."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT candidate_cursor FROM sources_registry WHERE source_id = ?;", (source_id,))
            row = cursor.fetchone()
            return row["candidate_cursor"] if (row and row["candidate_cursor"] is not None) else 0

    def set_candidate_cursor(self, source_id: str, cursor_idx: int) -> bool:
        """Sets persistent candidate rotation cursor index for a source."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE sources_registry SET candidate_cursor = ? WHERE source_id = ?;", (cursor_idx, source_id))
            conn.commit()
            return cursor.rowcount > 0

    def update_source_lifecycle(
        self,
        source_id: str,
        validation_status: Optional[str] = None,
        agent_state: Optional[str] = None,
        connection_state: Optional[str] = None,
        access_method: Optional[str] = None,
        human_action_state: Optional[str] = None,
        failure_reason: Optional[str] = None,
        update_health_check: bool = True
    ) -> bool:
        """Updates granular live lifecycle fields for a source."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        fields = []
        params = []

        if validation_status:
            fields.append("validation_status = ?")
            params.append(validation_status)
        if agent_state:
            fields.append("agent_state = ?")
            params.append(agent_state)
        if connection_state:
            fields.append("connection_state = ?")
            params.append(connection_state)
        if access_method:
            fields.append("access_method = ?")
            params.append(access_method)
        if human_action_state:
            fields.append("human_action_state = ?")
            params.append(human_action_state)
        if failure_reason is not None:
            fields.append("failure_reason = ?")
            params.append(failure_reason)
        if update_health_check:
            fields.append("last_health_check_utc = ?")
            params.append(now_iso)

        if not fields:
            return False

        params.append(source_id)
        sql = f"UPDATE sources_registry SET {', '.join(fields)} WHERE source_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()
            return cursor.rowcount > 0

    def record_event(self, event_type: str, source_id: Optional[str] = None, message: str = "", metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Records a structured system event into system_events database table."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        import uuid
        event_id = f"EVT_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"
        meta_json = json.dumps(metadata or {})
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_events (event_id, event_type, source_id, timestamp_utc, message, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (event_id, event_type, source_id, now_iso, message, meta_json))
            conn.commit()
            return True

    def get_events(self, source_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent system events, optionally filtered by source_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if source_id:
                cursor.execute("""
                    SELECT * FROM system_events WHERE source_id = ? ORDER BY timestamp_utc DESC LIMIT ?;
                """, (source_id, limit))
            else:
                cursor.execute("""
                    SELECT * FROM system_events ORDER BY timestamp_utc DESC LIMIT ?;
                """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def register_source(
        self,
        canonical_url: Optional[str] = None,
        source_type: str = "FORUM",
        collector_type: str = "HTTP_CLEARNET",
        source_id: Optional[str] = None,
        url: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Alias for add_source ensuring backward compatibility with UI registrations."""
        target_url = canonical_url or url or ""
        if not source_id:
            source_id = f"SRC_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{hash(target_url) % 10000:04d}"
        return self.add_source(
            source_id=source_id,
            url=target_url,
            source_type=source_type,
            collector_type=collector_type,
            **kwargs
        )

    def deactivate_source(self, source_id: str) -> bool:
        """Deactivates a source by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sources_registry SET validation_status = 'INACTIVE' WHERE source_id = ?;
            """, (source_id,))
            conn.commit()
            return cursor.rowcount > 0

    def reactivate_source(self, source_id: str) -> bool:
        """Reactivates a source by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sources_registry SET validation_status = 'ACTIVE' WHERE source_id = ?;
            """, (source_id,))
            conn.commit()
            return cursor.rowcount > 0

    def remove_source(self, source_id: str) -> bool:
        """Removes a source from registry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM sources_registry WHERE source_id = ?;
            """, (source_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_source_by_id(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Finds a source by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sources_registry WHERE source_id = ?;", (source_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_source(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Finds a source by ID or URL."""
        if not source_id:
            return None
        return self.get_source_by_id(source_id) or self.get_source_by_url(source_id)

    def get_source_by_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Finds a source by canonical URL."""
        canonical_url = self.canonicalize_url(url)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sources_registry WHERE canonical_url = ?;", (canonical_url,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_active_sources(self) -> List[Dict[str, Any]]:
        """Returns all registered sources for dashboard display."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sources_registry ORDER BY discovery_timestamp_utc DESC;")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_all_sources(self) -> List[Dict[str, Any]]:
        """Returns all registered sources (both ACTIVE and INACTIVE)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sources_registry ORDER BY discovery_timestamp_utc DESC;")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_due_sources(self) -> List[Dict[str, Any]]:
        """Returns approved/active sources whose next_scheduled_utc is <= current time."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM sources_registry 
                WHERE validation_status IN ('APPROVED', 'LIVE', 'ACTIVE') 
                AND (next_scheduled_utc IS NULL OR next_scheduled_utc <= ?)
                ORDER BY next_scheduled_utc ASC;
            """, (now_iso,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def update_source_observation(
        self,
        source_id: str,
        status: str,
        raw_html_sha256: str,
        clean_text_sha256: str,
        content_changed: bool = False,
        minhash_signature: Optional[List[int]] = None,
        polling_interval_mins: int = 30
    ) -> bool:
        """Updates content hash signatures, timestamps, and next scheduled observation time."""
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()
        next_sched = (now_dt + datetime.timedelta(minutes=polling_interval_mins)).isoformat()
        minhash_json = json.dumps(minhash_signature) if minhash_signature is not None else None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            if content_changed:
                cursor.execute("""
                    UPDATE sources_registry SET
                        validation_status = ?,
                        last_checked_utc = ?,
                        last_successful_utc = ?,
                        last_change_utc = ?,
                        next_scheduled_utc = ?,
                        polling_interval_mins = ?,
                        failure_count = 0,
                        raw_html_sha256 = ?,
                        clean_text_sha256 = ?,
                        minhash_signature = ?
                    WHERE source_id = ?;
                """, (
                    status, now_iso, now_iso, now_iso, next_sched, polling_interval_mins,
                    raw_html_sha256, clean_text_sha256, minhash_json, source_id
                ))
            else:
                cursor.execute("""
                    UPDATE sources_registry SET
                        validation_status = ?,
                        last_checked_utc = ?,
                        last_successful_utc = ?,
                        next_scheduled_utc = ?,
                        polling_interval_mins = ?,
                        failure_count = 0,
                        raw_html_sha256 = ?,
                        clean_text_sha256 = ?,
                        minhash_signature = ?
                    WHERE source_id = ?;
                """, (
                    status, now_iso, now_iso, next_sched, polling_interval_mins,
                    raw_html_sha256, clean_text_sha256, minhash_json, source_id
                ))
            conn.commit()
            return cursor.rowcount > 0

    def increment_failure_count(self, source_id: str, status: str = "OFFLINE") -> bool:
        """Increments failure count and updates last_checked_utc without deactivating the registered source."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sources_registry SET
                    failure_count = failure_count + 1,
                    last_checked_utc = ?
                WHERE source_id = ?;
            """, (now_iso, source_id))
            conn.commit()
            return cursor.rowcount > 0
