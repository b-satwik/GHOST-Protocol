"""
Observation History Persistence Store for DarkWatch Stage 1 (SQLite Implementation).
Persists complete observation evidence across time to enable historical entity correlation.
"""

import sqlite3
import json
import os
import datetime
from typing import Dict, Any, Optional, List


class ObservationHistoryStore:
    """
    SQLite persistence store for historical observation evidence records.
    """

    def __init__(self, db_path: str = "data/observation_history.db"):
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
        """Initializes SQLite schema for observation_history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS observation_history (
                    observation_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    canonical_url TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    status TEXT NOT NULL,
                    change_state TEXT NOT NULL,
                    raw_html_sha256 TEXT NOT NULL,
                    clean_text_sha256 TEXT NOT NULL,
                    clean_text TEXT NOT NULL,
                    extracted_links_json TEXT NOT NULL,
                    extracted_cves_json TEXT NOT NULL,
                    extracted_malware_json TEXT NOT NULL,
                    extracted_iocs_json TEXT NOT NULL,
                    stix_bundle_id TEXT,
                    mitre_techniques_json TEXT NOT NULL,
                    fusion_risk_score REAL NOT NULL DEFAULT 0.0,
                    risk_severity TEXT NOT NULL DEFAULT 'LOW',
                    xai_summary TEXT,
                    provenance_json TEXT NOT NULL
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_obs_source 
                ON observation_history(source_id);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_obs_url 
                ON observation_history(canonical_url);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_obs_sha 
                ON observation_history(clean_text_sha256);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_obs_time 
                ON observation_history(timestamp_utc);
            """)
            conn.commit()

    def save_observation(self, observation_data: Dict[str, Any]) -> bool:
        """Saves a structured observation record."""
        obs_id = observation_data.get("observation_id", f"obs_{int(datetime.datetime.now().timestamp())}")
        source_id = observation_data.get("source_id", "unknown_source")
        canonical_url = observation_data.get("canonical_url", "")
        now_iso = observation_data.get("timestamp_utc", datetime.datetime.now(datetime.timezone.utc).isoformat())
        status = observation_data.get("status", "CONTENT_ACCESSIBLE")
        change_state = observation_data.get("change_state", "CHANGED_UNIQUE")

        raw_sha = observation_data.get("raw_html_sha256", "")
        clean_sha = observation_data.get("clean_text_sha256", "")
        clean_text = observation_data.get("clean_text", "")

        links_json = json.dumps(observation_data.get("extracted_links", []))
        cves_json = json.dumps(observation_data.get("extracted_cves", []))
        malware_json = json.dumps(observation_data.get("extracted_malware", []))
        iocs_json = json.dumps(observation_data.get("extracted_iocs", []))

        stix_id = observation_data.get("stix_bundle_id", "")
        mitre_json = json.dumps(observation_data.get("mitre_techniques", []))

        fusion_score = float(observation_data.get("fusion_risk_score", 0.0))
        severity = observation_data.get("risk_severity", "LOW")
        xai_summary = observation_data.get("xai_summary", "")
        prov_json = json.dumps(observation_data.get("provenance", {}))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO observation_history (
                    observation_id, source_id, canonical_url, timestamp_utc, status,
                    change_state, raw_html_sha256, clean_text_sha256, clean_text,
                    extracted_links_json, extracted_cves_json, extracted_malware_json,
                    extracted_iocs_json, stix_bundle_id, mitre_techniques_json,
                    fusion_risk_score, risk_severity, xai_summary, provenance_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                obs_id, source_id, canonical_url, now_iso, status,
                change_state, raw_sha, clean_sha, clean_text,
                links_json, cves_json, malware_json,
                iocs_json, stix_id, mitre_json,
                fusion_score, severity, xai_summary, prov_json
            ))
            conn.commit()
            return True

    def query_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Returns recent observation records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM observation_history ORDER BY timestamp_utc DESC LIMIT ?;
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_observations_by_entity(self, entity_query: str) -> List[Dict[str, Any]]:
        """Searches observation records matching an entity query (CVE, malware, URL, hash)."""
        q = f"%{entity_query.strip().lower()}%"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM observation_history 
                WHERE LOWER(clean_text) LIKE ? 
                OR LOWER(canonical_url) LIKE ?
                OR LOWER(extracted_cves_json) LIKE ?
                OR LOWER(extracted_malware_json) LIKE ?
                OR LOWER(extracted_iocs_json) LIKE ?
                OR LOWER(clean_text_sha256) LIKE ?
                ORDER BY timestamp_utc ASC;
            """, (q, q, q, q, q, q))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_source_history(self, source_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns observation history records for a specific source_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM observation_history 
                WHERE source_id = ? 
                ORDER BY timestamp_utc DESC
                LIMIT ?;
            """, (source_id, limit))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
