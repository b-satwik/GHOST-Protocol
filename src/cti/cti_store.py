"""
CTI Evidence Store (SQLite Persistence) for DarkWatch CTI Pipeline.
Persists CTI indicator evidence, STIX 2.1 JSON objects, and STIX 2.1 Bundles
to feed future multi-modal fusion and XAI engines.
"""

import sqlite3
import os
import json
from typing import Dict, Any, Optional, List


class CTIStore:
    """
    SQLite persistence layer for CTI evidence and STIX 2.1 bundles.
    """

    def __init__(self, db_path: str = "data/collector_evidence.db", conn: Optional[sqlite3.Connection] = None):
        self.db_path = db_path
        self._persistent_conn: Optional[sqlite3.Connection] = conn
        if not self._persistent_conn:
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
        """Initializes SQLite CTI tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cti_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_record_id INTEGER NOT NULL,
                    onion_address TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    raw_indicator TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    extraction_method TEXT NOT NULL,
                    stix_object_id TEXT,
                    stix_json TEXT NOT NULL,
                    mitre_technique_id TEXT,
                    misp_category TEXT,
                    is_observed INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY(source_record_id) REFERENCES verification_attempts(id)
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS stix_bundles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_record_id INTEGER NOT NULL,
                    onion_address TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    bundle_id TEXT NOT NULL,
                    stix_bundle_json TEXT NOT NULL,
                    FOREIGN KEY(source_record_id) REFERENCES verification_attempts(id)
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL UNIQUE,
                    source_record_id INTEGER NOT NULL,
                    stix_bundle_id TEXT,
                    onion_address TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    alert_json TEXT NOT NULL,
                    FOREIGN KEY(source_record_id) REFERENCES verification_attempts(id)
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cti_source_record 
                ON cti_evidence(source_record_id);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_stix_bundle_source 
                ON stix_bundles(source_record_id);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_security_alert_source 
                ON security_alerts(source_record_id);
            """)
            conn.commit()


    def save_cti_results(
        self,
        source_record_id: int,
        onion_address: str,
        timestamp: str,
        stix_bundle: Dict[str, Any],
        correlated_indicators: List[Dict[str, Any]],
        mitre_mappings: List[Dict[str, Any]]
    ) -> None:
        """
        Saves STIX 2.1 Bundle and individual CTI evidence items to SQLite.
        """
        bundle_id = stix_bundle.get("id", "")
        bundle_json = json.dumps(stix_bundle)

        # Map STIX object IDs from bundle to normalized values
        val_to_stix_id: Dict[str, str] = {}
        for obj in stix_bundle.get("objects", []):
            name = obj.get("name", "")
            if name and obj.get("id"):
                # Clean prefix if present
                clean_name = name.split(":")[-1].strip()
                val_to_stix_id[clean_name.lower()] = obj["id"]

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Insert STIX Bundle
            cursor.execute("""
                INSERT INTO stix_bundles (
                    source_record_id, onion_address, timestamp, bundle_id, stix_bundle_json
                ) VALUES (?, ?, ?, ?, ?);
            """, (source_record_id, onion_address, timestamp, bundle_id, bundle_json))

            # 2. Insert Extracted & Correlated Indicators
            for ind in correlated_indicators:
                val = ind["normalized_value"]
                stix_obj_id = val_to_stix_id.get(val.lower())
                
                # Find matching STIX object json if available
                matching_stix_obj = next(
                    (o for o in stix_bundle.get("objects", []) if o.get("id") == stix_obj_id),
                    {"type": "indicator", "value": val}
                )

                cursor.execute("""
                    INSERT INTO cti_evidence (
                        source_record_id, onion_address, timestamp, indicator_type,
                        raw_indicator, normalized_value, extraction_method,
                        stix_object_id, stix_json, mitre_technique_id, misp_category, is_observed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    source_record_id,
                    onion_address,
                    timestamp,
                    ind["indicator_type"],
                    ind["raw_indicator"],
                    val,
                    ind["extraction_method"],
                    stix_obj_id,
                    json.dumps(matching_stix_obj),
                    None,
                    ind.get("misp_category"),
                    1 if ind.get("is_observed", True) else 0
                ))

            conn.commit()

    def lookup_indicator(self, normalized_value: str) -> List[Dict[str, Any]]:
        """Look up prior CTI evidence records in the local SQLite store matching a normalized value."""
        if not normalized_value:
            return []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, source_record_id, onion_address, timestamp, indicator_type,
                       raw_indicator, normalized_value, extraction_method, stix_object_id,
                       misp_category, is_observed
                FROM cti_evidence
                WHERE LOWER(normalized_value) = LOWER(?);
            """, (normalized_value,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_cti_evidence_by_record(self, source_record_id: int) -> List[Dict[str, Any]]:
        """Retrieves all CTI evidence records for a given source record ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM cti_evidence WHERE source_record_id = ?;
            """, (source_record_id,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_stix_bundle_by_record(self, source_record_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves STIX bundle for a given source record ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT stix_bundle_json FROM stix_bundles
                WHERE source_record_id = ?
                ORDER BY id DESC LIMIT 1;
            """, (source_record_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["stix_bundle_json"])
            return None

    def save_security_alert(
        self,
        alert_object: Dict[str, Any],
        source_record_id: int,
        onion_address: str
    ) -> None:
        """Saves a generated security alert payload to SQLite database."""
        alert_id = alert_object["alert_id"]
        stix_bundle_id = alert_object.get("stix_bundle_id")
        timestamp = alert_object.get("timestamp", "")
        severity = alert_object.get("severity", "LOW")
        risk_score = float(alert_object.get("risk_score", 0.0))
        alert_json = json.dumps(alert_object)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO security_alerts (
                    alert_id, source_record_id, stix_bundle_id, onion_address,
                    timestamp, severity, risk_score, alert_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                alert_id, source_record_id, stix_bundle_id, onion_address,
                timestamp, severity, risk_score, alert_json
            ))
            conn.commit()

    def get_security_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a security alert object by alert_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT alert_json FROM security_alerts WHERE alert_id = ?;
            """, (alert_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["alert_json"])
            return None

    def get_security_alert_by_record(self, source_record_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves latest security alert object for a source_record_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT alert_json FROM security_alerts
                WHERE source_record_id = ?
                ORDER BY id DESC LIMIT 1;
            """, (source_record_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["alert_json"])
            return None

