"""
Stage 1 Alert Engine for DarkWatch GHOST PROTOCOL.
Generates structured security alert records when an observation produces a meaningful threat event.
"""

import sqlite3
import json
import os
import datetime
import uuid
from typing import Dict, Any, Optional, List


class Stage1AlertEngine:
    """
    SQLite-backed alert engine enforcing notification rules based on DarkWatch CTI & ML outputs.
    """

    def __init__(self, db_path: str = "data/alerts.db"):
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
        """Initializes SQLite schema for stage1_alerts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS stage1_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp_utc TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    canonical_url TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    evidence_summary TEXT NOT NULL,
                    relevant_cti_json TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    provenance_json TEXT NOT NULL,
                    observation_id TEXT NOT NULL
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alert_time 
                ON stage1_alerts(timestamp_utc);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alert_severity 
                ON stage1_alerts(severity);
            """)
            conn.commit()

    def evaluate_and_alert(
        self,
        observation_data: Dict[str, Any],
        bridge_output: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Evaluates an observation and its bridge output against alert rules.
        Generates and persists alerts for meaningful threat events.
        """
        alerts_generated = []
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        source_id = observation_data.get("source_id", "unknown_source")
        canonical_url = observation_data.get("url") or observation_data.get("canonical_url", "")
        obs_id = observation_data.get("observation_id", f"obs_{int(datetime.datetime.now().timestamp())}")
        change_state = observation_data.get("change_state", "CHANGED_UNIQUE")

        b_out = bridge_output or {}
        risk_score = float(b_out.get("risk_score", 0.0))
        severity = b_out.get("risk_severity", "LOW")

        cti_data = b_out.get("cti", {})
        indicators = cti_data.get("indicators", [])

        cves = [ind.get("normalized_value") for ind in indicators if ind.get("indicator_type") == "CVE"]
        malware = [ind.get("normalized_value") for ind in indicators if ind.get("indicator_type") == "MALWARE"]

        # Rule 1: High/Elevated Threat Content Alert
        if risk_score >= 0.60 or severity in ("ELEVATED", "HIGH"):
            alert_rec = {
                "alert_id": f"ALT-RISK-{uuid.uuid4().hex[:6].upper()}",
                "timestamp_utc": now_iso,
                "source_id": source_id,
                "canonical_url": canonical_url,
                "event_type": "NEW_HIGH_RISK_THREAT",
                "severity": severity,
                "evidence_summary": f"High risk content observed (Risk Score: {risk_score:.3f}, Severity: {severity}).",
                "relevant_cti_json": json.dumps({"indicators_count": len(indicators)}),
                "risk_score": risk_score,
                "provenance_json": json.dumps({"change_state": change_state}),
                "observation_id": obs_id
            }
            self._save_alert(alert_rec)
            alerts_generated.append(alert_rec)

        # Rule 2: New CVE Alert
        if cves:
            alert_rec = {
                "alert_id": f"ALT-CVE-{uuid.uuid4().hex[:6].upper()}",
                "timestamp_utc": now_iso,
                "source_id": source_id,
                "canonical_url": canonical_url,
                "event_type": "NEW_CVE_DISCOVERED",
                "severity": "ELEVATED",
                "evidence_summary": f"Vulnerability CVEs detected in text: {', '.join(cves)}.",
                "relevant_cti_json": json.dumps({"cves": cves}),
                "risk_score": risk_score,
                "provenance_json": json.dumps({"change_state": change_state}),
                "observation_id": obs_id
            }
            self._save_alert(alert_rec)
            alerts_generated.append(alert_rec)

        # Rule 3: New Malware Alert
        if malware:
            alert_rec = {
                "alert_id": f"ALT-MAL-{uuid.uuid4().hex[:6].upper()}",
                "timestamp_utc": now_iso,
                "source_id": source_id,
                "canonical_url": canonical_url,
                "event_type": "NEW_MALWARE_DISCOVERED",
                "severity": "HIGH",
                "evidence_summary": f"Malware names/tools detected in text: {', '.join(malware)}.",
                "relevant_cti_json": json.dumps({"malware": malware}),
                "risk_score": risk_score,
                "provenance_json": json.dumps({"change_state": change_state}),
                "observation_id": obs_id
            }
            self._save_alert(alert_rec)
            alerts_generated.append(alert_rec)

        return alerts_generated

    def _save_alert(self, alert_rec: Dict[str, Any]) -> bool:
        """Saves alert record into SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO stage1_alerts (
                    alert_id, timestamp_utc, source_id, canonical_url, event_type,
                    severity, evidence_summary, relevant_cti_json, risk_score,
                    provenance_json, observation_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                alert_rec["alert_id"],
                alert_rec["timestamp_utc"],
                alert_rec["source_id"],
                alert_rec["canonical_url"],
                alert_rec["event_type"],
                alert_rec["severity"],
                alert_rec["evidence_summary"],
                alert_rec["relevant_cti_json"],
                alert_rec["risk_score"],
                alert_rec["provenance_json"],
                alert_rec["observation_id"]
            ))
            conn.commit()
            return True

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent alerts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM stage1_alerts ORDER BY timestamp_utc DESC LIMIT ?;", (limit,))
            rows = cursor.fetchall()
            alerts = []
            for r in rows:
                item = dict(r)
                item["relevant_cti"] = json.loads(item.get("relevant_cti_json") or "{}")
                item["provenance"] = json.loads(item.get("provenance_json") or "{}")
                alerts.append(item)
            return alerts

    def get_alerts_count_today(self) -> int:
        """Returns total alerts generated today."""
        today_prefix = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM stage1_alerts WHERE timestamp_utc LIKE ?;", (f"{today_prefix}%",))
            row = cursor.fetchone()
            return row[0] if row else 0
