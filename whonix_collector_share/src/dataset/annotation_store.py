"""
Annotation Store for DarkWatch Gold Dataset (SQLite Implementation).
Persists multi-tier GoldRecord entries, annotation history, confidence scores,
and disputed label statuses.
"""

import sqlite3
import json
import os
import datetime
from typing import Dict, Any, Optional, List
from src.dataset.schema import GoldRecord, AnnotationTier


class AnnotationStore:
    """
    SQLite persistence store for Gold Dataset records and annotation lineage.
    """

    def __init__(self, db_path: str = "data/gold_dataset.db"):
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
        """Initializes SQLite schema for records and annotation history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS gold_dataset_records (
                    record_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    sanitized_text TEXT NOT NULL,
                    activity_categories TEXT NOT NULL,
                    intent TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    target_sector TEXT NOT NULL,
                    cti_entities TEXT NOT NULL,
                    mitre_mappings TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    annotation_tier TEXT NOT NULL,
                    annotator_id TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    disputed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    review_notes TEXT,
                    full_record_json TEXT NOT NULL
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS annotation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL,
                    annotation_tier TEXT NOT NULL,
                    annotator_id TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    disputed INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    change_summary TEXT NOT NULL,
                    record_snapshot TEXT NOT NULL,
                    FOREIGN KEY(record_id) REFERENCES gold_dataset_records(record_id)
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_gold_tier 
                ON gold_dataset_records(annotation_tier);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_gold_disputed 
                ON gold_dataset_records(disputed);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_hist_record_id 
                ON annotation_history(record_id);
            """)
            conn.commit()

    def save_record(self, record: GoldRecord, change_summary: str = "Initial creation") -> bool:
        """Saves or replaces a GoldRecord in the database and logs history."""
        rec_dict = record.to_dict()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        rec_dict["annotation_metadata"]["updated_at"] = now_iso

        record_id = record.record_id
        meta = rec_dict["annotation_metadata"]
        tier = meta.get("annotation_tier", AnnotationTier.AUTOMATED.value)
        annotator = meta.get("annotator_id", "system")
        confidence = float(meta.get("confidence", 0.5))
        disputed = 1 if meta.get("disputed") else 0
        review_notes = meta.get("review_notes")

        full_json = json.dumps(rec_dict, ensure_ascii=False)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO gold_dataset_records (
                    record_id, schema_version, sanitized_text, activity_categories,
                    intent, severity, target_sector, cti_entities, mitre_mappings,
                    provenance, annotation_tier, annotator_id, confidence, disputed,
                    created_at, updated_at, review_notes, full_record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                record_id,
                record.schema_version,
                record.sanitized_text,
                json.dumps(record.activity_categories),
                record.intent,
                record.severity,
                json.dumps(record.target_sector),
                json.dumps(record.cti_entities),
                json.dumps(record.mitre_mappings),
                json.dumps(record.provenance),
                tier,
                annotator,
                confidence,
                disputed,
                meta.get("created_at", now_iso),
                now_iso,
                review_notes,
                full_json
            ))

            # Record history entry
            cursor.execute("""
                INSERT INTO annotation_history (
                    record_id, annotation_tier, annotator_id, confidence,
                    disputed, timestamp, change_summary, record_snapshot
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                record_id,
                tier,
                annotator,
                confidence,
                disputed,
                now_iso,
                change_summary,
                full_json
            ))
            conn.commit()
            return True

    def get_record(self, record_id: str) -> Optional[GoldRecord]:
        """Retrieves a GoldRecord by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT full_record_json FROM gold_dataset_records WHERE record_id = ?;
            """, (record_id,))
            row = cursor.fetchone()
            if row and row["full_record_json"]:
                data = json.loads(row["full_record_json"])
                return GoldRecord.from_dict(data)
            return None

    def get_records_by_tier(self, tier: str) -> List[GoldRecord]:
        """Retrieves all GoldRecords belonging to a specific annotation tier."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT full_record_json FROM gold_dataset_records 
                WHERE annotation_tier = ? ORDER BY created_at ASC;
            """, (tier,))
            rows = cursor.fetchall()
            records = []
            for r in rows:
                data = json.loads(r["full_record_json"])
                records.append(GoldRecord.from_dict(data))
            return records

    def get_all_records(self, include_duplicates: bool = True) -> List[GoldRecord]:
        """Retrieves all GoldRecords."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT full_record_json FROM gold_dataset_records ORDER BY created_at ASC;
            """)
            rows = cursor.fetchall()
            records = []
            for r in rows:
                data = json.loads(r["full_record_json"])
                rec = GoldRecord.from_dict(data)
                if not include_duplicates and rec.provenance.get("duplicate_of"):
                    continue
                records.append(rec)
            return records

    def get_disputed_records(self) -> List[GoldRecord]:
        """Retrieves records marked as disputed."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT full_record_json FROM gold_dataset_records WHERE disputed = 1;
            """)
            rows = cursor.fetchall()
            return [GoldRecord.from_dict(json.loads(r["full_record_json"])) for r in rows]

    def get_history(self, record_id: str) -> List[Dict[str, Any]]:
        """Retrieves annotation history for a record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM annotation_history 
                WHERE record_id = ? ORDER BY id ASC;
            """, (record_id,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def update_annotation(
        self,
        record_id: str,
        new_tier: str,
        annotator_id: str,
        confidence: float,
        activity_categories: Optional[List[str]] = None,
        intent: Optional[str] = None,
        severity: Optional[str] = None,
        target_sector: Optional[List[str]] = None,
        disputed: Optional[bool] = None,
        review_notes: Optional[str] = None,
        change_summary: str = "Updated annotation"
    ) -> bool:
        """
        Updates annotation attributes of a GoldRecord and writes a history entry.
        """
        rec = self.get_record(record_id)
        if not rec:
            return False

        if activity_categories is not None:
            rec.activity_categories = activity_categories
        if intent is not None:
            rec.intent = intent
        if severity is not None:
            rec.severity = severity
        if target_sector is not None:
            rec.target_sector = target_sector

        rec.annotation_metadata["annotation_tier"] = new_tier
        rec.annotation_metadata["annotator_id"] = annotator_id
        rec.annotation_metadata["confidence"] = round(confidence, 2)
        if disputed is not None:
            rec.annotation_metadata["disputed"] = disputed
        if review_notes is not None:
            rec.annotation_metadata["review_notes"] = review_notes

        return self.save_record(rec, change_summary=change_summary)

    def get_record_count(self) -> Dict[str, Any]:
        """Returns statistics on dataset records by tier and total."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT annotation_tier, COUNT(*) as cnt 
                FROM gold_dataset_records GROUP BY annotation_tier;
            """)
            tier_counts = {r["annotation_tier"]: r["cnt"] for r in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) FROM gold_dataset_records;")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM gold_dataset_records WHERE disputed = 1;")
            disputed_count = cursor.fetchone()[0]

            return {
                "total_records": total,
                "disputed_records": disputed_count,
                "by_tier": tier_counts
            }
