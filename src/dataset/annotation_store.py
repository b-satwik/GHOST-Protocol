"""
Annotation Store for DarkWatch Gold Dataset (SQLite Implementation).
Persists multi-tier GoldRecord entries, annotation history, confidence scores,
and disputed label statuses.
"""

import sqlite3
import json
import os
import datetime
import uuid
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

            # --- GHOST PROTOCOL EXTENSIONS ---
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
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entities (
                    entity_id TEXT PRIMARY KEY,
                    canonical_name TEXT UNIQUE NOT NULL,
                    entity_type TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    observation_count INTEGER NOT NULL DEFAULT 1,
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    metadata_json TEXT
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_aliases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    source TEXT,
                    confidence REAL DEFAULT 1.0,
                    FOREIGN KEY(entity_id) REFERENCES entities(entity_id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    edge_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    edge_type TEXT NOT NULL,
                    weight REAL NOT NULL DEFAULT 1.0,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS breach_claims (
                    claim_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    target_company TEXT,
                    actor_handle TEXT,
                    malware_used TEXT,
                    data_size TEXT,
                    breach_date TEXT,
                    source_url TEXT,
                    observation_id TEXT,
                    timestamp TEXT NOT NULL,
                    raw_claim TEXT
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hibp_dumps (
                    dump_id TEXT PRIMARY KEY,
                    identity_indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    breach_name TEXT NOT NULL,
                    exposed_fields_json TEXT NOT NULL,
                    breach_date TEXT NOT NULL,
                    source_provenance TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    created_at TEXT NOT NULL
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_sessions (
                    session_id TEXT PRIMARY KEY,
                    source_id TEXT,
                    source_ids_json TEXT NOT NULL DEFAULT '[]',
                    primary_source_url TEXT,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    actors_json TEXT NOT NULL DEFAULT '[]',
                    aliases_json TEXT NOT NULL DEFAULT '[]',
                    targets_json TEXT NOT NULL DEFAULT '[]',
                    sources_json TEXT NOT NULL DEFAULT '[]',
                    observation_ids_json TEXT NOT NULL DEFAULT '[]',
                    cti_entities_json TEXT NOT NULL DEFAULT '[]',
                    indicators_json TEXT NOT NULL DEFAULT '[]',
                    urls_json TEXT NOT NULL DEFAULT '[]',
                    timeline_json TEXT NOT NULL DEFAULT '[]',
                    correlation_reasons_json TEXT NOT NULL DEFAULT '[]',
                    temporal_anomaly_json TEXT NOT NULL DEFAULT '{}',
                    stix_relationships_json TEXT NOT NULL DEFAULT '[]',
                    mitre_techniques_json TEXT NOT NULL DEFAULT '[]',
                    direct_replies_json TEXT NOT NULL DEFAULT '[]',
                    nested_replies_json TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT
                );
            """)

            cursor.execute("PRAGMA table_info(threat_sessions);")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            if "source_id" not in existing_cols:
                cursor.execute("ALTER TABLE threat_sessions ADD COLUMN source_id TEXT;")
            if "source_ids_json" not in existing_cols:
                cursor.execute("ALTER TABLE threat_sessions ADD COLUMN source_ids_json TEXT NOT NULL DEFAULT '[]';")
            if "primary_source_url" not in existing_cols:
                cursor.execute("ALTER TABLE threat_sessions ADD COLUMN primary_source_url TEXT;")
            if "direct_replies_json" not in existing_cols:
                cursor.execute("ALTER TABLE threat_sessions ADD COLUMN direct_replies_json TEXT NOT NULL DEFAULT '[]';")
            if "nested_replies_json" not in existing_cols:
                cursor.execute("ALTER TABLE threat_sessions ADD COLUMN nested_replies_json TEXT NOT NULL DEFAULT '[]';")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS external_research_logs (
                    research_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    analyst_question TEXT NOT NULL,
                    sanitized_query TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    answer TEXT NOT NULL,
                    sources_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'SUCCESS',
                    provenance_label TEXT NOT NULL DEFAULT 'EXTERNAL WEB AI RESEARCH',
                    metadata_json TEXT,
                    FOREIGN KEY(session_id) REFERENCES threat_sessions(session_id)
                );
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(canonical_name);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_graph_src ON graph_edges(source_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_graph_tgt ON graph_edges(target_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_hibp_indicator ON hibp_dumps(identity_indicator);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_breach_company ON breach_claims(target_company);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_status ON threat_sessions(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_research_session ON external_research_logs(session_id);")

            conn.commit()
        self.purge_stale_synthetic_sessions()

    def purge_stale_synthetic_sessions(self) -> int:
        """Deletes synthetic test sessions (e.g. synthetic_test_feed) from SQLite database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM threat_sessions
                WHERE sources_json LIKE '%synthetic_test_feed%'
                   OR sources_json LIKE '%idempotent_test%'
                   OR session_id LIKE '%synthetic%'
                   OR metadata_json LIKE '%synthetic%';
            """)
            cursor.execute("""
                DELETE FROM sources_registry
                WHERE canonical_url LIKE '%synthetic_test_feed%'
                   OR canonical_url LIKE '%idempotent_test%';
            """)
            conn.commit()
            return cursor.rowcount

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

    def save_threat_session(self, session_dict: Dict[str, Any]) -> bool:
        """Saves or replaces a Threat Session entry in SQLite."""
        session_id = session_dict["session_id"]
        source_id = session_dict.get("source_id")
        source_ids = json.dumps(session_dict.get("source_ids", []))
        primary_source_url = session_dict.get("primary_source_url")
        status = session_dict.get("status", "ACTIVE")
        first_seen = session_dict.get("first_seen", datetime.datetime.now(datetime.timezone.utc).isoformat())
        last_seen = session_dict.get("last_seen", datetime.datetime.now(datetime.timezone.utc).isoformat())

        meta_dict = session_dict.get("metadata", {}) or {}
        if session_dict.get("candidate_id"):
            meta_dict["candidate_id"] = session_dict.get("candidate_id")
        if session_dict.get("thread_url"):
            meta_dict["thread_url"] = session_dict.get("thread_url")
        if session_dict.get("risk_score") is not None:
            meta_dict["risk_score"] = session_dict.get("risk_score")
        if session_dict.get("severity"):
            meta_dict["severity"] = session_dict.get("severity")

        actors = json.dumps(session_dict.get("actors", []))
        aliases = json.dumps(session_dict.get("aliases", []))
        targets = json.dumps(session_dict.get("targets", []))
        
        sources_list = session_dict.get("sources") or []
        if not sources_list:
            if session_dict.get("primary_source_url"):
                sources_list = [session_dict["primary_source_url"]]
            elif session_dict.get("thread_url"):
                sources_list = [session_dict["thread_url"]]
            elif meta_dict.get("thread_url"):
                sources_list = [meta_dict["thread_url"]]
        sources = json.dumps(sources_list)

        obs_ids = json.dumps(session_dict.get("observation_ids", []))
        cti_entities = json.dumps(session_dict.get("cti_entities", []))
        indicators = json.dumps(session_dict.get("indicators", []))
        urls = json.dumps(session_dict.get("urls", []))
        timeline = json.dumps(session_dict.get("timeline", []))
        correlation_reasons = json.dumps(session_dict.get("correlation_reasons", []))
        temporal_anomaly = json.dumps(session_dict.get("temporal_anomaly", {}))
        stix_rel = json.dumps(session_dict.get("stix_relationships", []))
        mitre_tech = json.dumps(session_dict.get("mitre_techniques", []))
        direct_replies = json.dumps(session_dict.get("direct_replies", []))
        nested_replies = json.dumps(session_dict.get("nested_replies", []))
        meta = json.dumps(meta_dict)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_sessions (
                    session_id, source_id, source_ids_json, primary_source_url,
                    status, first_seen, last_seen, actors_json,
                    aliases_json, targets_json, sources_json, observation_ids_json,
                    cti_entities_json, indicators_json, urls_json, timeline_json,
                    correlation_reasons_json, temporal_anomaly_json,
                    stix_relationships_json, mitre_techniques_json,
                    direct_replies_json, nested_replies_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                session_id, source_id, source_ids, primary_source_url,
                status, first_seen, last_seen, actors,
                aliases, targets, sources, obs_ids,
                cti_entities, indicators, urls, timeline,
                correlation_reasons, temporal_anomaly,
                stix_rel, mitre_tech, direct_replies, nested_replies, meta
            ))
            conn.commit()
            return True

    def get_threat_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a Threat Session by session_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            if not row:
                return None
            keys = set(row.keys()) if hasattr(row, "keys") else set()
            meta_obj = json.loads(row["metadata_json"] or "{}") if "metadata_json" in keys else {}

            sources_val = json.loads(row["sources_json"]) if ("sources_json" in keys and row["sources_json"]) else []
            if not sources_val:
                if "primary_source_url" in keys and row["primary_source_url"]:
                    sources_val = [row["primary_source_url"]]
                elif meta_obj.get("thread_url"):
                    sources_val = [meta_obj["thread_url"]]

            return {
                "session_id": row["session_id"],
                "source_id": row["source_id"] if "source_id" in keys else None,
                "candidate_id": meta_obj.get("candidate_id"),
                "thread_url": meta_obj.get("thread_url"),
                "source_ids": json.loads(row["source_ids_json"]) if ("source_ids_json" in keys and row["source_ids_json"]) else [],
                "primary_source_url": row["primary_source_url"] if "primary_source_url" in keys else None,
                "status": row["status"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "actors": json.loads(row["actors_json"]),
                "aliases": json.loads(row["aliases_json"]),
                "targets": json.loads(row["targets_json"]),
                "sources": sources_val,
                "observation_ids": json.loads(row["observation_ids_json"]),
                "cti_entities": json.loads(row["cti_entities_json"]),
                "indicators": json.loads(row["indicators_json"]),
                "urls": json.loads(row["urls_json"]),
                "timeline": json.loads(row["timeline_json"]),
                "correlation_reasons": json.loads(row["correlation_reasons_json"]),
                "temporal_anomaly": json.loads(row["temporal_anomaly_json"]),
                "stix_relationships": json.loads(row["stix_relationships_json"]),
                "mitre_techniques": json.loads(row["mitre_techniques_json"]),
                "direct_replies": json.loads(row["direct_replies_json"]) if ("direct_replies_json" in keys and row["direct_replies_json"]) else [],
                "nested_replies": json.loads(row["nested_replies_json"]) if ("nested_replies_json" in keys and row["nested_replies_json"]) else [],
                "risk_score": meta_obj.get("risk_score", 0.0),
                "severity": meta_obj.get("severity", "LOW"),
                "metadata": meta_obj
            }

    def list_threat_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists threat sessions ordered by last_seen descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT session_id FROM threat_sessions ORDER BY last_seen DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            result = []
            for r in rows:
                sess = self.get_threat_session(r["session_id"])
                if sess:
                    result.append(sess)
            return result

    def save_external_research(self, log_dict: Dict[str, Any]) -> bool:
        """Saves an External Research Log entry in SQLite."""
        research_id = log_dict.get("research_id", f"RES-{uuid.uuid4().hex[:8].upper()}")
        session_id = log_dict["session_id"]
        question = log_dict["analyst_question"]
        sanitized_query = log_dict.get("sanitized_query", question)
        provider = log_dict.get("provider", "GEMINI_SEARCH_GROUNDING")
        ts = log_dict.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
        answer = log_dict.get("answer", "")
        sources = json.dumps(log_dict.get("sources", []))
        status = log_dict.get("status", "SUCCESS")
        provenance = log_dict.get("provenance_label", "EXTERNAL WEB AI RESEARCH")
        meta = json.dumps(log_dict.get("metadata", {}))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO external_research_logs (
                    research_id, session_id, analyst_question, sanitized_query,
                    provider, timestamp, answer, sources_json, status,
                    provenance_label, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                research_id, session_id, question, sanitized_query,
                provider, ts, answer, sources, status,
                provenance, meta
            ))
            conn.commit()
            return True

    def get_external_research_for_session(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieves external research logs for a specific threat session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM external_research_logs WHERE session_id = ? ORDER BY timestamp DESC", (session_id,))
            rows = cursor.fetchall()
            return [
                {
                    "research_id": r["research_id"],
                    "session_id": r["session_id"],
                    "analyst_question": r["analyst_question"],
                    "sanitized_query": r["sanitized_query"],
                    "provider": r["provider"],
                    "timestamp": r["timestamp"],
                    "answer": r["answer"],
                    "sources": json.loads(r["sources_json"]),
                    "status": r["status"],
                    "provenance_label": r["provenance_label"],
                    "metadata": json.loads(r["metadata_json"] or "{}")
                }
                for r in rows
            ]

    def list_cti_entities(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Lists extracted CTI indicators and entities across threat sessions."""
        sessions = self.list_threat_sessions(limit=limit)
        entities = []
        for s in sessions:
            for ind in s.get("indicators", []):
                if isinstance(ind, dict):
                    ind["session_id"] = s.get("session_id")
                    entities.append(ind)
                else:
                    entities.append({
                        "entity": str(ind),
                        "type": "Indicator",
                        "session_id": s.get("session_id"),
                        "severity": s.get("risk_severity", "HIGH"),
                        "risk_score": s.get("risk_score", 0.85)
                    })
        return entities
