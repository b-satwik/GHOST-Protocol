"""
Unit and Integration Tests for DarkWatch Gold Dataset Pipeline.
Tests schema, AnnotationStore, WeakSupervisionEngine, MinHashLSHDeduplicator,
ReviewQueueManager, QualityAuditor, DatasetExporter, and pilot runner integration.
"""

import unittest
import os
import json
import tempfile
import sqlite3
from src.dataset.schema import (
    GoldRecord,
    SCHEMA_VERSION,
    AnnotationTier,
    ActivityCategory,
    Intent,
    Severity,
    TargetSector
)
from src.dataset.annotation_store import AnnotationStore
from src.dataset.weak_supervision import WeakSupervisionEngine
from src.deduplication.minhash_lsh import MinHashLSHDeduplicator
from src.review.reviewer import ReviewQueueManager
from src.review.quality_auditor import QualityAuditor
from src.exporter.export_runner import DatasetExporter
from pilot_runner import run_gold_dataset_pilot


class TestGoldRecordSchema(unittest.TestCase):
    """Tests GoldRecord schema serialization, deserialization, and validation."""

    def test_schema_serialization(self):
        prov = {"source_id": "SRC_TEST_1", "onion_address": "abc.onion"}
        record = GoldRecord(
            sanitized_text="SELLING LOKI KEYLOGGER SOURCE CODE",
            provenance=prov,
            activity_categories=[ActivityCategory.MALWARE_SALES.value],
            intent=Intent.ILLICIT_SALE.value,
            severity=Severity.HIGH.value
        )
        rec_dict = record.to_dict()
        self.assertEqual(rec_dict["schema_version"], SCHEMA_VERSION)
        self.assertEqual(rec_dict["sanitized_text"], "SELLING LOKI KEYLOGGER SOURCE CODE")
        self.assertEqual(rec_dict["annotation_metadata"]["annotation_tier"], AnnotationTier.AUTOMATED.value)

        # Deserialize
        reconstructed = GoldRecord.from_dict(rec_dict)
        self.assertEqual(reconstructed.record_id, record.record_id)
        self.assertEqual(reconstructed.activity_categories, [ActivityCategory.MALWARE_SALES.value])

    def test_schema_validation(self):
        record = GoldRecord(
            sanitized_text="Sample dark web content",
            provenance={"source_id": "SRC_01"}
        )
        errors = record.validate()
        self.assertEqual(len(errors), 0)

        # Invalid record without text
        bad_record = GoldRecord(
            sanitized_text="",
            provenance={}
        )
        bad_errors = bad_record.validate()
        self.assertTrue(len(bad_errors) >= 1)


class TestAnnotationStore(unittest.TestCase):
    """Tests SQLite AnnotationStore persistence, updates, and history."""

    def setUp(self):
        self.store = AnnotationStore(db_path=":memory:")

    def test_save_and_retrieve_record(self):
        rec = GoldRecord(
            record_id="gold_test_001",
            sanitized_text="Selling botnet logins",
            provenance={"source_id": "SRC_001"}
        )
        self.assertTrue(self.store.save_record(rec))

        retrieved = self.store.get_record("gold_test_001")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.sanitized_text, "Selling botnet logins")

    def test_annotation_update_and_history(self):
        rec = GoldRecord(
            record_id="gold_test_002",
            sanitized_text="Zero-day exploit for sale",
            provenance={"source_id": "SRC_002"}
        )
        self.store.save_record(rec)

        # Update annotation
        success = self.store.update_annotation(
            record_id="gold_test_002",
            new_tier=AnnotationTier.HUMAN_VERIFIED.value,
            annotator_id="human_analyst_01",
            confidence=1.0,
            activity_categories=[ActivityCategory.EXPLOIT_DISTRIBUTION.value],
            intent=Intent.ILLICIT_SALE.value,
            severity=Severity.CRITICAL.value,
            review_notes="Verified zero-day exploit listing."
        )
        self.assertTrue(success)

        updated_rec = self.store.get_record("gold_test_002")
        self.assertEqual(updated_rec.annotation_metadata["annotation_tier"], AnnotationTier.HUMAN_VERIFIED.value)
        self.assertEqual(updated_rec.annotation_metadata["annotator_id"], "human_analyst_01")
        self.assertEqual(updated_rec.severity, Severity.CRITICAL.value)

        # Check History
        history = self.store.get_history("gold_test_002")
        self.assertEqual(len(history), 2)  # Initial insert + update


class TestWeakSupervision(unittest.TestCase):
    """Tests WeakSupervisionEngine candidate label generation."""

    def setUp(self):
        self.engine = WeakSupervisionEngine()

    def test_malware_sales_inference(self):
        text = "Selling Loki 2.0 keylogger source code. Price $500 BTC. Contact via Jabber."
        provenance = {"source_id": "SRC_01"}
        rec = self.engine.generate_candidate_record(text, provenance)

        self.assertEqual(rec.annotation_metadata["annotation_tier"], AnnotationTier.WEAK_SUPERVISION.value)
        self.assertTrue(rec.annotation_metadata["confidence"] <= 0.85)
        self.assertIn(ActivityCategory.MALWARE_SALES.value, rec.activity_categories)
        self.assertEqual(rec.intent, Intent.ILLICIT_SALE.value)
        self.assertTrue(len(rec.cti_entities["malware"]) > 0)

    def test_exploit_distribution_inference(self):
        text = "New Windows RCE zero-day CVE-2024-38077 payload released."
        provenance = {"source_id": "SRC_02"}
        rec = self.engine.generate_candidate_record(text, provenance)

        self.assertIn(ActivityCategory.EXPLOIT_DISTRIBUTION.value, rec.activity_categories)
        self.assertEqual(rec.severity, Severity.CRITICAL.value)
        self.assertIn("CVE-2024-38077", rec.cti_entities["cves"])


class TestMinHashLSHDeduplication(unittest.TestCase):
    """Tests exact SHA-256 and near-duplicate MinHash LSH detection."""

    def setUp(self):
        self.deduper = MinHashLSHDeduplicator(jaccard_threshold=0.80)

    def test_exact_and_near_duplicate_detection(self):
        rec1 = GoldRecord(
            record_id="rec_1",
            sanitized_text="SELLING LOKI 2.0 BOTNET & KEYLOGGER SOURCE CODE INCLUDING CVE-2024-38077",
            provenance={"source_id": "SRC_1", "sanitized_sha256": "hash_1"}
        )
        rec2_exact = GoldRecord(
            record_id="rec_2",
            sanitized_text="SELLING LOKI 2.0 BOTNET & KEYLOGGER SOURCE CODE INCLUDING CVE-2024-38077",
            provenance={"source_id": "SRC_2", "sanitized_sha256": "hash_1"}
        )
        rec3_near = GoldRecord(
            record_id="rec_3",
            sanitized_text="SELLING LOKI 2.0 BOTNET & KEYLOGGER SOURCE CODE INCLUDING CVE-2024-38077 BUY NOW",
            provenance={"source_id": "SRC_3", "sanitized_sha256": "hash_3"}
        )
        rec4_unique = GoldRecord(
            record_id="rec_4",
            sanitized_text="Hiring senior Python developer for privacy-focused encryption project.",
            provenance={"source_id": "SRC_4", "sanitized_sha256": "hash_4"}
        )

        canonical, stats = self.deduper.process_records([rec1, rec2_exact, rec3_near, rec4_unique])

        self.assertEqual(stats["total_input_records"], 4)
        self.assertEqual(stats["canonical_records"], 2)  # rec_1 and rec_4
        self.assertEqual(stats["exact_duplicates"], 1)  # rec2_exact
        self.assertEqual(stats["near_duplicates"], 1)   # rec3_near

        # Verify duplicate provenance on canonical rec_1
        self.assertIn("duplicate_observations", rec1.provenance)
        self.assertEqual(len(rec1.provenance["duplicate_observations"]), 2)


class TestReviewQueueManager(unittest.TestCase):
    """Tests review task export and promotion to HUMAN_VERIFIED."""

    def setUp(self):
        self.store = AnnotationStore(db_path=":memory:")
        self.manager = ReviewQueueManager(self.store)

        rec = GoldRecord(
            record_id="rec_review_1",
            sanitized_text="Selling stolen RDP access",
            provenance={"source_id": "SRC_REV_1"}
        )
        rec.annotation_metadata["annotation_tier"] = AnnotationTier.WEAK_SUPERVISION.value
        self.store.save_record(rec)

    def test_export_and_import_review_promotion(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "review_tasks.json")
            exported_count = self.manager.export_review_tasks(task_file, limit=10)
            self.assertEqual(exported_count, 1)

            # Read exported file and simulate human review input
            with open(task_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            task = data["tasks"][0]
            task["human_review_input"]["human_validation_confirmed"] = True
            task["human_review_input"]["annotator_id"] = "human_expert_42"
            task["human_review_input"]["verified_activity_categories"] = [ActivityCategory.ACCESS_BROKERAGE.value]
            task["human_review_input"]["verified_intent"] = Intent.ILLICIT_SALE.value

            with open(task_file, "w", encoding="utf-8") as f:
                json.dump(data, f)

            # Import completed review
            res = self.manager.import_completed_reviews(task_file)
            self.assertEqual(res["promoted_to_human_verified"], 1)

            promoted_rec = self.store.get_record("rec_review_1")
            self.assertEqual(promoted_rec.annotation_metadata["annotation_tier"], AnnotationTier.HUMAN_VERIFIED.value)
            self.assertEqual(promoted_rec.annotation_metadata["annotator_id"], "human_expert_42")

    def test_rejection_without_human_validation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "review_tasks.json")
            self.manager.export_review_tasks(task_file, limit=10)

            # Attempt import without setting human_validation_confirmed=True
            res = self.manager.import_completed_reviews(task_file)
            self.assertEqual(res["promoted_to_human_verified"], 0)
            self.assertEqual(res["rejected_or_skipped"], 1)


class TestQualityAuditorAndExporter(unittest.TestCase):
    """Tests QualityAuditor metrics and DatasetExporter outputs."""

    def setUp(self):
        self.store = AnnotationStore(db_path=":memory:")
        self.auditor = QualityAuditor()
        self.exporter = DatasetExporter(self.store)

        rec = GoldRecord(
            record_id="rec_exp_1",
            sanitized_text="Ransomware leak site publishing victim files.",
            provenance={"source_id": "SRC_EXP_1"},
            activity_categories=[ActivityCategory.RANSOMWARE_LEAK.value],
            intent=Intent.THREAT_EXCHANGE.value,
            severity=Severity.CRITICAL.value
        )
        self.store.save_record(rec)

    def test_quality_audit(self):
        report = self.auditor.audit_dataset(self.store)
        self.assertEqual(report["summary"]["total_records"], 1)
        self.assertEqual(report["summary"]["schema_violation_count"], 0)
        self.assertIn(ActivityCategory.RANSOMWARE_LEAK.value, report["label_distributions"]["activity_categories"])

    def test_jsonl_and_csv_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            jsonl_path = os.path.join(tmpdir, "export.jsonl")
            csv_path = os.path.join(tmpdir, "export.csv")

            jsonl_manifest = self.exporter.export_jsonl(jsonl_path)
            self.assertEqual(jsonl_manifest["record_count"], 1)
            self.assertTrue(os.path.exists(jsonl_path))
            self.assertTrue(os.path.exists(jsonl_path + ".manifest.json"))

            csv_manifest = self.exporter.export_csv(csv_path)
            self.assertEqual(csv_manifest["record_count"], 1)
            self.assertTrue(os.path.exists(csv_path))


class TestPilotRunnerIntegration(unittest.TestCase):
    """Integration test running pilot against temporary collector database."""

    def test_pilot_runner_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_collector.db")
            gold_db = os.path.join(tmpdir, "test_gold.db")
            out_dir = os.path.join(tmpdir, "processed")
            rep_dir = os.path.join(tmpdir, "reports")

            # Create dummy collector database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE verification_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT, onion_address TEXT, timestamp TEXT,
                    http_status INTEGER, response_time_ms INTEGER, state TEXT,
                    text_length INTEGER, sha256 TEXT, previous_sha256 TEXT,
                    content_changed INTEGER, error TEXT, sanitized_text TEXT
                );
            """)
            cursor.execute("""
                INSERT INTO verification_attempts (source_id, onion_address, timestamp, http_status, response_time_ms, state, text_length, sha256, sanitized_text)
                VALUES ('SRC_DEMO_01', 'http://demo.onion', '2026-09-26T12:00:00Z', 200, 100, 'CONTENT_ACCESSIBLE', 100, 'sha_1', 'Selling Loki Botnet source code.');
            """)
            conn.commit()
            conn.close()

            res = run_gold_dataset_pilot(
                collector_db_path=db_path,
                gold_db_path=gold_db,
                output_dir=out_dir,
                reports_dir=rep_dir
            )

            self.assertEqual(res["total_attempts"], 1)
            self.assertEqual(res["records_processed"], 1)
            self.assertTrue(os.path.exists(res["jsonl_export"]))
            self.assertTrue(os.path.exists(res["csv_export"]))


if __name__ == "__main__":
    unittest.main()
