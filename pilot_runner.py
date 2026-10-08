#!/usr/bin/env python3
"""
DarkWatch Gold Dataset Pilot Runner.
Executes the Gold Dataset Pipeline directly against evidence in the actual collector SQLite database.
Performs deduplication, CTI enrichment, weak supervision labeling, storage, review queue generation,
quality auditing, and JSONL/CSV export.
"""

import os
import json
import sqlite3
import datetime
from typing import Dict, Any, List

from src.collector.sanitizer import ContentSanitizer
from src.dataset.schema import GoldRecord, SCHEMA_VERSION, AnnotationTier
from src.dataset.annotation_store import AnnotationStore
from src.dataset.weak_supervision import WeakSupervisionEngine
from src.deduplication.minhash_lsh import MinHashLSHDeduplicator
from src.review.reviewer import ReviewQueueManager
from src.review.quality_auditor import QualityAuditor
from src.exporter.export_runner import DatasetExporter


def run_gold_dataset_pilot(
    collector_db_path: str = "data/collector_evidence.db",
    gold_db_path: str = "data/gold_dataset.db",
    output_dir: str = "data/processed",
    reports_dir: str = "reports"
) -> Dict[str, Any]:
    """
    Executes end-to-end Gold Dataset pilot pipeline on actual collector evidence.
    """
    print("=" * 70)
    print("DarkWatch Gold Dataset Pipeline - Pilot Runner")
    print(f"Schema Version: {SCHEMA_VERSION}")
    print("=" * 70)

    if not os.path.exists(collector_db_path):
        raise FileNotFoundError(f"Collector database not found at '{collector_db_path}'")

    # 1. Load records from actual Collector SQLite database
    print(f"\n[Step 1] Reading observations from collector database: {collector_db_path}")
    conn = sqlite3.connect(collector_db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM verification_attempts ORDER BY id ASC;")
    rows = cursor.fetchall()
    conn.close()

    total_attempts = len(rows)
    print(f"Total collector verification attempts found: {total_attempts}")

    # Check for synthetic / demo records
    demo_count = 0
    raw_records: List[Dict[str, Any]] = []
    sanitizer = ContentSanitizer()

    for r in rows:
        row_dict = dict(r)
        source_id = row_dict.get("source_id", "")
        onion_addr = row_dict.get("onion_address", "")

        is_demo = "DEMO" in source_id.upper() or "demo" in onion_addr.lower()
        if is_demo:
            demo_count += 1

        sanitized = row_dict.get("sanitized_text")
        if not sanitized and row_dict.get("state") == "CONTENT_ACCESSIBLE":
            # Sanitize raw text if needed
            sanitized, text_len, text_sha = sanitizer.sanitize_html(row_dict.get("raw_text", ""))
            row_dict["sanitized_text"] = sanitized
            row_dict["sha256"] = text_sha
        elif sanitized and not row_dict.get("sha256"):
            row_dict["sha256"] = sanitizer.compute_sha256(sanitized)

        if sanitized and len(sanitized.strip()) > 0:
            raw_records.append(row_dict)

    is_all_demo = (demo_count == total_attempts) and (total_attempts > 0)
    print(f"Records with valid sanitized text: {len(raw_records)}")
    if is_all_demo:
        print("⚠️ NOTICE: Collector database contains ONLY demo/synthetic records.")
    elif demo_count > 0:
        print(f"⚠️ NOTICE: Collector database contains {demo_count} demo/synthetic records out of {total_attempts}.")
    else:
        print("✅ Real Dark Web observations detected in collector database.")

    # 2. Build Candidate GoldRecords for Deduplication
    candidate_gold_records: List[GoldRecord] = []
    for item in raw_records:
        rec_id = f"gold_col_{item['id']}"
        provenance = {
            "collector_attempt_id": item["id"],
            "source_id": item["source_id"],
            "onion_address": item["onion_address"],
            "timestamp": item["timestamp"],
            "http_status": item.get("http_status"),
            "state": item.get("state"),
            "sanitized_sha256": item.get("sha256"),
            "is_demo_observation": "DEMO" in item["source_id"].upper()
        }
        rec = GoldRecord(
            record_id=rec_id,
            sanitized_text=item["sanitized_text"],
            provenance=provenance
        )
        candidate_gold_records.append(rec)

    # 3. Deduplication (Exact SHA-256 + MinHash LSH)
    print("\n[Step 2] Executing Exact SHA-256 and MinHash LSH Near-Duplicate Detection...")
    deduper = MinHashLSHDeduplicator(jaccard_threshold=0.85)
    canonical_candidates, dedup_stats = deduper.process_records(candidate_gold_records)
    print(f"Exact duplicates detected: {dedup_stats['exact_duplicates']}")
    print(f"Near duplicates detected:  {dedup_stats['near_duplicates']}")
    print(f"Canonical records retained: {dedup_stats['canonical_records']}")

    # 4. Weak Supervision & CTI/MITRE Enrichment
    print("\n[Step 3] Running Weak Supervision Engine & CTI/MITRE Enrichment...")
    weak_engine = WeakSupervisionEngine()
    processed_gold_records: List[GoldRecord] = []

    for cand_rec in candidate_gold_records:
        # Generate candidate annotations
        enriched_rec = weak_engine.generate_candidate_record(
            sanitized_text=cand_rec.sanitized_text,
            provenance=cand_rec.provenance,
            record_id=cand_rec.record_id
        )
        processed_gold_records.append(enriched_rec)

    # 5. SQLite Persistence Store
    print(f"\n[Step 4] Persisting Gold Records into AnnotationStore: {gold_db_path}")
    gold_store = AnnotationStore(db_path=gold_db_path)
    for rec in processed_gold_records:
        gold_store.save_record(rec, change_summary="Pilot pipeline weak supervision import.")

    store_stats = gold_store.get_record_count()
    print(f"Total stored records: {store_stats['total_records']}")
    print(f"Records by tier: {store_stats['by_tier']}")

    # 6. Review Queue Task Generation
    print("\n[Step 5] Generating Human Review Queue Tasks...")
    review_manager = ReviewQueueManager(store=gold_store)
    review_task_path = os.path.join(reports_dir, "review_tasks_pilot.json")
    tasks_exported = review_manager.export_review_tasks(output_filepath=review_task_path, limit=50)
    print(f"Exported {tasks_exported} review task(s) to '{review_task_path}'")

    # 7. Quality Audit
    print("\n[Step 6] Running Dataset Quality Auditor...")
    auditor = QualityAuditor()
    audit_report = auditor.audit_dataset(gold_store)
    audit_path = os.path.join(reports_dir, "gold_dataset_audit.json")
    os.makedirs(reports_dir, exist_ok=True)
    with open(audit_path, "w", encoding="utf-8") as f:
        json.dump(audit_report, f, indent=2)
    print(f"Quality audit report saved to '{audit_path}'")

    # 8. Training Dataset Export (JSONL & CSV)
    print("\n[Step 7] Exporting Training Datasets (excluding duplicates)...")
    exporter = DatasetExporter(store=gold_store)
    jsonl_path = os.path.join(output_dir, "gold_dataset_pilot.jsonl")
    csv_path = os.path.join(output_dir, "gold_dataset_pilot.csv")

    jsonl_manifest = exporter.export_jsonl(output_filepath=jsonl_path, include_duplicates=False)
    csv_manifest = exporter.export_csv(output_filepath=csv_path, include_duplicates=False)

    print(f"JSONL Export: {jsonl_manifest['record_count']} record(s) -> '{jsonl_path}'")
    print(f"CSV Export:   {csv_manifest['record_count']} record(s) -> '{csv_path}'")

    # Sample Record Output
    sample_rec_dict = None
    if processed_gold_records:
        sample_rec_dict = processed_gold_records[0].to_dict()

    print("\n" + "=" * 70)
    print("PILOT PIPELINE EXECUTION SUMMARY")
    print("=" * 70)
    print(f"Collector DB Used:       {os.path.abspath(collector_db_path)}")
    print(f"Is Demo/Synthetic Data:  {is_all_demo} (Demo count: {demo_count}/{total_attempts})")
    print(f"Total Attempts Processed:{total_attempts}")
    print(f"Records With Text:       {len(raw_records)}")
    print(f"Exact Duplicates:        {dedup_stats['exact_duplicates']}")
    print(f"Near Duplicates:         {dedup_stats['near_duplicates']}")
    print(f"Candidate Annotations:   {len(processed_gold_records)}")
    print(f"Requires Human Review:   {tasks_exported}")
    print(f"HUMAN_VERIFIED Count:    {store_stats['by_tier'].get(AnnotationTier.HUMAN_VERIFIED.value, 0)}")
    print(f"Exported Datasets:       JSONL: {jsonl_path} | CSV: {csv_path}")

    return {
        "collector_db": os.path.abspath(collector_db_path),
        "is_demo_data": is_all_demo,
        "total_attempts": total_attempts,
        "records_processed": len(raw_records),
        "exact_duplicates": dedup_stats['exact_duplicates'],
        "near_duplicates": dedup_stats['near_duplicates'],
        "candidate_annotations": len(processed_gold_records),
        "requires_human_review": tasks_exported,
        "human_verified_count": store_stats['by_tier'].get(AnnotationTier.HUMAN_VERIFIED.value, 0),
        "jsonl_export": jsonl_path,
        "csv_export": csv_path,
        "sample_record": sample_rec_dict
    }


if __name__ == "__main__":
    run_gold_dataset_pilot()
