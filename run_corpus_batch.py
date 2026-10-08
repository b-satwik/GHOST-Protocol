#!/usr/bin/env python3
"""
DarkWatch Real Corpus Batch Runner & Quality Audit Orchestrator.

Usage:
  python3 run_corpus_batch.py [--small-batch] [--export] [--audit-only]

Workflow:
1. Validates config/seed_sources.yaml and loads explicitly approved sources.
2. If no approved sources are configured, reports:
   "REAL CORPUS COLLECTION NOT STARTED — NO APPROVED SOURCES CONFIGURED."
3. Runs RealCorpusIngester on approved seed sources in safe/small-batch mode.
4. Executes MinHashLSH exact/near-duplicate detection and links duplicate provenance.
5. Runs WeakSupervisionEngine to generate candidate GoldRecords.
6. Executes QualityAuditor to generate comprehensive dataset health report.
7. Produces data/exports/darkwatch_gold_dataset.jsonl and .csv via DatasetExporter.
"""

import sys
import os
import json
import argparse
import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from real_corpus_ingester import RealCorpusIngester
from src.dataset.annotation_store import AnnotationStore
from src.review.quality_auditor import QualityAuditor
from src.exporter.export_runner import DatasetExporter


def run_corpus_batch(
    small_batch: bool = True,
    do_export: bool = True,
    audit_only: bool = False,
    sync_manifest: bool = False,
    seeds_path: str = "config/seed_sources.yaml",
    db_path: str = "data/collector_evidence.db",
    gold_db_path: str = "data/gold_dataset.db"
):
    print("=" * 75)
    print("DarkWatch Real Corpus Batch Runner & Dataset Quality Auditor")
    print("=" * 75)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    seeds_path = seeds_path if os.path.isabs(seeds_path) else os.path.join(base_dir, seeds_path)
    db_path = db_path if os.path.isabs(db_path) else os.path.join(base_dir, db_path)
    gold_db_path = gold_db_path if os.path.isabs(gold_db_path) else os.path.join(base_dir, gold_db_path)


    # Pre-create data and exports directories
    os.makedirs(os.path.join(base_dir, "data", "exports"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "manifests"), exist_ok=True)

    ingester = RealCorpusIngester(seeds_path=seeds_path, db_path=db_path, gold_db_path=gold_db_path)
    approved_sources = ingester.load_approved_sources()

    print(f"\n[+] Seed Source Registry Audit ({seeds_path}):")
    print(f"    • Approved Sources Configured: {len(approved_sources)}")

    if sync_manifest:
        print("\n[+] Syncing collection manifest from database state...")
        sync_res = ingester.sync_manifest_from_db()
        print(f"    -> Manifest Sync Status: {sync_res.get('status')} ({sync_res.get('attempts_count')} attempts, {sync_res.get('gold_records_count')} records)")

    if not approved_sources and not audit_only and not sync_manifest:
        msg = "REAL CORPUS COLLECTION NOT STARTED — NO APPROVED SOURCES CONFIGURED."
        print("\n" + "=" * 75)
        print(f"[!] {msg}")
        print("=" * 75)
        print("\nTo collect real corpus records:")
        print("1. Edit config/seed_sources.yaml")
        print("2. Set approved: true for research-approved target sources")
        print("3. Specify the valid onion/target URL")
        print("4. Re-run run_corpus_batch.py\n")
        
        # Run audit on any existing records to report current dataset status
        gold_store = AnnotationStore(db_path=gold_db_path)
        auditor = QualityAuditor()
        audit_res = auditor.audit_dataset(gold_store)

        print("\n[+] Current Dataset Quality Audit Summary:")
        print(json.dumps(audit_res["summary"], indent=2))
        return {
            "status": "NOT_STARTED",
            "message": msg,
            "approved_sources_count": 0,
            "audit_summary": audit_res["summary"]
        }

    if not audit_only and not sync_manifest:
        print("\n[+] Step 1: Executing Real Corpus Ingestion Batch...")
        max_records = 10 if small_batch else 150
        ingest_res = ingester.run_ingestion_batch(max_batch_records=max_records)
        print(f"    -> Ingestion Status: {ingest_res.get('status')}")

    # Run Quality Audit
    print("\n[+] Step 2: Executing Dataset Quality Audit...")
    gold_store = AnnotationStore(db_path=gold_db_path)
    auditor = QualityAuditor()
    audit_report = auditor.audit_dataset(gold_store)

    print("\n" + "=" * 75)
    print("DATASET HEALTH & QUALITY AUDIT REPORT")
    print("=" * 75)
    print(f"• Total Records:               {audit_report['summary']['total_records']}")
    print(f"• Canonical (Unique) Records:  {audit_report['summary']['canonical_records']}")
    print(f"• Duplicate Records Excluded: {audit_report['summary']['duplicate_records']}")
    print(f"• Schema Violation Count:      {audit_report['summary']['schema_violation_count']}")
    print("\n• Annotation Tier Breakdown:")
    for tier, count in audit_report["annotation_tiers"].items():
        print(f"    - {tier}: {count}")

    print("\n• Category Distribution:")
    for cat, count in audit_report["label_distributions"]["activity_categories"].items():
        print(f"    - {cat}: {count}")

    # Export dataset if requested
    export_manifests = {}
    if do_export:
        print("\n[+] Step 3: Exporting Gold Dataset Artifacts...")
        exporter = DatasetExporter(store=gold_store)
        jsonl_path = os.path.join(base_dir, "data", "exports", "darkwatch_gold_dataset.jsonl")
        csv_path = os.path.join(base_dir, "data", "exports", "darkwatch_gold_dataset.csv")

        jsonl_manifest = exporter.export_jsonl(jsonl_path, include_duplicates=False)
        csv_manifest = exporter.export_csv(csv_path, include_duplicates=False)

        print(f"    -> Exported JSONL: {jsonl_path} ({jsonl_manifest['record_count']} records)")
        print(f"    -> Exported CSV:   {csv_path} ({csv_manifest['record_count']} records)")
        export_manifests = {"jsonl": jsonl_manifest, "csv": csv_manifest}

    return {
        "status": "COMPLETED",
        "approved_sources_count": len(approved_sources),
        "audit_report": audit_report,
        "export_manifests": export_manifests
    }


def main():
    parser = argparse.ArgumentParser(description="DarkWatch Real Corpus Batch Runner & Quality Auditor")
    parser.add_argument("--full-batch", action="store_true", help="Run full-batch ingestion instead of small-batch")
    parser.add_argument("--no-export", action="store_true", help="Disable JSONL/CSV dataset export")
    parser.add_argument("--audit-only", action="store_true", help="Run quality audit without collection")
    parser.add_argument("--sync-manifest", action="store_true", help="Sync collection manifest from existing database state without re-crawling")
    parser.add_argument("--seeds-path", type=str, default="config/seed_sources.yaml", help="Path to seed_sources.yaml")
    
    args = parser.parse_args()
    
    run_corpus_batch(
        small_batch=not args.full_batch,
        do_export=not args.no_export,
        audit_only=args.audit_only,
        sync_manifest=args.sync_manifest,
        seeds_path=args.seeds_path
    )


if __name__ == "__main__":
    main()

