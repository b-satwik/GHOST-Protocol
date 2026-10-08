#!/usr/bin/env python3
"""
Host Ingestion & Dataset Quality Audit Script for DarkWatch.
Reads sanitized GoldRecord JSONL export from the shared folder, ingests records
into host AnnotationStore (data/gold_dataset.db), and runs QualityAuditor checks.
"""

import os
import sys
import json
from typing import Dict, Any, List

from src.dataset.schema import GoldRecord, AnnotationTier
from src.dataset.annotation_store import AnnotationStore
from src.review.quality_auditor import QualityAuditor


def ingest_and_audit(
    jsonl_filepath: str = "whonix_collector_share/darkwatch_test_export.jsonl",
    host_db_path: str = "data/gold_dataset.db"
) -> Dict[str, Any]:
    """
    Ingests GoldRecord JSONL export from shared folder into host SQLite database
    and performs a comprehensive quality audit.
    """
    print("=" * 75)
    print("DarkWatch Host Dataset Ingestion & Quality Audit")
    print("=" * 75)

    if not os.path.exists(jsonl_filepath):
        # Fallback check for darkwatch_imports/ directory if mapped differently
        fallback = os.path.join(os.path.expanduser("~"), "darkwatch_imports", "darkwatch_test_export.jsonl")
        if os.path.exists(fallback):
            jsonl_filepath = fallback
        else:
            raise FileNotFoundError(f"Export file not found at '{jsonl_filepath}' or '{fallback}'")

    print(f"\n[Step 1] Reading GoldRecord JSONL export file: {jsonl_filepath}")
    records: List[GoldRecord] = []
    with open(jsonl_filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line_str = line.strip()
            if line_str:
                data = json.loads(line_str)
                rec = GoldRecord.from_dict(data)
                records.append(rec)

    print(f"Total exported GoldRecords read from JSONL: {len(records)}")

    # Ingest into Host AnnotationStore
    print(f"\n[Step 2] Ingesting GoldRecords into Host AnnotationStore ({host_db_path})...")
    host_store = AnnotationStore(db_path=host_db_path)
    ingested_count = 0
    for rec in records:
        if host_store.save_record(rec, change_summary="Host ingestion from Workstation JSONL export."):
            ingested_count += 1

    print(f"Successfully ingested/updated {ingested_count} record(s) in host database.")

    # Execute Quality Audit
    print("\n[Step 3] Running Dataset Quality Auditor...")
    auditor = QualityAuditor()
    audit_report = auditor.audit_dataset(host_store)

    # Display Pretty Audit Summary Tables
    print("\n" + "=" * 75)
    print("HOST DATASET QUALITY AUDIT REPORT")
    print("=" * 75)

    summary = audit_report["summary"]
    print(f"• Total Records in Host DB : {summary['total_records']}")
    print(f"• Canonical Records        : {summary['canonical_records']}")
    print(f"• Duplicate Records        : {summary['duplicate_records']}")
    print(f"• Schema Violations        : {summary['schema_violation_count']}")

    print("\n--- ANNOTATION TIER BREAKDOWN ---")
    for tier, count in audit_report["annotation_tiers"].items():
        print(f"  - {tier:<20} : {count} record(s)")

    print("\n--- CATEGORICAL LABEL DISTRIBUTIONS ---")
    dist = audit_report["label_distributions"]
    print("  • Activity Categories:")
    for cat, count in dist["activity_categories"].items():
        print(f"     * {cat:<25} : {count}")

    print("  • Intent:")
    for intent, count in dist["intent"].items():
        print(f"     * {intent:<25} : {count}")

    print("  • Severity:")
    for sev, count in dist["severity"].items():
        print(f"     * {sev:<25} : {count}")

    print("\n--- CTI ENTITY & MITRE ATT&CK SUMMARY (SAMPLE RECORD) ---")
    if records:
        sample = records[0]
        entities = sample.cti_entities or {}
        print(f"  • Sample Record ID  : {sample.record_id}")
        print(f"  • Extracted Malware : {entities.get('malware', [])}")
        print(f"  • Extracted CVEs    : {entities.get('cves', [])}")
        print(f"  • IoC IP Addresses  : {entities.get('iocs', {}).get('ip_addresses', [])}")
        print(f"  • IoC .onion Domains: {entities.get('iocs', {}).get('onion_domains', [])}")
        print(f"  • MITRE Techniques : {[m.get('technique_id') for m in sample.mitre_mappings]}")

    print("\n" + "=" * 75)
    print("HOST INGESTION & QUALITY AUDIT COMPLETE: SUCCESS ✅")
    print("=" * 75)

    return audit_report


if __name__ == "__main__":
    ingest_and_audit()
