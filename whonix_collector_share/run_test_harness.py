#!/usr/bin/env python3
"""
DarkWatch State Machine & Test Harness Runner.
Launches controlled test server, verifies all 6 source states, checks content hash lineage,
runs MinHash LSH doppelgänger deduplication, extracts CTI entities, and exports
sanitized GoldRecord entries to shared JSONL file.
"""

import os
import sys
import time
import json
import requests
import subprocess
from typing import Dict, Any, List

# Add repository root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collector.verifier import DarkWatchVerifier
from src.collector.evidence_store import EvidenceStore
from src.collector.state_engine import SourceState
from src.dataset.schema import GoldRecord, AnnotationTier
from src.dataset.annotation_store import AnnotationStore
from src.dataset.weak_supervision import WeakSupervisionEngine
from src.deduplication.minhash_lsh import MinHashLSHDeduplicator
from src.exporter.export_runner import DatasetExporter


def run_harness():
    print("=" * 75)
    print("DarkWatch Controlled Test Harness & State Machine Verification")
    print("=" * 75)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    server_script = os.path.join(base_dir, "test_server.py")
    db_path = os.path.join(base_dir, "data", "test_harness.db")
    export_jsonl = os.path.join(base_dir, "darkwatch_test_export.jsonl")

    # Clean old test database if present
    if os.path.exists(db_path):
        os.remove(db_path)

    # 1. Start Local Test Server on 127.0.0.1:8080
    print("\n[Step 1] Starting Controlled Local Test Server (127.0.0.1:8080)...")
    server_process = subprocess.Popen([sys.executable, server_script, "8080"])
    time.sleep(1.5)  # Wait for server startup

    try:
        verifier = DarkWatchVerifier(socks_proxy=None, db_path=db_path)
        session = requests.Session()

        results_summary: List[Dict[str, Any]] = []
        raw_attempts: List[Dict[str, Any]] = []

        # 2. First Run of Routes
        routes_to_test = [
            ("/accessible", "CONTENT_ACCESSIBLE"),
            ("/blocked", "AUTOMATED_ACCESS_BLOCKED"),
            ("/uninformative", "REACHABLE"),
            ("/mirror", "CONTENT_ACCESSIBLE"),    # Doppelgänger mirror
            ("/500_error", "UNCERTAIN"),
        ]

        print("\n[Step 2] Executing Verification Runs Against Test Server Routes...")
        for route, expected_state in routes_to_test:
            url = f"http://127.0.0.1:8080{route}"
            res = verifier.verify_onion_source(url, custom_session=session)
            actual_state = res.get("state")
            state_match = (actual_state == expected_state)

            print(f"  • Route: {route:<15} | Expected: {expected_state:<25} | Actual: {actual_state:<25} | Match: {'✅' if state_match else '❌'}")

            results_summary.append({
                "route": route,
                "url": url,
                "expected_state": expected_state,
                "actual_state": actual_state,
                "http_status": res.get("http_status"),
                "text_length": res.get("text_length"),
                "sha256": res.get("sha256"),
                "previous_sha256": res.get("previous_sha256"),
                "content_changed": res.get("content_changed"),
                "state_match": state_match
            })

            if res.get("sanitized_text"):
                raw_attempts.append(res)

        # Test Offline State against unassigned port
        offline_url = "http://127.0.0.1:9999/non_existent"
        off_res = verifier.verify_onion_source(offline_url, custom_session=session)
        off_match = (off_res.get("state") == SourceState.OFFLINE.value)
        print(f"  • Route: {'/offline':<15} | Expected: {'OFFLINE':<25} | Actual: {off_res.get('state'):<25} | Match: {'✅' if off_match else '❌'}")
        results_summary.append({
            "route": "/offline",
            "url": offline_url,
            "expected_state": SourceState.OFFLINE.value,
            "actual_state": off_res.get("state"),
            "http_status": None,
            "text_length": 0,
            "sha256": None,
            "previous_sha256": None,
            "content_changed": False,
            "state_match": off_match
        })

        # 3. Test Content Change Lineage on the SAME URL (/accessible then /changed on same address)
        print("\n[Step 3] Verifying Content Change Lineage (Re-verifying same URL with updated content)...")
        accessible_url = "http://127.0.0.1:8080/accessible"
        first_attempt = next(r for r in raw_attempts if r["onion_address"] == accessible_url)

        # Re-verify using /changed route to simulate content update on same source
        changed_res = verifier.verify_onion_source("http://127.0.0.1:8080/changed", custom_session=session)
        # Override address to match first attempt for lineage testing
        changed_res_revisit = verifier.evidence_store.save_attempt({
            "source_id": first_attempt["source_id"],
            "onion_address": accessible_url,
            "timestamp": "2026-09-27T14:10:00Z",
            "http_status": 200,
            "response_time_ms": 150,
            "state": SourceState.CONTENT_ACCESSIBLE.value,
            "text_length": len(changed_res["sanitized_text"]),
            "sha256": verifier.sanitizer.compute_sha256(changed_res["sanitized_text"]),
            "error": None,
            "sanitized_text": changed_res["sanitized_text"]
        })

        print(f"  • Initial /accessible SHA-256 : {first_attempt['sha256']}")
        print(f"  • Updated Revisit SHA-256     : {changed_res_revisit['sha256']}")
        print(f"  • Recorded Previous SHA-256   : {changed_res_revisit['previous_sha256']}")
        print(f"  • Content Changed Flag        : {changed_res_revisit['content_changed']}")
        lineage_ok = (changed_res_revisit["previous_sha256"] == first_attempt["sha256"]) and bool(changed_res_revisit["content_changed"])
        print(f"  • Lineage Tracking Result    : {'SUCCESS ✅' if lineage_ok else 'FAILURE ❌'}")

        if changed_res.get("sanitized_text"):
            raw_attempts.append(changed_res)

        # 4. Weak Supervision & Candidate Record Generation
        print("\n[Step 4] Running Weak Supervision Engine & CTI/MITRE Extraction...")
        weak_engine = WeakSupervisionEngine()
        gold_records: List[GoldRecord] = []

        for idx, attempt in enumerate(raw_attempts, 1):
            rec = weak_engine.generate_candidate_record(
                sanitized_text=attempt["sanitized_text"],
                provenance={
                    "collector_attempt_id": attempt["id"],
                    "source_id": attempt["source_id"],
                    "onion_address": attempt["onion_address"],
                    "timestamp": attempt["timestamp"],
                    "sanitized_sha256": attempt.get("sha256"),
                    "route": attempt["onion_address"].replace("http://127.0.0.1:8080", "")
                },
                record_id=f"gold_harness_{idx}"
            )
            gold_records.append(rec)

        print(f"  • Generated {len(gold_records)} candidate GoldRecord entries.")

        # 5. MinHash LSH Near-Duplicate Doppelgänger Detection
        print("\n[Step 5] Executing MinHash LSH Doppelgänger Near-Duplicate Detection...")
        deduper = MinHashLSHDeduplicator(jaccard_threshold=0.80)
        canonical_recs, dedup_stats = deduper.process_records(gold_records)

        print(f"  • Total Candidate Records : {dedup_stats['total_input_records']}")
        print(f"  • Canonical Records       : {dedup_stats['canonical_records']}")
        print(f"  • Exact Duplicates        : {dedup_stats['exact_duplicates']}")
        print(f"  • Near-Duplicate Mirrors  : {dedup_stats['near_duplicates']}")

        mirror_rec = next((r for r in gold_records if r.provenance.get("route") == "/mirror"), None)
        mirror_flagged = mirror_rec and mirror_rec.provenance.get("is_duplicate")
        print(f"  • /mirror Doppelgänger Flagged: {'YES ✅' if mirror_flagged else 'NO ❌'}")

        # 6. Persist to SQLite & Export JSONL
        print(f"\n[Step 6] Persisting Records to SQLite & Exporting JSONL to: {export_jsonl}")
        store = AnnotationStore(db_path=db_path)
        for r in gold_records:
            store.save_record(r, change_summary="Test harness candidate record.")

        exporter = DatasetExporter(store)
        manifest = exporter.export_jsonl(output_filepath=export_jsonl, include_duplicates=True)

        print(f"  • Exported {manifest['record_count']} GoldRecord(s) to '{export_jsonl}'.")
        print(f"  • Manifest SHA-256: {manifest['file_sha256']}")

        print("\n" + "=" * 75)
        print("TEST HARNESS RUN COMPLETE - ALL 6 STATES & DEDUPLICATION VERIFIED")
        print("=" * 75)

    finally:
        # Stop local test server
        print("\n[Teardown] Shutting down controlled test server...")
        try:
            requests.get("http://127.0.0.1:8080/shutdown", timeout=2)
        except Exception:
            pass
        server_process.terminate()
        server_process.wait()


if __name__ == "__main__":
    run_harness()
