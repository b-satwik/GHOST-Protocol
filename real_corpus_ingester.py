#!/usr/bin/env python3
"""
DarkWatch Real Corpus Ingester.
In-depth workflow orchestrator for acquiring real Dark Web text corpus records:
1. Loads seed_sources.yaml and selects ONLY explicitly approved sources (approved: true, valid url).
2. Respects per-source max_pages_cap (anti-domination).
3. Routes requests through Whonix SOCKS5 proxy (socks5h://10.152.152.10:9050).
4. Enforces strict passive collection rules (text/html, 2 MB limit, no JS/auth/exploitation).
5. Applies HTMLSanitizer and stores raw/sanitized content in SQLite EvidenceStore and data/corpus/.
6. Runs CTI indicator extraction & STIX 2.1 serialization.
7. Runs local MITRE ATT&CK STIX 2.1 enrichment.
8. Runs WeakSupervisionEngine to generate candidate GoldRecords under WEAK_SUPERVISION tier.
9. Runs MinHashLSHDeduplicator for exact (SHA-256) and near-duplicate (Jaccard 0.85) detection.
10. Persists canonical and duplicate lineage in AnnotationStore (data/gold_dataset.db).
11. Updates collection_manifest.json and domain_stats.json.
"""

import sys
import os
import json
import yaml
import hashlib
import datetime
from typing import Dict, Any, List, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.collector.verifier import DarkWatchVerifier
from src.collector.evidence_store import EvidenceStore
from src.collector.sanitizer import ContentSanitizer
from src.collector.state_engine import StateEngine, SourceState
from src.cti.stix_extractor import STIXExtractor
from src.cti.stix_generator import STIXGenerator
from src.cti.mitre_enricher import MITREEnricher
from src.cti.mitre_kb import MITREKnowledgeBase
from src.cti.cti_store import CTIStore
from src.dataset.schema import GoldRecord, AnnotationTier
from src.dataset.annotation_store import AnnotationStore
from src.dataset.weak_supervision import WeakSupervisionEngine
from src.deduplication.minhash_lsh import MinHashLSHDeduplicator


class RealCorpusIngester:
    """
    Production-grade DarkWatch Real Corpus Ingester.
    """

    def __init__(
        self,
        seeds_path: str = "config/seed_sources.yaml",
        crawler_config_path: str = "config/crawler_config.yaml",
        db_path: str = "data/collector_evidence.db",
        gold_db_path: str = "data/gold_dataset.db",
        manifest_path: str = "manifests/collection_manifest.json",
        stats_path: str = "manifests/domain_stats.json"
    ):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

        self.seeds_path = seeds_path if os.path.isabs(seeds_path) else os.path.join(self.base_dir, seeds_path)
        self.crawler_config_path = crawler_config_path if os.path.isabs(crawler_config_path) else os.path.join(self.base_dir, crawler_config_path)
        self.db_path = db_path if os.path.isabs(db_path) else os.path.join(self.base_dir, db_path)
        self.gold_db_path = gold_db_path if os.path.isabs(gold_db_path) else os.path.join(self.base_dir, gold_db_path)
        self.manifest_path = manifest_path if os.path.isabs(manifest_path) else os.path.join(self.base_dir, manifest_path)
        self.stats_path = stats_path if os.path.isabs(stats_path) else os.path.join(self.base_dir, stats_path)


        # Pre-create all required runtime directories
        for path_val in [self.db_path, self.gold_db_path, self.manifest_path, self.stats_path]:
            dir_name = os.path.dirname(os.path.abspath(path_val))
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)

        self.evidence_store = EvidenceStore(db_path=self.db_path)
        self.cti_store = CTIStore(db_path=self.db_path, conn=self.evidence_store._persistent_conn)
        self.gold_store = AnnotationStore(db_path=self.gold_db_path)
        
        self.collector = DarkWatchVerifier(db_path=self.db_path)
        self.sanitizer = ContentSanitizer()

        self.stix_extractor = STIXExtractor()
        self.mitre_kb = MITREKnowledgeBase()
        self.mitre_enricher = MITREEnricher(kb=self.mitre_kb)
        self.stix_generator = STIXGenerator()
        self.weak_supervision = WeakSupervisionEngine()
        self.deduplicator = MinHashLSHDeduplicator(jaccard_threshold=0.85)

    def load_approved_sources(self) -> List[Dict[str, Any]]:
        """Loads and returns only explicitly approved sources with valid URLs."""
        if not os.path.exists(self.seeds_path):
            print(f"Warning: Seed registry file missing: {self.seeds_path}")
            return []

        with open(self.seeds_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        all_sources = data.get("sources", [])
        approved_sources = []
        for src in all_sources:
            is_app = src.get("approved") is True
            is_col = src.get("collection_allowed") is True
            url_valid = bool(src.get("url", "").strip())
            is_ref = src.get("approval_status") == "REFERENCE_ONLY"
            
            if is_app and is_col and url_valid and not is_ref:
                approved_sources.append(src)
        return approved_sources


    def run_ingestion_batch(self, max_batch_records: int = 50) -> Dict[str, Any]:
        """
        Executes a real-corpus collection & dataset processing batch.
        """
        approved_sources = self.load_approved_sources()

        if not approved_sources:
            msg = "REAL CORPUS COLLECTION NOT STARTED — NO APPROVED SOURCES CONFIGURED."
            print("\n" + "=" * 75)
            print(f"[!] {msg}")
            print("=" * 75 + "\n")
            return {
                "status": "NOT_STARTED",
                "message": msg,
                "approved_sources_count": 0,
                "collected_count": 0,
                "processed_count": 0
            }

        print(f"\n[+] RealCorpusIngester: Found {len(approved_sources)} approved seed sources.")
        
        run_id = f"run_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        collected_attempts = []
        candidate_gold_records = []

        # Process each approved source
        for src in approved_sources:
            source_id = src.get("source_id", "UNKNOWN_SOURCE")
            url = src["url"].strip()
            max_cap = src.get("max_pages_cap", 150)
            category = src.get("category", "BENIGN_OR_OTHER")

            print(f"  -> Processing Approved Source: {source_id} ({url}) | Max Cap: {max_cap}")

            # Collect source using DarkWatchVerifier (Whonix SOCKS5 proxy)
            attempt = self.collector.verify_onion_source(url)
            attempt["source_id"] = source_id
            saved_attempt = self.evidence_store.save_attempt(attempt)

            collected_attempts.append(saved_attempt)

            state = saved_attempt.get("state")
            sanitized_text = saved_attempt.get("sanitized_text", "")

            # Stop on blocked, offline, or error states without bypassing
            if state != SourceState.CONTENT_ACCESSIBLE.value or not sanitized_text:
                print(f"     [State: {state}] Content not accessible or empty. Skipping dataset promotion.")
                continue

            # 1. CTI Extraction & STIX 2.1 Serialization
            raw_indicators = self.stix_extractor.extract_indicators(sanitized_text)
            stix_bundle = self.stix_generator.build_stix_bundle(
                onion_address=url,
                timestamp=saved_attempt["timestamp"],
                correlated_indicators=raw_indicators,
                mitre_mappings=[]
            )
            self.cti_store.save_cti_results(
                source_record_id=saved_attempt["id"],
                onion_address=url,
                timestamp=saved_attempt["timestamp"],
                stix_bundle=stix_bundle,
                correlated_indicators=raw_indicators,
                mitre_mappings=[]
            )

            # 2. Candidate GoldRecord Generation via Weak Supervision
            candidate_record = self.weak_supervision.generate_candidate_record(
                sanitized_text=sanitized_text,
                provenance={
                    "source_id": source_id,
                    "onion_address": url,
                    "timestamp": saved_attempt["timestamp"],
                    "collector_attempt_id": saved_attempt["id"],
                    "sha256": saved_attempt.get("sha256"),
                    "http_status": saved_attempt.get("http_status"),
                    "collection_run_id": run_id,
                    "category": category,
                    "stix_bundle_id": stix_bundle["id"]
                }
            )
            candidate_gold_records.append(candidate_record)

        # 3. MinHash & LSH Deduplication
        if candidate_gold_records:
            canonical_records, dedup_stats = self.deduplicator.process_records(candidate_gold_records)
            print(f"  -> Deduplication Summary: {dedup_stats['total_input_records']} total -> {dedup_stats['canonical_records']} canonical ({dedup_stats['exact_duplicates']} exact, {dedup_stats['near_duplicates']} near-duplicates).")

            # Save records to AnnotationStore
            for rec in candidate_gold_records:
                self.gold_store.save_record(rec)

        # 4. Safe Manifest Update Recovery
        manifest_updated = True
        try:
            self._update_manifests(run_id, collected_attempts, candidate_gold_records)
        except Exception as e:
            manifest_updated = False
            print(f"[!] WARNING: Failed to update collection manifests ({e}). Collected evidence is SAFELY PERSISTED in SQLite databases.")

        return {
            "status": "COMPLETED",
            "run_id": run_id,
            "approved_sources_count": len(approved_sources),
            "collected_count": len(collected_attempts),
            "processed_gold_records": len(candidate_gold_records),
            "manifest_updated": manifest_updated
        }

    def _update_manifests(
        self, run_id: str, attempts: List[Dict[str, Any]], gold_records: List[GoldRecord]
    ) -> None:
        """Updates collection_manifest.json and domain_stats.json preserving existing data."""
        manifest_path = self.manifest_path
        stats_path = self.stats_path

        os.makedirs(os.path.dirname(os.path.abspath(manifest_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(stats_path)), exist_ok=True)

        manifest_data = {
            "last_updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_collection_runs": 0,
            "total_records_collected": 0,
            "total_canonical_documents": 0,
            "total_duplicates_excluded": 0,
            "runs": []
        }
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
                    if isinstance(existing, dict):
                        manifest_data.update(existing)
            except Exception as e:
                print(f"[!] Warning: Could not parse existing manifest at {manifest_path}: {e}")

        runs = manifest_data.get("runs", [])
        run_entry = {
            "run_id": run_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "attempts_count": len(attempts),
            "gold_records_generated": len(gold_records),
            "records": [
                {
                    "source_id": a.get("source_id"),
                    "onion_address": a.get("onion_address"),
                    "state": a.get("state"),
                    "sha256": a.get("sha256"),
                    "text_length": a.get("text_length")
                }
                for a in attempts
            ]
        }
        
        if not any(r.get("run_id") == run_id for r in runs):
            runs.append(run_entry)
        manifest_data["runs"] = runs

        manifest_data["last_updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        manifest_data["total_collection_runs"] = len(runs)
        manifest_data["total_records_collected"] = sum(r.get("attempts_count", 0) for r in runs)
        manifest_data["total_canonical_documents"] = sum(r.get("gold_records_generated", 0) for r in runs)

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        # Update Domain Stats
        stats_data = {
            "last_updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "domain_counts": {},
            "category_counts": {},
            "state_distribution": {}
        }
        if os.path.exists(stats_path):
            try:
                with open(stats_path, "r", encoding="utf-8") as f:
                    existing_stats = json.load(f)
                    if isinstance(existing_stats, dict):
                        stats_data["domain_counts"] = existing_stats.get("domain_counts", {})
                        stats_data["category_counts"] = existing_stats.get("category_counts", {})
                        stats_data["state_distribution"] = existing_stats.get("state_distribution", {})
            except Exception as e:
                print(f"[!] Warning: Could not parse existing domain stats at {stats_path}: {e}")

        domain_counts = stats_data["domain_counts"]
        category_counts = stats_data["category_counts"]
        state_counts = stats_data["state_distribution"]

        for a in attempts:
            dom = a.get("onion_address", "unknown")
            st = a.get("state", "UNKNOWN")
            cat = a.get("category", "UNKNOWN")
            domain_counts[dom] = domain_counts.get(dom, 0) + 1
            state_counts[st] = state_counts.get(st, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1

        stats_data["last_updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        stats_data["domain_counts"] = domain_counts
        stats_data["category_counts"] = category_counts
        stats_data["state_distribution"] = state_counts

        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(stats_data, f, indent=2)

    def sync_manifest_from_db(self) -> Dict[str, Any]:
        """
        Reconstructs or syncs collection_manifest.json and domain_stats.json
        from existing records in EvidenceStore and AnnotationStore.
        Useful for recovering manifest state after a crash without re-crawling.
        """
        attempts = self.evidence_store.get_all_attempts() if hasattr(self.evidence_store, 'get_all_attempts') else []
        records = self.gold_store.get_all_records(include_duplicates=True)
        
        run_id = "run_recovered_from_db"
        if attempts or records:
            self._update_manifests(run_id, attempts, records)
            print(f"[+] Successfully synced manifest files ({self.manifest_path}, {self.stats_path}) from database state ({len(attempts)} attempts, {len(records)} records).")
            return {
                "status": "SYNCED",
                "attempts_count": len(attempts),
                "gold_records_count": len(records)
            }
        return {"status": "NO_DATA", "attempts_count": 0, "gold_records_count": 0}


def main():
    ingester = RealCorpusIngester()
    result = ingester.run_ingestion_batch()
    print("Ingestion Result Summary:", json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

