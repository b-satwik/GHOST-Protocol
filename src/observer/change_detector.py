"""
Change Detection Module for Stage 1 Observation Layer.
Combines exact SHA-256 content hash matching and MinHash/LSH near-duplicate detection.
"""

import hashlib
from typing import Dict, Any, Tuple, Optional
from src.deduplication.minhash_lsh import MinHashLSHDeduplicator
from src.dataset.schema import GoldRecord


class ChangeDetector:
    """
    Evaluates incoming observation content against previous observations.
    Classifies changes as:
    - UNCHANGED
    - CHANGED_UNIQUE
    - CHANGED_NEAR_DUPLICATE
    """

    STATE_UNCHANGED = "UNCHANGED"
    STATE_CHANGED_UNIQUE = "CHANGED_UNIQUE"
    STATE_CHANGED_NEAR_DUPLICATE = "CHANGED_NEAR_DUPLICATE"

    def __init__(self, jaccard_threshold: float = 0.80):
        self.jaccard_threshold = jaccard_threshold
        self.deduplicator = MinHashLSHDeduplicator(jaccard_threshold=jaccard_threshold)
        self.known_raw_hashes: Dict[str, str] = {}  # source_id -> raw_sha256
        self.known_clean_hashes: Dict[str, str] = {}  # source_id -> clean_sha256

    @staticmethod
    def compute_sha256(text: str) -> str:
        """Calculates SHA-256 digest."""
        if not text:
            return hashlib.sha256(b"").hexdigest()
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def evaluate_change(
        self,
        source_id: str,
        raw_html: str,
        clean_text: str
    ) -> Tuple[str, str, str, Dict[str, Any]]:
        """
        Evaluates raw and clean text changes.
        
        Returns:
            Tuple[state, raw_sha256, clean_sha256, dedup_metadata]
        """
        raw_sha256 = self.compute_sha256(raw_html)
        clean_sha256 = self.compute_sha256(clean_text)

        # 1. Exact match check against previous run for this specific source
        prev_raw = self.known_raw_hashes.get(source_id)
        prev_clean = self.known_clean_hashes.get(source_id)

        if prev_raw == raw_sha256 and prev_clean == clean_sha256:
            return self.STATE_UNCHANGED, raw_sha256, clean_sha256, {"exact_match": True}

        # 2. Check for near-duplicates across global index using MinHash LSH
        gold_rec = GoldRecord(
            sanitized_text=clean_text,
            provenance={
                "source_id": source_id,
                "sanitized_sha256": clean_sha256
            },
            record_id=f"chk_{source_id}_{clean_sha256[:8]}"
        )

        canonical_recs, stats = self.deduplicator.process_records([gold_rec])

        # Update internal state for this source
        self.known_raw_hashes[source_id] = raw_sha256
        self.known_clean_hashes[source_id] = clean_sha256

        if gold_rec.provenance.get("is_duplicate"):
            dup_of = gold_rec.provenance.get("duplicate_of")
            return self.STATE_CHANGED_NEAR_DUPLICATE, raw_sha256, clean_sha256, {
                "exact_match": False,
                "duplicate_of": dup_of,
                "jaccard_threshold": self.jaccard_threshold
            }

        return self.STATE_CHANGED_UNIQUE, raw_sha256, clean_sha256, {
            "exact_match": False,
            "is_unique": True
        }
