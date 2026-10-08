"""
MinHash & LSH Deduplication Engine for DarkWatch Gold Dataset Pipeline.
Provides exact SHA-256 duplicate detection and near-duplicate detection via MinHash/LSH.
Preserves complete duplicate provenance and links duplicate records to canonical entries.
"""

import hashlib
import re
from typing import Dict, Any, List, Set, Tuple, Optional
from src.dataset.schema import GoldRecord


class MinHashLSHDeduplicator:
    """
    Deduplication engine implementing:
    1. Exact SHA-256 text hash matching
    2. MinHash & Locality-Sensitive Hashing (LSH) for near-duplicate text detection
    3. Complete provenance preservation across duplicate observations
    """

    def __init__(
        self,
        num_perm: int = 64,
        num_bands: int = 16,
        jaccard_threshold: float = 0.85,
        shingle_size: int = 4
    ):
        """
        Args:
            num_perm (int): Number of MinHash permutations (hash functions)
            num_bands (int): Number of LSH bands (num_perm = num_bands * rows_per_band)
            jaccard_threshold (float): Jaccard similarity threshold for near-duplicates
            shingle_size (int): Size of word or character shingles
        """
        self.num_perm = num_perm
        self.num_bands = num_bands
        self.rows_per_band = num_perm // num_bands
        self.jaccard_threshold = jaccard_threshold
        self.shingle_size = shingle_size

        # Hash seeds for MinHash permutations
        self._hash_seeds = [
            (i * 10007 + 3, i * 19997 + 17) for i in range(self.num_perm)
        ]
        self._prime = 4294967311  # Large prime

        # Index structures
        self.exact_sha256_index: Dict[str, str] = {}  # sha256 -> canonical_record_id
        self.records_by_id: Dict[str, GoldRecord] = {}
        self.shingles_by_id: Dict[str, Set[str]] = {}
        self.lsh_buckets: Dict[Tuple[int, str], List[str]] = {}  # (band_idx, band_hash) -> record_ids

    def _extract_shingles(self, text: str) -> Set[str]:
        """Extract character k-shingles from normalized text."""
        cleaned = re.sub(r'\s+', ' ', text.lower().strip())
        if len(cleaned) < self.shingle_size:
            return {cleaned} if cleaned else set()
        shingles = set()
        for i in range(len(cleaned) - self.shingle_size + 1):
            shingles.add(cleaned[i:i + self.shingle_size])
        return shingles

    def _compute_minhash(self, shingles: Set[str]) -> List[int]:
        """Computes MinHash signature vector for a set of shingles."""
        if not shingles:
            return [0] * self.num_perm

        signature = []
        # Precompute string hashes for shingles
        shingle_hashes = [int(hashlib.md5(s.encode('utf-8')).hexdigest()[:8], 16) for s in shingles]

        for a, b in self._hash_seeds:
            min_val = min((a * h + b) % self._prime for h in shingle_hashes)
            signature.append(min_val)

        return signature

    @staticmethod
    def _jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
        """Calculates exact Jaccard similarity between two shingle sets."""
        if not set_a and not set_b:
            return 1.0
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return intersection / float(union)

    def process_records(self, records: List[GoldRecord]) -> Tuple[List[GoldRecord], Dict[str, Any]]:
        """
        Deduplicates a list of GoldRecords.
        Returns (deduplicated_canonical_records, deduplication_stats).
        """
        exact_duplicates_found = 0
        near_duplicates_found = 0
        canonical_records: List[GoldRecord] = []

        for record in records:
            text = record.sanitized_text or ""
            text_sha256 = record.provenance.get("sanitized_sha256") or hashlib.sha256(text.encode('utf-8')).hexdigest()
            record.provenance["sanitized_sha256"] = text_sha256

            # 1. Exact Duplicate Check
            if text_sha256 in self.exact_sha256_index:
                exact_duplicates_found += 1
                canonical_id = self.exact_sha256_index[text_sha256]
                canonical_rec = self.records_by_id[canonical_id]

                # Update provenance in canonical record
                self._add_duplicate_provenance(
                    canonical_rec, record, is_exact=True, similarity=1.0
                )
                # Link duplicate record
                record.provenance["duplicate_of"] = canonical_id
                record.provenance["is_duplicate"] = True
                continue

            # 2. Near-Duplicate Check via MinHash LSH
            shingles = self._extract_shingles(text)
            minhash_sig = self._compute_minhash(shingles)

            candidate_ids: Set[str] = set()
            for band_idx in range(self.num_bands):
                start = band_idx * self.rows_per_band
                end = start + self.rows_per_band
                band_key = hashlib.md5(str(minhash_sig[start:end]).encode('utf-8')).hexdigest()
                bucket = (band_idx, band_key)
                if bucket in self.lsh_buckets:
                    candidate_ids.update(self.lsh_buckets[bucket])

            near_duplicate_canonical_id: Optional[str] = None
            highest_sim = 0.0

            for cand_id in candidate_ids:
                cand_shingles = self.shingles_by_id.get(cand_id, set())
                sim = self._jaccard_similarity(shingles, cand_shingles)
                if sim >= self.jaccard_threshold and sim > highest_sim:
                    highest_sim = sim
                    near_duplicate_canonical_id = cand_id

            if near_duplicate_canonical_id:
                near_duplicates_found += 1
                canonical_rec = self.records_by_id[near_duplicate_canonical_id]
                self._add_duplicate_provenance(
                    canonical_rec, record, is_exact=False, similarity=highest_sim
                )
                record.provenance["duplicate_of"] = near_duplicate_canonical_id
                record.provenance["is_duplicate"] = True
                continue

            # 3. If unique: Register as a canonical record
            self.exact_sha256_index[text_sha256] = record.record_id
            self.records_by_id[record.record_id] = record
            self.shingles_by_id[record.record_id] = shingles

            # Index in LSH buckets
            for band_idx in range(self.num_bands):
                start = band_idx * self.rows_per_band
                end = start + self.rows_per_band
                band_key = hashlib.md5(str(minhash_sig[start:end]).encode('utf-8')).hexdigest()
                bucket = (band_idx, band_key)
                if bucket not in self.lsh_buckets:
                    self.lsh_buckets[bucket] = []
                self.lsh_buckets[bucket].append(record.record_id)

            canonical_records.append(record)

        stats = {
            "total_input_records": len(records),
            "canonical_records": len(canonical_records),
            "exact_duplicates": exact_duplicates_found,
            "near_duplicates": near_duplicates_found,
            "jaccard_threshold": self.jaccard_threshold
        }

        return canonical_records, stats

    def _add_duplicate_provenance(
        self, canonical_rec: GoldRecord, duplicate_rec: GoldRecord, is_exact: bool, similarity: float
    ) -> None:
        """Preserves complete duplicate provenance on the canonical record."""
        prov = canonical_rec.provenance
        if "duplicate_observations" not in prov:
            prov["duplicate_observations"] = []

        dup_info = {
            "record_id": duplicate_rec.record_id,
            "source_id": duplicate_rec.provenance.get("source_id"),
            "onion_address": duplicate_rec.provenance.get("onion_address"),
            "timestamp": duplicate_rec.provenance.get("timestamp"),
            "collector_attempt_id": duplicate_rec.provenance.get("collector_attempt_id"),
            "exact_match": is_exact,
            "jaccard_similarity": round(similarity, 4)
        }
        prov["duplicate_observations"].append(dup_info)
        prov["duplicate_count"] = len(prov["duplicate_observations"])
