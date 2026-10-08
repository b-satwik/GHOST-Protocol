"""
Training Dataset Exporter for DarkWatch Gold Dataset Pipeline.
Exports curated GoldRecord entries to JSONL and CSV training formats.
Supports annotation-tier filtering and automatic duplicate exclusion.
"""

import json
import csv
import os
import hashlib
import datetime
from typing import Dict, Any, List, Optional
from src.dataset.annotation_store import AnnotationStore
from src.dataset.schema import GoldRecord, AnnotationTier


class DatasetExporter:
    """
    Exports Gold Dataset records for ML training pipelines.
    Enforces tier filtering, deduplication hygiene, and export manifests.
    """

    def __init__(self, store: AnnotationStore):
        self.store = store

    def export_jsonl(
        self,
        output_filepath: str,
        allowed_tiers: Optional[List[str]] = None,
        include_duplicates: bool = False
    ) -> Dict[str, Any]:
        """
        Exports records to a line-delimited JSONL file.
        """
        records = self._fetch_filtered_records(allowed_tiers, include_duplicates)

        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)

        tier_counts: Dict[str, int] = {}
        written_count = 0

        with open(output_filepath, "w", encoding="utf-8") as f:
            for rec in records:
                rec_dict = rec.to_dict()
                tier = rec.annotation_metadata.get("annotation_tier", "UNKNOWN")
                tier_counts[tier] = tier_counts.get(tier, 0) + 1

                f.write(json.dumps(rec_dict, ensure_ascii=False) + "\n")
                written_count += 1

        file_sha256 = self._compute_file_sha256(output_filepath)
        manifest_path = f"{output_filepath}.manifest.json"

        manifest = {
            "export_format": "JSONL",
            "output_file": os.path.basename(output_filepath),
            "export_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "record_count": written_count,
            "allowed_tiers": allowed_tiers or [t.value for t in AnnotationTier],
            "include_duplicates": include_duplicates,
            "tier_counts": tier_counts,
            "file_sha256": file_sha256
        }

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest

    def export_csv(
        self,
        output_filepath: str,
        allowed_tiers: Optional[List[str]] = None,
        include_duplicates: bool = False
    ) -> Dict[str, Any]:
        """
        Exports records to a tabular CSV format.
        """
        records = self._fetch_filtered_records(allowed_tiers, include_duplicates)

        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)

        fieldnames = [
            "record_id",
            "schema_version",
            "annotation_tier",
            "annotator_id",
            "confidence",
            "disputed",
            "activity_categories",
            "intent",
            "severity",
            "target_sector",
            "sanitized_text",
            "malware_entities",
            "cve_entities",
            "onion_address",
            "source_id",
            "timestamp"
        ]

        tier_counts: Dict[str, int] = {}
        written_count = 0

        with open(output_filepath, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for rec in records:
                meta = rec.annotation_metadata
                tier = meta.get("annotation_tier", "UNKNOWN")
                tier_counts[tier] = tier_counts.get(tier, 0) + 1

                entities = rec.cti_entities or {}
                malware_str = ", ".join(entities.get("malware", []))
                cves_str = ", ".join(entities.get("cves", []))

                writer.writerow({
                    "record_id": rec.record_id,
                    "schema_version": rec.schema_version,
                    "annotation_tier": tier,
                    "annotator_id": meta.get("annotator_id", ""),
                    "confidence": meta.get("confidence", 0.0),
                    "disputed": 1 if meta.get("disputed") else 0,
                    "activity_categories": "|".join(rec.activity_categories),
                    "intent": rec.intent,
                    "severity": rec.severity,
                    "target_sector": "|".join(rec.target_sector),
                    "sanitized_text": rec.sanitized_text,
                    "malware_entities": malware_str,
                    "cve_entities": cves_str,
                    "onion_address": rec.provenance.get("onion_address", ""),
                    "source_id": rec.provenance.get("source_id", ""),
                    "timestamp": rec.provenance.get("timestamp", "")
                })
                written_count += 1

        file_sha256 = self._compute_file_sha256(output_filepath)
        manifest_path = f"{output_filepath}.manifest.json"

        manifest = {
            "export_format": "CSV",
            "output_file": os.path.basename(output_filepath),
            "export_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "record_count": written_count,
            "allowed_tiers": allowed_tiers or [t.value for t in AnnotationTier],
            "include_duplicates": include_duplicates,
            "tier_counts": tier_counts,
            "file_sha256": file_sha256
        }

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest

    def _fetch_filtered_records(
        self, allowed_tiers: Optional[List[str]], include_duplicates: bool
    ) -> List[GoldRecord]:
        all_records = self.store.get_all_records(include_duplicates=include_duplicates)

        if not allowed_tiers:
            return all_records

        allowed_set = set(allowed_tiers)
        return [
            r for r in all_records
            if r.annotation_metadata.get("annotation_tier") in allowed_set
        ]

    @staticmethod
    def _compute_file_sha256(filepath: str) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
