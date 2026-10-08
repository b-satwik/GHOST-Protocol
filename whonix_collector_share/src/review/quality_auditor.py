"""
Quality Auditor for DarkWatch Gold Dataset Pipeline.
Performs dataset health checks, label distribution analysis, schema validation,
unlinked duplicate checks, and inter-annotator agreement metrics (Cohen's Kappa).
"""

import math
from typing import Dict, Any, List, Optional
from src.dataset.annotation_store import AnnotationStore
from src.dataset.schema import (
    GoldRecord,
    AnnotationTier,
    ActivityCategory,
    Intent,
    Severity,
    TargetSector
)


class QualityAuditor:
    """
    Audits Gold Dataset health, schema compliance, label distributions,
    and agreement metrics.
    """

    def audit_dataset(self, store: AnnotationStore) -> Dict[str, Any]:
        """
        Executes complete quality audit on the provided AnnotationStore.
        """
        all_records = store.get_all_records(include_duplicates=True)
        canonical_records = store.get_all_records(include_duplicates=False)

        # 1. Tier Distribution
        tier_counts: Dict[str, int] = {}
        for r in all_records:
            tier = r.annotation_metadata.get("annotation_tier", "UNKNOWN")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        # 2. Label Distributions (on canonical records)
        category_dist: Dict[str, int] = {}
        intent_dist: Dict[str, int] = {}
        severity_dist: Dict[str, int] = {}
        sector_dist: Dict[str, int] = {}

        schema_errors: List[Dict[str, Any]] = []

        for r in canonical_records:
            # Schema Validation
            errs = r.validate()
            if errs:
                schema_errors.append({"record_id": r.record_id, "errors": errs})

            for cat in r.activity_categories:
                category_dist[cat] = category_dist.get(cat, 0) + 1

            intent_dist[r.intent] = intent_dist.get(r.intent, 0) + 1
            severity_dist[r.severity] = severity_dist.get(r.severity, 0) + 1

            for sec in r.target_sector:
                sector_dist[sec] = sector_dist.get(sec, 0) + 1

        # 3. Duplicate Analysis
        duplicate_records = [r for r in all_records if r.provenance.get("duplicate_of")]
        exact_duplicates = [r for r in duplicate_records if r.provenance.get("sanitized_sha256")]

        # 4. Inter-Annotator Agreement (Cohen's Kappa on Intent/Severity)
        agreement_metrics = self.calculate_agreement_metrics(store)

        return {
            "summary": {
                "total_records": len(all_records),
                "canonical_records": len(canonical_records),
                "duplicate_records": len(duplicate_records),
                "schema_violation_count": len(schema_errors)
            },
            "annotation_tiers": tier_counts,
            "label_distributions": {
                "activity_categories": category_dist,
                "intent": intent_dist,
                "severity": severity_dist,
                "target_sector": sector_dist
            },
            "schema_errors": schema_errors,
            "duplicates": {
                "total_duplicate_records": len(duplicate_records),
                "exact_duplicates": len(exact_duplicates)
            },
            "agreement_metrics": agreement_metrics
        }

    def calculate_agreement_metrics(self, store: AnnotationStore) -> Dict[str, Any]:
        """
        Calculates Cohen's Kappa score comparing weak supervision labels
        vs human verified labels for records that have undergone human review.
        """
        human_records = store.get_records_by_tier(AnnotationTier.HUMAN_VERIFIED.value)
        if not human_records:
            return {
                "human_verified_count": 0,
                "cohens_kappa_intent": None,
                "cohens_kappa_severity": None,
                "message": "No HUMAN_VERIFIED records available yet for agreement scoring."
            }

        paired_intents: List[tuple] = []
        paired_severities: List[tuple] = []

        for h_rec in human_records:
            history = store.get_history(h_rec.record_id)
            weak_hist = None
            for entry in history:
                if entry.get("annotation_tier") == AnnotationTier.WEAK_SUPERVISION.value:
                    weak_hist = entry
                    break

            if weak_hist and weak_hist.get("record_snapshot"):
                try:
                    import json
                    snap = json.loads(weak_hist["record_snapshot"])
                    paired_intents.append((snap.get("intent"), h_rec.intent))
                    paired_severities.append((snap.get("severity"), h_rec.severity))
                except Exception:
                    pass

        kappa_intent = self._compute_cohens_kappa(paired_intents)
        kappa_severity = self._compute_cohens_kappa(paired_severities)

        return {
            "human_verified_count": len(human_records),
            "records_with_paired_annotations": len(paired_intents),
            "cohens_kappa_intent": round(kappa_intent, 4) if kappa_intent is not None else None,
            "cohens_kappa_severity": round(kappa_severity, 4) if kappa_severity is not None else None
        }

    @staticmethod
    def _compute_cohens_kappa(pairs: List[tuple]) -> Optional[float]:
        """Calculates Cohen's Kappa score for paired categorical ratings."""
        if not pairs:
            return None

        n = len(pairs)
        labels = sorted(list({item for p in pairs for item in p if item}))
        if not labels or n == 0:
            return None

        label_to_idx = {l: i for i, l in enumerate(labels)}
        num_labels = len(labels)

        # Build confusion matrix
        matrix = [[0] * num_labels for _ in range(num_labels)]
        for r1, r2 in pairs:
            if r1 in label_to_idx and r2 in label_to_idx:
                matrix[label_to_idx[r1]][label_to_idx[r2]] += 1

        # Observed Agreement Po
        agree_count = sum(matrix[i][i] for i in range(num_labels))
        p_o = agree_count / float(n)

        # Expected Agreement Pe
        p_e = 0.0
        for i in range(num_labels):
            row_sum = sum(matrix[i][j] for j in range(num_labels))
            col_sum = sum(matrix[j][i] for j in range(num_labels))
            p_e += (row_sum / float(n)) * (col_sum / float(n))

        if p_e == 1.0:
            return 1.0

        kappa = (p_o - p_e) / (1.0 - p_e)
        return float(kappa)
