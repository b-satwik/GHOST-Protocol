"""
Human Review Queue Manager for DarkWatch Gold Dataset Pipeline.
Exports candidate annotation tasks for human validation and ingests completed
human review decisions to promote records to HUMAN_VERIFIED tier.

RESTRICTION: Records are promoted to HUMAN_VERIFIED tier ONLY upon ingestion
of explicit, validated human reviewer inputs.
"""

import json
import csv
import os
import datetime
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


class ReviewQueueManager:
    """
    Manages review queues, exports review task files, and imports human validations.
    """

    def __init__(self, store: AnnotationStore):
        self.store = store

    def get_review_queue(self, limit: int = 100, filter_tier: Optional[str] = None) -> List[GoldRecord]:
        """
        Retrieves candidate records requiring human review.
        Default retrieves WEAK_SUPERVISION or AUTOMATED records, or disputed records.
        """
        if filter_tier:
            return self.store.get_records_by_tier(filter_tier)[:limit]

        weak_recs = self.store.get_records_by_tier(AnnotationTier.WEAK_SUPERVISION.value)
        auto_recs = self.store.get_records_by_tier(AnnotationTier.AUTOMATED.value)
        disputed_recs = self.store.get_disputed_records()

        seen_ids = set()
        queue = []

        for rec in (disputed_recs + weak_recs + auto_recs):
            if rec.record_id not in seen_ids:
                seen_ids.add(rec.record_id)
                queue.append(rec)
                if len(queue) >= limit:
                    break

        return queue

    def export_review_tasks(
        self,
        output_filepath: str,
        limit: int = 50,
        filter_tier: Optional[str] = None
    ) -> int:
        """
        Exports candidate records to a structured JSON task file for human review.
        """
        queue = self.get_review_queue(limit=limit, filter_tier=filter_tier)
        tasks = []

        for rec in queue:
            task = {
                "record_id": rec.record_id,
                "sanitized_text": rec.sanitized_text,
                "candidate_labels": {
                    "activity_categories": rec.activity_categories,
                    "intent": rec.intent,
                    "severity": rec.severity,
                    "target_sector": rec.target_sector
                },
                "cti_entities": rec.cti_entities,
                "mitre_mappings": [
                    {
                        "technique_id": m.get("technique_id"),
                        "technique_name": m.get("technique_name"),
                        "tactic": m.get("tactic")
                    } for m in rec.mitre_mappings
                ],
                "provenance": rec.provenance,
                "human_review_input": {
                    "human_validation_confirmed": False,
                    "annotator_id": "",
                    "verified_activity_categories": rec.activity_categories,
                    "verified_intent": rec.intent,
                    "verified_severity": rec.severity,
                    "verified_target_sector": rec.target_sector,
                    "disputed": False,
                    "review_notes": ""
                }
            }
            tasks.append(task)

        os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
        with open(output_filepath, "w", encoding="utf-8") as f:
            json.dump({
                "export_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "task_count": len(tasks),
                "instructions": "Set human_validation_confirmed to true, specify annotator_id, adjust verified labels if needed, and re-import file.",
                "tasks": tasks
            }, f, indent=2, ensure_ascii=False)

        return len(tasks)

    def import_completed_reviews(self, input_filepath: str) -> Dict[str, Any]:
        """
        Ingests completed human review tasks and promotes validated records to HUMAN_VERIFIED.

        Returns:
            Dict[str, Any]: Summary of imported, promoted, and rejected review tasks.
        """
        if not os.path.exists(input_filepath):
            raise FileNotFoundError(f"Review file not found: {input_filepath}")

        with open(input_filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        tasks = data.get("tasks", [])
        promoted_count = 0
        rejected_count = 0
        errors = []

        valid_categories = {c.value for c in ActivityCategory}
        valid_intents = {i.value for i in Intent}
        valid_severities = {s.value for s in Severity}
        valid_sectors = {sec.value for sec in TargetSector}

        for task in tasks:
            rec_id = task.get("record_id")
            inp = task.get("human_review_input", {})

            confirmed = inp.get("human_validation_confirmed", False)
            annotator_id = inp.get("annotator_id", "").strip()

            if not confirmed or not annotator_id or annotator_id in ["system", "system_init", "weak_supervision_engine_v1"]:
                rejected_count += 1
                errors.append(f"Record {rec_id}: Requires human_validation_confirmed=true and a non-system human annotator_id.")
                continue

            # Validate categorical choices
            cats = inp.get("verified_activity_categories", [])
            intent = inp.get("verified_intent")
            severity = inp.get("verified_severity")
            sectors = inp.get("verified_target_sector", [])

            invalid_cats = [c for c in cats if c not in valid_categories]
            if invalid_cats:
                rejected_count += 1
                errors.append(f"Record {rec_id}: Invalid activity categories {invalid_cats}")
                continue

            if intent not in valid_intents:
                rejected_count += 1
                errors.append(f"Record {rec_id}: Invalid intent '{intent}'")
                continue

            if severity not in valid_severities:
                rejected_count += 1
                errors.append(f"Record {rec_id}: Invalid severity '{severity}'")
                continue

            invalid_sec = [s for s in sectors if s not in valid_sectors]
            if invalid_sec:
                rejected_count += 1
                errors.append(f"Record {rec_id}: Invalid target sectors {invalid_sec}")
                continue

            # Update AnnotationStore entry and promote to HUMAN_VERIFIED
            success = self.store.update_annotation(
                record_id=rec_id,
                new_tier=AnnotationTier.HUMAN_VERIFIED.value,
                annotator_id=annotator_id,
                confidence=1.0,
                activity_categories=cats,
                intent=intent,
                severity=severity,
                target_sector=sectors,
                disputed=inp.get("disputed", False),
                review_notes=inp.get("review_notes", "Human review completed."),
                change_summary=f"Human review completed by {annotator_id}. Promoted to HUMAN_VERIFIED."
            )

            if success:
                promoted_count += 1
            else:
                rejected_count += 1
                errors.append(f"Record {rec_id}: Record not found in AnnotationStore.")

        return {
            "total_tasks_in_file": len(tasks),
            "promoted_to_human_verified": promoted_count,
            "rejected_or_skipped": rejected_count,
            "errors": errors
        }
