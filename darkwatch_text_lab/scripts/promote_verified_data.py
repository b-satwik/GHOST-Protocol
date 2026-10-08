#!/usr/bin/env python3
"""
DarkWatch Text Lab - Promote Verified Data Script
-------------------------------------------------
Inspects data/future_observations/future_observations.jsonl.
Filters for records where annotation_status == 'HUMAN_VERIFIED' or 'HUMAN_CORRECTED'
and human_label is not null.
Rejects PENDING_REVIEW, DISPUTED, and REJECTED.
"""

import os
import json
import hashlib

def get_lab_dirs(base_dir=None):
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "base": base_dir,
        "future": os.path.join(base_dir, "data", "future_observations")
    }

def promote_verified_observations(lab_base_dir=None):
    dirs = get_lab_dirs(lab_base_dir)
    jsonl_path = os.path.join(dirs["future"], "future_observations.jsonl")
    
    if not os.path.exists(jsonl_path):
        print(f"No future observations file found at {jsonl_path}")
        return []
        
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
                
    promoted = []
    rejected = []
    
    for r in records:
        status = r.get("annotation_status", "PENDING_REVIEW")
        h_label = r.get("human_label")
        
        if status in ["HUMAN_VERIFIED", "HUMAN_CORRECTED"] and h_label is not None:
            # Map into unified record format
            promoted_rec = {
                "record_id": r["observation_id"],
                "source_dataset": f"FUTURE_OBSERVATION_{r.get('source_id', 'LIVE')}",
                "source_type": "DARK_WEB",
                "text": r["text"],
                "title": r.get("title"),
                "created_at": r.get("timestamp"),
                "activity_label": h_label,
                "event_label": None,
                "original_category": h_label,
                "original_probability": str(r.get("model_confidence", 1.0)),
                "original_split": "train", # New verified samples are appended to train set
                "annotation_status": status,
                "is_future_observation": True
            }
            promoted.append(promoted_rec)
        else:
            rejected.append(r["observation_id"])
            
    print(f"Promoted {len(promoted)} verified/corrected observations (Rejected {len(rejected)} unverified/disputed records).")
    return promoted

def main(lab_base_dir=None):
    return promote_verified_observations(lab_base_dir)

if __name__ == "__main__":
    main()
