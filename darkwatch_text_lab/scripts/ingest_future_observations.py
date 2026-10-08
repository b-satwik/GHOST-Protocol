#!/usr/bin/env python3
"""
DarkWatch Text Lab - Future Observations Ingestion Script
---------------------------------------------------------
Ingests raw unreviewed DarkWatch text observations, applies initial model inference,
and marks annotation_status = PENDING_REVIEW.
Appends to data/future_observations/future_observations.jsonl.
"""

import os
import json
import time

def get_lab_dirs(base_dir=None):
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "base": base_dir,
        "future": os.path.join(base_dir, "data", "future_observations")
    }

def ingest_observation(text, title=None, author_handle=None, source_id="CRAWLER_LIVE", model_prediction=None, model_confidence=None, lab_base_dir=None):
    dirs = get_lab_dirs(lab_base_dir)
    os.makedirs(dirs["future"], exist_ok=True)
    
    obs_id = f"obs_{int(time.time() * 1000)}"
    record = {
        "observation_id": obs_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_id": source_id,
        "author_handle": author_handle or "unknown",
        "title": title,
        "text": text,
        "model_prediction": model_prediction or "UNCLASSIFIED",
        "model_confidence": float(model_confidence) if model_confidence is not None else 0.0,
        "human_label": None,
        "annotation_status": "PENDING_REVIEW",
        "reviewer": None,
        "review_timestamp": None
    }
    
    jsonl_path = os.path.join(dirs["future"], "future_observations.jsonl")
    with open(jsonl_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        
    print(f"Ingested observation {obs_id} [PENDING_REVIEW] into {jsonl_path}")
    return record

def main(lab_base_dir=None):
    print("Simulating ingestion of dark web text observation...")
    sample_text = "FRESH RANSOMWARE LEAK LOGS FOR ACME CORP 2026 DATABASES"
    rec = ingest_observation(
        text=sample_text,
        title="ACME Leak Announcement",
        author_handle="DarkLeakz",
        source_id="ONION_LEAK_SITE",
        model_prediction="data",
        model_confidence=0.912,
        lab_base_dir=lab_base_dir
    )
    return rec

if __name__ == "__main__":
    main()
