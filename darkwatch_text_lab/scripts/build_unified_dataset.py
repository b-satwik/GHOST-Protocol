#!/usr/bin/env python3
"""
DarkWatch Text Lab - Unified Dataset Builder
--------------------------------------------
Processes raw copied datasets (DWData, CySecED Dark, CySecED Surface)
and creates a source-aware unified text dataset:
- data/unified/darkwatch_unified_text.jsonl
- data/versions/dataset_v1/dataset_v1_text.jsonl
- data/versions/dataset_v1/dataset_manifest.json
"""

import os
import json
import hashlib
import numpy as np
import pandas as pd
from collections import Counter, defaultdict

def get_lab_dirs(base_dir=None):
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "base": base_dir,
        "raw": os.path.join(base_dir, "data", "raw"),
        "unified": os.path.join(base_dir, "data", "unified"),
        "v1": os.path.join(base_dir, "data", "versions", "dataset_v1")
    }

def hash_text(text: str) -> str:
    if not isinstance(text, str):
        text = str(text) if text is not None else ""
    return hashlib.md5(text.strip().encode("utf-8")).hexdigest()

def process_dwdata(raw_dir):
    print("  Processing DWData CSVs...")
    splits = {
        "train": os.path.join(raw_dir, "text_train.csv"),
        "validation": os.path.join(raw_dir, "text_validation.csv"),
        "test": os.path.join(raw_dir, "text_test.csv")
    }
    records = []
    for split_name, filepath in splits.items():
        if not os.path.exists(filepath):
            continue
        df = pd.read_csv(filepath)
        for _, row in df.iterrows():
            txt = str(row["text"]) if pd.notna(row["text"]) else ""
            sec_target = str(row["semantic_target"]) if pd.notna(row["semantic_target"]) else None
            orig_cat = str(row["category"]) if pd.notna(row["category"]) else None
            
            rec = {
                "record_id": str(row["record_id"]),
                "source_dataset": "DWData",
                "source_type": "DARK_WEB",
                "text": txt,
                "title": None,
                "created_at": None,
                "activity_label": sec_target,
                "event_label": None,
                "original_category": orig_cat,
                "original_probability": None,
                "original_split": split_name,
                "annotation_status": "ORIGINAL_GOLD",
                "is_future_observation": False
            }
            records.append(rec)
    return records

def process_cyseced_dark(raw_dir):
    print("  Processing CySecED Dark CSV...")
    filepath = os.path.join(raw_dir, "base_dark_final.csv")
    if not os.path.exists(filepath):
        return []
    df = pd.read_csv(filepath)
    np.random.seed(42)
    shuffled = np.random.permutation(len(df))
    n_train = int(len(df) * 0.70)
    n_val = int(len(df) * 0.15)
    
    split_map = {}
    for idx_pos, df_idx in enumerate(shuffled):
        if idx_pos < n_train:
            split_map[df_idx] = "train"
        elif idx_pos < n_train + n_val:
            split_map[df_idx] = "validation"
        else:
            split_map[df_idx] = "test"
            
    records = []
    for idx, row in df.iterrows():
        txt = str(row["full_text"]) if pd.notna(row["full_text"]) else ""
        title = str(row["title"]) if pd.notna(row["title"]) else None
        cat = str(row["category"]) if pd.notna(row["category"]) else None
        created_at = str(row["created_at"]) if pd.notna(row["created_at"]) else None
        prob = str(row["probability"]) if pd.notna(row["probability"]) else None
        rec_id = f"cyseced_dark_{row['id']}_{idx}" if pd.notna(row["id"]) else f"cyseced_dark_{idx}"
        
        rec = {
            "record_id": rec_id,
            "source_dataset": "CYSECED_DARK",
            "source_type": "DARK_WEB",
            "text": txt,
            "title": title,
            "created_at": created_at,
            "activity_label": None,
            "event_label": cat,
            "original_category": cat,
            "original_probability": prob,
            "original_split": split_map[idx],
            "annotation_status": "ORIGINAL_GOLD",
            "is_future_observation": False
        }
        records.append(rec)
    return records

def process_cyseced_surface(raw_dir):
    print("  Processing CySecED Surface CSV...")
    filepath = os.path.join(raw_dir, "base_surface_final.csv")
    if not os.path.exists(filepath):
        return []
    df = pd.read_csv(filepath)
    np.random.seed(42)
    shuffled = np.random.permutation(len(df))
    n_train = int(len(df) * 0.70)
    n_val = int(len(df) * 0.15)
    
    split_map = {}
    for idx_pos, df_idx in enumerate(shuffled):
        if idx_pos < n_train:
            split_map[df_idx] = "train"
        elif idx_pos < n_train + n_val:
            split_map[df_idx] = "validation"
        else:
            split_map[df_idx] = "test"
            
    records = []
    for idx, row in df.iterrows():
        txt = str(row["full_text"]) if pd.notna(row["full_text"]) else ""
        title = str(row["title"]) if pd.notna(row["title"]) else None
        cat = str(row["category"]) if pd.notna(row["category"]) else None
        created_at = str(row["created_at"]) if pd.notna(row["created_at"]) else None
        prob = str(row["probability"]) if pd.notna(row["probability"]) else None
        rec_id = f"cyseced_surf_{row['id']}_{idx}" if pd.notna(row["id"]) else f"cyseced_surf_{idx}"
        
        rec = {
            "record_id": rec_id,
            "source_dataset": "CYSECED_SURFACE",
            "source_type": "SURFACE_WEB",
            "text": txt,
            "title": title,
            "created_at": created_at,
            "activity_label": None,
            "event_label": cat,
            "original_category": cat,
            "original_probability": prob,
            "original_split": split_map[idx],
            "annotation_status": "ORIGINAL_GOLD",
            "is_future_observation": False
        }
        records.append(rec)
    return records

def main(lab_base_dir=None):
    dirs = get_lab_dirs(lab_base_dir)
    print(f"Building Unified Dataset in {dirs['unified']}...")
    
    dw_recs = process_dwdata(dirs["raw"])
    dark_recs = process_cyseced_dark(dirs["raw"])
    surf_recs = process_cyseced_surface(dirs["raw"])
    
    all_records = dw_recs + dark_recs + surf_recs
    
    # Save unified jsonl
    unified_file = os.path.join(dirs["unified"], "darkwatch_unified_text.jsonl")
    with open(unified_file, "w", encoding="utf-8") as f:
        for r in all_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    print(f"Saved {len(all_records)} unified records to {unified_file}")
    
    # Generate Dataset V1
    os.makedirs(dirs["v1"], exist_ok=True)
    v1_file = os.path.join(dirs["v1"], "dataset_v1_text.jsonl")
    with open(v1_file, "w", encoding="utf-8") as f:
        for r in all_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    manifest_v1 = {
        "dataset_version": "dataset_v1",
        "description": "Initial benchmark training corpus composed of DWData and CySecED datasets",
        "total_records": len(all_records),
        "source_counts": {
            "DWData": len(dw_recs),
            "CYSECED_DARK": len(dark_recs),
            "CYSECED_SURFACE": len(surf_recs)
        },
        "split_counts": {
            "train": sum(r["original_split"] == "train" for r in all_records),
            "validation": sum(r["original_split"] == "validation" for r in all_records),
            "test": sum(r["original_split"] == "test" for r in all_records)
        },
        "created_from_observations": 0
    }
    
    manifest_file = os.path.join(dirs["v1"], "dataset_manifest.json")
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest_v1, f, indent=2)
        
    print(f"Created dataset_v1 at {dirs['v1']}")
    return all_records

if __name__ == "__main__":
    main()
