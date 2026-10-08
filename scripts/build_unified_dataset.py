#!/usr/bin/env python3
"""
DarkWatch Unified Text Dataset & Manifest Generator
--------------------------------------------------
Builds a unified source-aware text dataset preserving task semantics and provenance.
Generates:
1. data/unified/darkwatch_unified_text.jsonl
2. data/unified/darkwatch_unified_manifest.json
3. data/unified/xin_annotation_index.json
"""

import os
import json
import hashlib
import numpy as np
import pandas as pd
from collections import Counter, defaultdict

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset")
UNIFIED_DIR = os.path.join(DATA_DIR, "unified")
os.makedirs(UNIFIED_DIR, exist_ok=True)

def hash_text(text: str) -> str:
    if not isinstance(text, str):
        text = str(text) if text is not None else ""
    return hashlib.md5(text.strip().encode("utf-8")).hexdigest()

def process_dwdata():
    print("[1/5] Processing DWData corpus...")
    files = {
        "train": os.path.join(DATA_DIR, "processed", "training", "text_train.csv"),
        "validation": os.path.join(DATA_DIR, "processed", "training", "text_validation.csv"),
        "test": os.path.join(DATA_DIR, "processed", "training", "text_test.csv"),
    }
    
    records = []
    split_counts = defaultdict(int)
    activity_counts = Counter()
    
    for split_name, filepath in files.items():
        if not os.path.exists(filepath):
            print(f"Warning: {filepath} not found!")
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
                "intent_label": None,
                "crime_label": None,
                "supply_chain_label": None,
                "original_category": orig_cat,
                "original_probability": None,
                "original_split": split_name,
            }
            records.append(rec)
            split_counts[split_name] += 1
            if sec_target:
                activity_counts[sec_target] += 1
                
    print(f"  DWData total: {len(records)} records (train={split_counts['train']}, val={split_counts['validation']}, test={split_counts['test']})")
    return records, dict(split_counts), dict(activity_counts)

def process_cyseced_dark():
    print("[2/5] Processing CySecED Dark corpus...")
    filepath = os.path.join(DATASET_DIR, "Labeled Dataset of Cybersecurity Events from Dark", "base_dark_final.csv")
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found!")
        return [], {}, {}
    
    df = pd.read_csv(filepath)
    np.random.seed(42)
    shuffled_indices = np.random.permutation(len(df))
    
    n_total = len(df)
    n_train = int(n_total * 0.70)
    n_val = int(n_total * 0.15)
    
    split_assignment = {}
    for idx_pos, df_idx in enumerate(shuffled_indices):
        if idx_pos < n_train:
            split_assignment[df_idx] = "train"
        elif idx_pos < n_train + n_val:
            split_assignment[df_idx] = "validation"
        else:
            split_assignment[df_idx] = "test"
            
    records = []
    split_counts = defaultdict(int)
    event_counts = Counter()
    
    for idx, row in df.iterrows():
        txt = str(row["full_text"]) if pd.notna(row["full_text"]) else ""
        title = str(row["title"]) if pd.notna(row["title"]) else None
        cat = str(row["category"]) if pd.notna(row["category"]) else None
        created_at = str(row["created_at"]) if pd.notna(row["created_at"]) else None
        prob = str(row["probability"]) if pd.notna(row["probability"]) else None
        rec_id = f"cyseced_dark_{row['id']}_{idx}" if pd.notna(row["id"]) else f"cyseced_dark_idx_{idx}"
        assigned_split = split_assignment[idx]
        
        rec = {
            "record_id": rec_id,
            "source_dataset": "CYSECED_DARK",
            "source_type": "DARK_WEB",
            "text": txt,
            "title": title,
            "created_at": created_at,
            "activity_label": None,
            "event_label": cat,
            "intent_label": None,
            "crime_label": None,
            "supply_chain_label": None,
            "original_category": cat,
            "original_probability": prob,
            "original_split": assigned_split,
        }
        records.append(rec)
        split_counts[assigned_split] += 1
        if cat:
            event_counts[cat] += 1
            
    print(f"  CYSECED_DARK total: {len(records)} records (train={split_counts['train']}, val={split_counts['validation']}, test={split_counts['test']})")
    return records, dict(split_counts), dict(event_counts)

def process_cyseced_surface():
    print("[3/5] Processing CySecED Surface corpus...")
    filepath = os.path.join(DATASET_DIR, "Labeled Dataset of Cybersecurity Events from Dark", "base_surface_final.csv")
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found!")
        return [], {}, {}
    
    df = pd.read_csv(filepath)
    np.random.seed(42)
    shuffled_indices = np.random.permutation(len(df))
    
    n_total = len(df)
    n_train = int(n_total * 0.70)
    n_val = int(n_total * 0.15)
    
    split_assignment = {}
    for idx_pos, df_idx in enumerate(shuffled_indices):
        if idx_pos < n_train:
            split_assignment[df_idx] = "train"
        elif idx_pos < n_train + n_val:
            split_assignment[df_idx] = "validation"
        else:
            split_assignment[df_idx] = "test"
            
    records = []
    split_counts = defaultdict(int)
    event_counts = Counter()
    
    for idx, row in df.iterrows():
        txt = str(row["full_text"]) if pd.notna(row["full_text"]) else ""
        title = str(row["title"]) if pd.notna(row["title"]) else None
        cat = str(row["category"]) if pd.notna(row["category"]) else None
        created_at = str(row["created_at"]) if pd.notna(row["created_at"]) else None
        prob = str(row["probability"]) if pd.notna(row["probability"]) else None
        rec_id = f"cyseced_surf_{row['id']}_{idx}" if pd.notna(row["id"]) else f"cyseced_surf_idx_{idx}"
        assigned_split = split_assignment[idx]
        
        rec = {
            "record_id": rec_id,
            "source_dataset": "CYSECED_SURFACE",
            "source_type": "SURFACE_WEB",
            "text": txt,
            "title": title,
            "created_at": created_at,
            "activity_label": None,
            "event_label": cat,
            "intent_label": None,
            "crime_label": None,
            "supply_chain_label": None,
            "original_category": cat,
            "original_probability": prob,
            "original_split": assigned_split,
        }
        records.append(rec)
        split_counts[assigned_split] += 1
        if cat:
            event_counts[cat] += 1
            
    print(f"  CYSECED_SURFACE total: {len(records)} records (train={split_counts['train']}, val={split_counts['validation']}, test={split_counts['test']})")
    return records, dict(split_counts), dict(event_counts)

def process_xin():
    print("[4/5] Indexing XIN annotation dataset...")
    xin_file = os.path.join(DATASET_DIR, "Dataset_labels.json")
    index_file = os.path.join(UNIFIED_DIR, "xin_annotation_index.json")
    
    if not os.path.exists(xin_file):
        print(f"Warning: XIN file {xin_file} not found!")
        return 0, {}
        
    with open(xin_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    post_type_counts = Counter()
    author_intent_counts = Counter()
    crime_type_counts = Counter()
    supply_chain_counts = Counter()
    
    indexed_data = {}
    for idx, item in enumerate(data):
        pid = str(item.get("post_id", idx))
        p_types = item.get("post_type", [])
        intents = item.get("author_intent", [])
        crimes = item.get("crime_type", [])
        sc_cat = item.get("supply_chain_category", "Other")
        
        indexed_data[pid] = {
            "post_type": p_types,
            "author_intent": intents,
            "crime_type": crimes,
            "supply_chain_category": sc_cat,
        }
        
        for pt in p_types:
            post_type_counts[pt] += 1
        for ai in intents:
            author_intent_counts[ai] += 1
        for ct in crimes:
            crime_type_counts[ct] += 1
        supply_chain_counts[sc_cat] += 1
        
    xin_summary = {
        "status": "TEXT_UNAVAILABLE",
        "total_annotation_records": len(data),
        "post_type_distribution": dict(post_type_counts),
        "author_intent_distribution": dict(author_intent_counts),
        "crime_type_distribution": dict(crime_type_counts),
        "supply_chain_distribution": dict(supply_chain_counts),
        "note": "XIN contains rich CTI annotations (post_type, author_intent, crime_type, supply_chain_category) but post text is absent in this release. Indexed as auxiliary metadata."
    }
    
    with open(index_file, "w", encoding="utf-8") as f:
        json.dump(xin_summary, f, indent=2)
        
    print(f"  XIN indexed: {len(data)} records saved summary to {index_file}")
    return len(data), xin_summary

def analyze_deduplication(all_records):
    print("[5/5] Analyzing text deduplication and cross-split leakage...")
    text_to_splits = defaultdict(set)
    text_to_sources = defaultdict(set)
    text_to_ids = defaultdict(list)
    
    for r in all_records:
        h = hash_text(r["text"])
        text_to_splits[h].add(r["original_split"])
        text_to_sources[h].add(r["source_dataset"])
        text_to_ids[h].append(r["record_id"])
        
    total_records = len(all_records)
    unique_texts = len(text_to_splits)
    exact_duplicates = total_records - unique_texts
    
    train_val_overlap = 0
    train_test_overlap = 0
    val_test_overlap = 0
    cross_source_overlap = 0
    
    for h, splits in text_to_splits.items():
        if "train" in splits and "validation" in splits:
            train_val_overlap += 1
        if "train" in splits and "test" in splits:
            train_test_overlap += 1
        if "validation" in splits and "test" in splits:
            val_test_overlap += 1
            
    for h, sources in text_to_sources.items():
        if len(sources) > 1:
            cross_source_overlap += 1
            
    dedup_stats = {
        "total_records": total_records,
        "unique_texts": unique_texts,
        "exact_duplicate_texts": exact_duplicates,
        "train_val_text_overlap": train_val_overlap,
        "train_test_text_overlap": train_test_overlap,
        "val_test_text_overlap": val_test_overlap,
        "cross_source_text_overlap": cross_source_overlap,
    }
    print(f"  Deduplication Summary:")
    print(f"    Total Records: {total_records}")
    print(f"    Unique Texts: {unique_texts}")
    print(f"    Exact Duplicates: {exact_duplicates}")
    print(f"    Train-Val Overlap: {train_val_overlap}")
    print(f"    Train-Test Overlap: {train_test_overlap}")
    print(f"    Cross-Source Overlap: {cross_source_overlap}")
    
    return dedup_stats

def main():
    dw_recs, dw_splits, dw_activities = process_dwdata()
    dark_recs, dark_splits, dark_events = process_cyseced_dark()
    surf_recs, surf_splits, surf_events = process_cyseced_surface()
    
    all_records = dw_recs + dark_recs + surf_recs
    
    # Save unified jsonl
    jsonl_path = os.path.join(UNIFIED_DIR, "darkwatch_unified_text.jsonl")
    print(f"Writing unified text dataset to {jsonl_path}...")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in all_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    xin_count, xin_summary = process_xin()
    dedup_stats = analyze_deduplication(all_records)
    
    manifest = {
        "dataset_name": "DarkWatch Unified Text Intelligence Corpus",
        "version": "1.0.0",
        "total_text_records": len(all_records),
        "source_record_counts": {
            "DWData": len(dw_recs),
            "CYSECED_DARK": len(dark_recs),
            "CYSECED_SURFACE": len(surf_recs)
        },
        "split_counts": {
            "train": sum(r["original_split"] == "train" for r in all_records),
            "validation": sum(r["original_split"] == "validation" for r in all_records),
            "test": sum(r["original_split"] == "test" for r in all_records)
        },
        "task_semantics": {
            "DWData_activity_classes": len(dw_activities),
            "CYSECED_DARK_event_classes": len(dark_events),
            "CYSECED_SURFACE_event_classes": len(surf_events)
        },
        "deduplication_analysis": dedup_stats,
        "auxiliary_datasets": {
            "XIN_annotations": {
                "records": xin_count,
                "text_available": False,
                "index_file": "data/unified/xin_annotation_index.json"
            },
            "safe_corpus": {
                "records": 201,
                "posts_field": "empty array []",
                "text_available": False,
                "action": "Excluded from text model training"
            }
        },
        "DWData_activity_distribution": dw_activities,
        "CYSECED_DARK_event_distribution": dark_events,
    }
    
    manifest_path = os.path.join(UNIFIED_DIR, "darkwatch_unified_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        
    print(f"Successfully generated darkwatch_unified_manifest.json at {manifest_path}")

if __name__ == "__main__":
    main()
