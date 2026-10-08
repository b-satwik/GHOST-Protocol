#!/usr/bin/env python3
"""
DarkWatch Text Lab - Dataset Versioning Script
----------------------------------------------
Creates dataset_v2, dataset_v3, etc. by merging promoted human-verified observations
with previous version corpus while preserving held-out test splits untouched.
Generates:
- data/versions/dataset_vX/dataset_vX_text.jsonl
- data/versions/dataset_vX/dataset_manifest.json
"""

import os
import json
import time

from promote_verified_data import promote_verified_observations

def get_lab_dirs(base_dir=None):
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "base": base_dir,
        "unified": os.path.join(base_dir, "data", "unified"),
        "versions": os.path.join(base_dir, "data", "versions")
    }

def create_next_dataset_version(target_version_name=None, lab_base_dir=None):
    dirs = get_lab_dirs(lab_base_dir)
    
    # Identify existing versions
    existing_versions = sorted([d for d in os.listdir(dirs["versions"]) if os.path.isdir(os.path.join(dirs["versions"], d)) and d.startswith("dataset_v")])
    if not existing_versions:
        base_version = "dataset_v1"
        next_version = "dataset_v2"
    else:
        last_ver_num = int(existing_versions[-1].replace("dataset_v", ""))
        base_version = existing_versions[-1]
        next_version = f"dataset_v{last_ver_num + 1}"
        
    if target_version_name:
        next_version = target_version_name
        
    base_file = os.path.join(dirs["versions"], base_version, f"{base_version}_text.jsonl")
    if not os.path.exists(base_file):
        base_file = os.path.join(dirs["unified"], "darkwatch_unified_text.jsonl")
        
    print(f"Reading base version dataset from {base_file}...")
    base_records = []
    with open(base_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                base_records.append(json.loads(line))
                
    # Get promoted verified observations
    promoted_records = promote_verified_observations(lab_base_dir)
    
    if len(promoted_records) == 0:
        print(f"No new human-verified observations to promote. Skipping creation of {next_version}.")
        return base_version
        
    new_corpus = base_records + promoted_records
    
    next_ver_dir = os.path.join(dirs["versions"], next_version)
    os.makedirs(next_ver_dir, exist_ok=True)
    
    new_jsonl = os.path.join(next_ver_dir, f"{next_version}_text.jsonl")
    with open(new_jsonl, "w", encoding="utf-8") as f:
        for r in new_corpus:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    manifest = {
        "dataset_version": next_version,
        "base_version": base_version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_records": len(new_corpus),
        "base_records": len(base_records),
        "newly_promoted_records": len(promoted_records),
        "split_counts": {
            "train": sum(r["original_split"] == "train" for r in new_corpus),
            "validation": sum(r["original_split"] == "validation" for r in new_corpus),
            "test": sum(r["original_split"] == "test" for r in new_corpus)
        },
        "description": f"Continual learning release {next_version} incorporating {len(promoted_records)} human-verified observations."
    }
    
    manifest_file = os.path.join(next_ver_dir, "dataset_manifest.json")
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        
    print(f"Successfully created {next_version} at {next_ver_dir}")
    return next_version

def main(lab_base_dir=None):
    return create_next_dataset_version(lab_base_dir=lab_base_dir)

if __name__ == "__main__":
    main()
