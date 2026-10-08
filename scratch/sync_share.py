#!/usr/bin/env python3
import os
import shutil
import yaml
import json

ROOT = "/home/balasatwik/Downloads/darkwatch (2)/darkwatch"
SHARE = os.path.join(ROOT, "whonix_collector_share")

print(f"[+] Syncing DarkWatch collector package to {SHARE}...")

# 1. Sync config
config_src = os.path.join(ROOT, "config")
config_dst = os.path.join(SHARE, "config")
os.makedirs(config_dst, exist_ok=True)
for item in ["seed_sources.yaml", "crawler_config.yaml", "collector_config.json"]:
    sp = os.path.join(config_src, item)
    dp = os.path.join(config_dst, item)
    if os.path.exists(sp):
        shutil.copy2(sp, dp)
        print(f"  - Config copied: {item}")

# 2. Sync manifests
manifests_src = os.path.join(ROOT, "manifests")
manifests_dst = os.path.join(SHARE, "manifests")
os.makedirs(manifests_dst, exist_ok=True)
for item in ["collection_manifest.json", "domain_stats.json"]:
    sp = os.path.join(manifests_src, item)
    dp = os.path.join(manifests_dst, item)
    if os.path.exists(sp):
        shutil.copy2(sp, dp)
        print(f"  - Manifest copied: {item}")

# 3. Sync src package
src_root = os.path.join(ROOT, "src")
src_dst = os.path.join(SHARE, "src")
os.makedirs(src_dst, exist_ok=True)
for item in os.listdir(src_root):
    sp = os.path.join(src_root, item)
    dp = os.path.join(src_dst, item)
    if item == "__pycache__":
        continue
    if os.path.isdir(sp):
        if os.path.exists(dp):
            shutil.rmtree(dp)
        shutil.copytree(sp, dp)
        print(f"  - Package dir copied: src/{item}")
    else:
        shutil.copy2(sp, dp)
        print(f"  - Package file copied: src/{item}")

# 4. Sync python scripts
for item in ["real_corpus_ingester.py", "run_corpus_batch.py", "requirements-collector.txt", "README_REAL_CORPUS.md", "SOURCE_PROPOSAL_REVIEW.md"]:
    sp = os.path.join(ROOT, item)
    dp = os.path.join(SHARE, item)
    if os.path.exists(sp):
        shutil.copy2(sp, dp)
        print(f"  - Top-level file copied: {item}")

# 5. Ensure permissions on shell scripts
for sh_file in [os.path.join(SHARE, "run_real_corpus_batch.sh"), os.path.join(SHARE, "commands", "run_real_corpus_batch.sh")]:
    if os.path.exists(sh_file):
        os.chmod(sh_file, 0o755)
        print(f"  - Executable permissions set: {os.path.basename(sh_file)}")

print("\n[+] Shared folder package sync complete.")

# 6. Validate Package
seeds_file = os.path.join(SHARE, "config", "seed_sources.yaml")
with open(seeds_file, "r", encoding="utf-8") as f:
    data = yaml.safe_load(f)

sources = data.get("sources", [])
approved = [s for s in sources if s.get("approved") is True and s.get("collection_allowed") is True and s.get("approval_status") != "REFERENCE_ONLY"]

print(f"\n[+] Validation Summary:")
print(f"    Total Seed Sources in Registry: {len(sources)}")
print(f"    Approved First-Batch Sources:  {len(approved)}")
for s in approved:
    print(f"    - {s.get('source_id')}: {s.get('url')} (Cap: {s.get('max_pages_cap')})")

assert len(approved) == 7, f"Expected 7 approved sources, got {len(approved)}"
print("\n[+] Host-Side Validation: SUCCESSFUL!")
