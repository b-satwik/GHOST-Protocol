#!/usr/bin/env bash
# DarkWatch Real Corpus Package Preflight Verification Script
# Validates environment, package files, python imports, configurations,
# 7 approved sources, MITRE CTI resources, writable runtime dir, and SOCKS5 proxy.
# DOES NOT COLLECT ANY DATA.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PACKAGE_ROOT"

PYTHON_CMD="python3"

$PYTHON_CMD - << 'EOF'
import sys
import os
import socket
import yaml
import json

package_root = os.getcwd()
sys.path.insert(0, package_root)

pkg_status = "PASS"
imports_status = "PASS"
config_status = "PASS"
resources_status = "PASS"
socks_status = "PASS"

pkg_errors = []
imports_errors = []
config_errors = []
resources_errors = []
socks_errors = []

# 1. Package File Audit
req_files = [
    "run_real_corpus_batch.sh",
    "run_corpus_batch.py",
    "real_corpus_ingester.py",
    "requirements-collector.txt",
    "config/seed_sources.yaml",
    "config/crawler_config.yaml",
    "config/collector_config.json",
    "manifests/collection_manifest.json",
    "manifests/domain_stats.json"
]


for f in req_files:
    p = os.path.join(package_root, f)
    if not os.path.exists(p):
        pkg_errors.append(f"Missing file: {f}")
        pkg_status = "FAIL"

# Check Python version >= 3.8
if sys.version_info < (3, 8):
    pkg_errors.append(f"Python version too old: {sys.version}")
    pkg_status = "FAIL"

# 2. Imports Audit
modules_to_test = [
    "real_corpus_ingester",
    "run_corpus_batch",
    "src.collector.sanitizer",
    "src.collector.evidence_store",
    "src.collector.state_engine",
    "src.collector.verifier",
    "src.config",
    "src.cti.mitre_kb",
    "src.cti.mitre_enricher",
    "src.cti.stix_generator",
    "src.cti.stix_extractor",
    "src.cti.cti_store",
    "src.dataset.schema",
    "src.dataset.annotation_store",
    "src.dataset.weak_supervision",
    "src.deduplication.minhash_lsh",
    "src.review.quality_auditor",
    "src.review.reviewer",
    "src.exporter.export_runner"
]

import importlib
for mod in modules_to_test:
    try:
        importlib.import_module(mod)
    except Exception as e:
        imports_errors.append(f"Failed to import {mod}: {e}")
        imports_status = "FAIL"

# 3. Configuration Audit
seeds_path = os.path.join(package_root, "config/seed_sources.yaml")
if os.path.exists(seeds_path):
    try:
        with open(seeds_path, "r", encoding="utf-8") as sf:
            data = yaml.safe_load(sf) or {}
        sources = data.get("sources", [])
        expected_sources = [
            "CISA_KEV", "EXPLOIT_DB", "0X00SEC_FORUM", "RANSOMWARE_LIVE",
            "VX_UNDERGROUND", "PROPUBLICA_ONION", "DREAD_FORUM_ONION",
            "REDDIT_CYBERSECURITY", "FOURCHAN_TECH", "FOURPLEBS_ARCHIVE",
            "HACKER_NEWS", "PASTEBIN_PUBLIC", "PSBDMP_PASTE_DUMP",
            "OCCRP_ALEPH", "CRYPTOME_ARCHIVE", "MUCKROCK_PUBLIC_RECORDS"
        ]
        found_sources = {s.get("source_id"): s for s in sources}
        
        for sid in expected_sources:
            if sid not in found_sources:
                config_errors.append(f"Missing approved source: {sid}")
                config_status = "FAIL"
            else:
                s = found_sources[sid]
                if s.get("approved") is not True:
                    config_errors.append(f"{sid} is not approved: true")
                    config_status = "FAIL"
                if s.get("collection_allowed") is not True:
                    config_errors.append(f"{sid} is not collection_allowed: true")
                    config_status = "FAIL"
                if not isinstance(s.get("max_pages_cap"), int) or s.get("max_pages_cap") < 1:
                    config_errors.append(f"{sid} max_pages_cap is {s.get('max_pages_cap')}, expected positive integer")
                    config_status = "FAIL"
                if not s.get("url", "").strip():
                    config_errors.append(f"{sid} URL is empty")
                    config_status = "FAIL"

    except Exception as e:
        config_errors.append(f"Error parsing seed_sources.yaml: {e}")
        config_status = "FAIL"
else:
    config_errors.append("config/seed_sources.yaml missing")
    config_status = "FAIL"

# 4. Runtime Resources Audit
res_files = [
    "src/config/enterprise_attack_stix_2.1.json",
    "src/config/mitre_knowledge_base.json",
    "src/config/risk_policy.json"
]

for rf in res_files:
    rp = os.path.join(package_root, rf)
    if not os.path.exists(rp) or os.path.getsize(rp) == 0:
        resources_errors.append(f"Missing or empty resource file: {rf}")
        resources_status = "FAIL"

# Check writable runtime dir
runtime_dir = os.path.join(package_root, "data")
try:
    os.makedirs(runtime_dir, exist_ok=True)
    test_file = os.path.join(runtime_dir, ".write_test")
    with open(test_file, "w") as tf:
        tf.write("test")
    os.remove(test_file)
except Exception as e:
    # If package root is read-only (e.g. shared folder mount), check $HOME/darkwatch_collector
    home_dir = os.path.expanduser("~/darkwatch_collector/data")
    try:
        os.makedirs(home_dir, exist_ok=True)
        test_file = os.path.join(home_dir, ".write_test")
        with open(test_file, "w") as tf:
            tf.write("test")
        os.remove(test_file)
    except Exception as e2:
        resources_errors.append(f"No writable runtime directory available: {e2}")
        resources_status = "FAIL"

# 5. Tor SOCKS5 Proxy Connectivity Check
proxy_host = "10.152.152.10"
proxy_port = 9050

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect((proxy_host, proxy_port))
    s.close()
except Exception as e:
    # Also check localhost:9050 as fallback
    try:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(2.0)
        s2.connect(("127.0.0.1", 9050))
        s2.close()
    except Exception:
        socks_errors.append(f"SOCKS5 proxy ({proxy_host}:{proxy_port}) unreachable: {e}")
        socks_status = "FAIL"

print("\nDARKWATCH REAL CORPUS PREFLIGHT")
print("-------------------------------")
print(f"Package:           {pkg_status}")
print(f"Imports:           {imports_status}")
print(f"Configuration:     {config_status}")
print(f"Runtime resources: {resources_status}")
print(f"Tor SOCKS5:        {socks_status}")
print("-------------------------------")

if pkg_errors:
    print("\nPackage Errors:")
    for err in pkg_errors:
        print(f"  - {err}")

if imports_errors:
    print("\nImport Errors:")
    for err in imports_errors:
        print(f"  - {err}")

if config_errors:
    print("\nConfiguration Errors:")
    for err in config_errors:
        print(f"  - {err}")

if resources_errors:
    print("\nRuntime Resource Errors:")
    for err in resources_errors:
        print(f"  - {err}")

if socks_errors:
    print("\nTor SOCKS5 Proxy Errors (Note: Whonix Gateway provides 10.152.152.10:9050):")
    for err in socks_errors:
        print(f"  - {err}")

# Overall exit code
all_passed = (
    pkg_status == "PASS" and
    imports_status == "PASS" and
    config_status == "PASS" and
    resources_status == "PASS" and
    socks_status == "PASS"
)

if not all_passed:
    sys.exit(1)
else:
    print("\n[+] ALL PREFLIGHT CHECKS PASSED SUCCESSFULLY.")
EOF
