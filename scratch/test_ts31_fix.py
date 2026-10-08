#!/usr/bin/env python3
"""
Targeted Verification for TS-031 Threat Session Detail Fix & Empty-Source Edge Case
"""
import sys
import os
import json

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.dataset.annotation_store import AnnotationStore
from src.stage1_dashboard import app, resolve_session_source


def run_tests():
    print("\n================================================================================")
    print("         GHOST PROTOCOL — TS-031 THREAT SESSION FIX VERIFICATION")
    print("================================================================================\n")

    store = AnnotationStore()

    # 1. Seed TS-031 with exact edge-case structure (source_id set, primary_source_url set, but sources = [])
    ts31_payload = {
        "session_id": "TS-031",
        "source_id": "SRC_d9186e",
        "candidate_id": "cand_105",
        "primary_source_url": "http://shadowboard.lab/post/cve_test",
        "root_post_title": "Vulnerability Discussion CVE-2024-38077",
        "root_post_content": "Full proof of concept for CVE-2024-38077 attached.",
        "root_author": "Dencodey",
        "status": "ACTIVE",
        "sources": [],  # Explicit empty sources list
        "indicators": ["CVE-2024-38077"],
        "cti_entities": [{"type": "CVE", "value": "CVE-2024-38077", "confidence": None}]
    }
    store.save_threat_session(ts31_payload)

    # 2. Seed TS-051 and SESSION-31C7 to verify existing non-regression
    ts51_payload = {
        "session_id": "TS-051",
        "source_id": "SRC_test51",
        "primary_source_url": "http://shadowboard.lab/post/test51",
        "root_post_title": "Test Session TS-051",
        "root_author": "user07",
        "status": "ACTIVE",
        "sources": ["http://shadowboard.lab/post/test51"]
    }
    store.save_threat_session(ts51_payload)

    ts31c7_payload = {
        "session_id": "SESSION-31C7",
        "source_id": "SRC_31c7",
        "primary_source_url": "http://shadowboard.lab/post/31c7",
        "root_post_title": "Test Session SESSION-31C7",
        "root_author": "user08",
        "status": "ACTIVE",
        "sources": ["http://shadowboard.lab/post/31c7"]
    }
    store.save_threat_session(ts31c7_payload)

    # 3. Test resolve_session_source helper directly
    print("[*] 1. Testing resolve_session_source helper on empty-source edge case...")
    recovered_ts31 = store.get_threat_session("TS-031")
    assert recovered_ts31 is not None, "Failed to retrieve TS-031 from store"
    src_node_id, src_label = resolve_session_source(recovered_ts31)
    print(f"    [✓] Resolved TS-031 Source Node ID: {src_node_id}")
    print(f"    [✓] Resolved TS-031 Source Label:   {src_label}")
    assert src_label != "ShadowBoard" or recovered_ts31.get("source_id") == "ShadowBoard", "Must not blindly fabricate ShadowBoard"

    # 4. Test Flask Test Client Endpoints
    print("\n[*] 2. Testing Flask API endpoints via test client...")
    client = app.test_client()

    # GET /api/threat_sessions/TS-031
    res31 = client.get("/api/threat_sessions/TS-031")
    print(f"    GET /api/threat_sessions/TS-031 -> Status: {res31.status_code}")
    assert res31.status_code == 200, f"Expected 200, got {res31.status_code}: {res31.get_data(as_text=True)}"
    data31 = res31.get_json()
    assert data31.get("session_id") == "TS-031"
    print(f"    [✓] TS-031 Detail payload retrieved successfully. Header Source: '{data31.get('header', {}).get('source')}'")

    # GET /api/threat_sessions/TS-051
    res51 = client.get("/api/threat_sessions/TS-051")
    print(f"    GET /api/threat_sessions/TS-051 -> Status: {res51.status_code}")
    assert res51.status_code == 200, f"Expected 200, got {res51.status_code}"

    # GET /api/threat_sessions/SESSION-31C7
    res31c7 = client.get("/api/threat_sessions/SESSION-31C7")
    print(f"    GET /api/threat_sessions/SESSION-31C7 -> Status: {res31c7.status_code}")
    assert res31c7.status_code == 200, f"Expected 200, got {res31c7.status_code}"

    # GET /api/threat_sessions summary
    res_list = client.get("/api/threat_sessions")
    assert res_list.status_code == 200
    print(f"    [✓] GET /api/threat_sessions -> Status: 200 (Total sessions: {len(res_list.get_json())})")

    # GET /api/sources
    res_src = client.get("/api/sources")
    assert res_src.status_code == 200
    print(f"    [✓] GET /api/sources -> Status: 200")

    # GET /api/live_status
    res_live = client.get("/api/live_status")
    assert res_live.status_code == 200
    print(f"    [✓] GET /api/live_status -> Status: 200")

    # 5. Test Pure Empty Source Edge Case (No primary_source_url, no source_id, sources = [])
    print("\n[*] 3. Testing Pure Empty Source Edge Case (sources = [], source_id = None)...")
    pure_empty_payload = {
        "session_id": "TS-EMPTY-TEST",
        "status": "ACTIVE",
        "root_post_title": "Pure Empty Session Test",
        "root_author": "anonymous",
        "sources": []
    }
    store.save_threat_session(pure_empty_payload)
    res_empty = client.get("/api/threat_sessions/TS-EMPTY-TEST")
    assert res_empty.status_code == 200, f"Expected 200 for pure empty session, got {res_empty.status_code}"
    data_empty = res_empty.get_json()
    assert data_empty.get("header", {}).get("source") == "SOURCE_UNAVAILABLE", f"Expected SOURCE_UNAVAILABLE, got {data_empty.get('header', {}).get('source')}"
    print(f"    [✓] Pure Empty Session returned HTTP 200 with explicit 'SOURCE_UNAVAILABLE' state.")

    print("\n================================================================================")
    print("         ALL TS-031 THREAT SESSION DETAIL CHECKS PASSED SUCCESSFULLY!")
    print("================================================================================\n")

if __name__ == "__main__":
    run_tests()
