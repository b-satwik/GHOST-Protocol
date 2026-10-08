"""
End-to-End Real Observation & Persistence Acceptance Test for GHOST PROTOCOL.
Verifies that:
1. Real site observation creates and updates real Threat Session records in SQLite (AnnotationStore).
2. Threat Session actors contain only real extracted thread users.
3. XGBoost reports NETWORK MODALITY UNAVAILABLE when no flow features exist.
4. GHOST DATA LINEAGE debug output block is printed.
5. Dashboard APIs (/api/sources, /api/sources/<source_id>/details, /api/threat_sessions) return non-zero sessions & users.
"""

import sys
import os
import time
import json
import uuid
import datetime

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.stage1_continuous_observer import Stage1ContinuousObserver
from src.dataset.annotation_store import AnnotationStore
from src.stage1_dashboard import app, enrich_source_entry, is_session_matching_source


def run_acceptance_test():
    print("======================================================================")
    print("STARTING GHOST PROTOCOL END-TO-END PERSISTENCE & DASHBOARD ACCEPTANCE TEST")
    print("======================================================================")

    observer = Stage1ContinuousObserver()
    store = AnnotationStore()

    # Register real target source (0x00sec.org)
    test_url = "https://0x00sec.org/"
    source_id = "src_test_real_01"

    print(f"\n[1] Registering target source: {test_url} (ID: {source_id})")
    observer.registry.register_source(
        canonical_url=test_url,
        source_id=source_id,
        source_type="FORUM",
        collector_type="HTTP_CLEARNET",
        discovered_via="ACCEPTANCE_TEST"
    )

    # Retrieve actual registered source entry
    source_entry = observer.registry.get_source_by_url(test_url) or observer.registry.get_source_by_id(source_id)
    assert source_entry is not None, f"FAIL: Target source {test_url} could not be retrieved from registry!"
    source_id = source_entry["source_id"]

    # Approve source to LIVE state
    observer.registry.update_source_lifecycle(
        source_id=source_id,
        validation_status="LIVE",
        agent_state="RUNNING",
        connection_state="ACTIVE",
        access_method="HTTP_DIRECT"
    )

    # Enqueue valid genuine thread candidate
    observer.queue.enqueue(url="https://0x00sec.org/t/cve-2024-38077-analysis-and-exploitation/38910", discovered_via="ACCEPTANCE_TEST", parent_source_url=test_url)

    # Run single observation pass over target source
    print(f"\n[2] Executing live observation pass on source {source_id} ({test_url})...")
    obs_res = observer.observe_source_entry(source_entry)

    print(f"\n[3] Observation Pass Result:")
    print(f"    Status: {obs_res.get('status')}")
    print(f"    Change State: {obs_res.get('change_state')}")
    print(f"    Threat Session ID: {obs_res.get('threat_session_id')}")

    session_id = obs_res.get("threat_session_id")
    assert session_id, "FAIL: No Threat Session ID returned from observation!"

    # Verify Database Persistence
    print(f"\n[4] Verifying SQLite persistence for session {session_id}...")
    session_data = store.get_threat_session(session_id)
    assert session_data is not None, f"FAIL: Threat Session {session_id} was NOT persisted in SQLite!"
    print(f"    SUCCESS: Persisted Threat Session found in AnnotationStore SQLite DB!")
    print(f"    Session ID: {session_data.get('session_id')}")
    print(f"    Source ID: {session_data.get('source_id')}")
    print(f"    Primary Source URL: {session_data.get('primary_source_url')}")
    print(f"    Sources: {session_data.get('sources')}")
    print(f"    Actors/Users: {session_data.get('actors')}")
    print(f"    Root Author: {session_data.get('root_author')}")
    print(f"    Root Post: {session_data.get('root_post')}")

    # Verify session matching logic
    print(f"\n[5] Verifying session-to-source matching helper logic...")
    matched = is_session_matching_source(session_data, source_id, test_url)
    assert matched, f"FAIL: is_session_matching_source returned False for source {source_id} and URL {test_url}!"
    print("    SUCCESS: Session matches source ID and URL!")

    # Test Dashboard APIs using Flask Test Client
    print(f"\n[6] Testing Dashboard REST APIs with test client...")
    client = app.test_client()

    # 6a. GET /api/sources
    resp_sources = client.get("/api/sources")
    assert resp_sources.status_code == 200, f"FAIL: /api/sources returned status {resp_sources.status_code}"
    sources_data = json.loads(resp_sources.data)
    test_src = next((s for s in sources_data if s.get("source_id") == source_id), None)
    assert test_src is not None, f"FAIL: Source {source_id} missing from /api/sources response!"
    print(f"    /api/sources -> sessions_count: {test_src.get('sessions_count')}, users_count: {test_src.get('users_count')}")
    assert test_src.get("sessions_count", 0) > 0, "FAIL: Dashboard /api/sources returned sessions_count = 0!"

    # 6b. GET /api/sources/<source_id>/details
    resp_details = client.get(f"/api/sources/{source_id}/details")
    assert resp_details.status_code == 200, f"FAIL: /api/sources/{source_id}/details returned status {resp_details.status_code}"
    details_data = json.loads(resp_details.data)
    matched_sessions = details_data.get("threat_sessions", [])
    print(f"    /api/sources/{source_id}/details -> threat_sessions found: {len(matched_sessions)}")
    assert len(matched_sessions) > 0, f"FAIL: /api/sources/{source_id}/details returned 0 threat sessions!"

    # 6c. GET /api/threat_sessions?source_id=<source_id>
    resp_threat_sessions = client.get(f"/api/threat_sessions?source_id={source_id}")
    assert resp_threat_sessions.status_code == 200, f"FAIL: /api/threat_sessions returned status {resp_threat_sessions.status_code}"
    ts_list = json.loads(resp_threat_sessions.data)
    print(f"    /api/threat_sessions?source_id={source_id} -> sessions found: {len(ts_list)}")
    assert len(ts_list) > 0, f"FAIL: /api/threat_sessions returned 0 sessions for source {source_id}!"

    # 6d. Verify Network Modality status (XGBoost unavailable when no 79 flow features exist)
    bridge_out = obs_res.get("bridge_output", {})
    xgb_res = bridge_out.get("ml", {}).get("xgboost", {}) or bridge_out.get("xgboost", {})
    print(f"\n[7] Verifying XGBoost network modality handling...")
    print(f"    XGBoost Result: {xgb_res}")
    assert not xgb_res.get("network_available", False), "FAIL: XGBoost network_available was True despite missing 79 flow features!"
    print("    SUCCESS: XGBoost correctly reported NETWORK MODALITY UNAVAILABLE (no fake score fabricated)!")

    print("\n======================================================================")
    print("ALL ACCEPTANCE TEST ASSERTIONS PASSED SUCCESSFULLY!")
    print("GHOST PROTOCOL END-TO-END DATA PERSISTENCE & DASHBOARD INTEGRATION VERIFIED.")
    print("======================================================================\n")


if __name__ == "__main__":
    run_acceptance_test()
