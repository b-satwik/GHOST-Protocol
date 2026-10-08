"""
Live Verification Script for Controlled Docker Laboratory & Live Network Flow Workspace.
"""

import sys
import os
import time
import json
import unittest

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.stage1_dashboard import app as flask_app
from src.observer.tor_browser_observer import get_all_docker_onion_hostnames


def run_live_docker_verification():
    print("\n==================================================")
    print("  LIVE DOCKER LABORATORY NETWORK FLOW VERIFICATION ")
    print("==================================================")

    client = flask_app.test_client()

    # 1. Retrieve Docker Onion Hostnames
    onion_hosts = get_all_docker_onion_hostnames()
    print(f"\n[1] Discovered Docker Onion Hostnames:")
    for s_name, addr in onion_hosts.items():
        print(f"    - {s_name:12s} -> {addr}")

    # 2. Test 1: ShadowForum (Direct Observation Path)
    print("\n[2] Testing ShadowForum Direct Network Observation...")
    shadow_url = onion_hosts.get("shadowforum", "http://127.0.0.1:8085/shadowforum")

    start_res = client.post("/api/network_flow/start", json={
        "source_id": "src_shadowforum",
        "target_url": shadow_url
    })
    self_assert_200(start_res.status_code)
    start_data = json.loads(start_res.data.decode("utf-8"))

    print(f"    - Access Requirement : {start_data.get('access_requirement')}")
    print(f"    - Collector          : {start_data.get('collector')}")
    print(f"    - Flow ID            : {start_data.get('latest_flow', {}).get('flow_id')}")

    flow = start_data.get("latest_flow", {})
    xgb = flow.get("xgboost", {})
    print(f"    - Captured Packets   : {flow.get('packets')}")
    print(f"    - Captured Bytes     : {flow.get('bytes')} B")
    print(f"    - 79 Features Count  : {len(flow.get('features_raw', {}))}")
    print(f"    - XGBoost Prediction : Class {xgb.get('predicted_class')}")
    print(f"    - XGBoost Confidence : {xgb.get('confidence')}")
    print(f"    - Network Score S_net: {flow.get('network_score')}")

    # 3. Test 2: DreadLab (Session Gated / Browser-Required Path)
    print("\n[3] Testing DreadLab Browser-Required Session Flow...")
    dread_url = onion_hosts.get("dreadlab", "http://127.0.0.1:8085/dreadlab")

    dread_res = client.post("/api/network_flow/start", json={
        "source_id": "src_dreadlab",
        "target_url": dread_url
    })
    self_assert_200(dread_res.status_code)
    dread_data = json.loads(dread_res.data.decode("utf-8"))

    print(f"    - Access Requirement : {dread_data.get('access_requirement')}")
    print(f"    - Collector          : {dread_data.get('collector')}")
    print(f"    - Status             : {dread_data.get('status')}")
    print(f"    - Tor Browser Action : {dread_data.get('message')}")

    # 4. Verify Flow Investigation API
    print("\n[4] Verifying Flow Investigation Drawer API...")
    flow_id = flow.get("flow_id")
    inv_res = client.get(f"/api/network_flow/investigate/{flow_id}")
    self_assert_200(inv_res.status_code)
    inv_data = json.loads(inv_res.data.decode("utf-8"))
    print(f"    - Provenance Source  : {inv_data.get('source_id')}")
    print(f"    - Target URL         : {inv_data.get('target_url')}")
    print(f"    - Feature Groups     : {list(inv_data.get('features_normalized', {}).keys())}")

    # 5. Verify XGBoost Analysis API
    print("\n[5] Verifying XGBoost Analysis API...")
    xgb_res = client.get("/api/network_flow/xgboost_analysis")
    self_assert_200(xgb_res.status_code)
    xgb_data = json.loads(xgb_res.data.decode("utf-8"))
    print(f"    - Model Artifact     : {xgb_data.get('model_artifact')}")
    print(f"    - Total Features     : {xgb_data.get('feature_count')}")
    print(f"    - Modality Available : {xgb_data.get('modality_available')}")
    print(f"    - Interpretation     : {xgb_data.get('interpretation')}")

    print("\n==================================================")
    print("  LIVE DOCKER VERIFICATION COMPLETE — ALL PASSED! ")
    print("==================================================\n")


def self_assert_200(code):
    if code != 200:
        raise RuntimeError(f"Expected HTTP 200, got {code}")


if __name__ == "__main__":
    run_live_docker_verification()
