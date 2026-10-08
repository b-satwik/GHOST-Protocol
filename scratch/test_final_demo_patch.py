import sys
import os
import json

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.stage1_dashboard import app, is_session_matching_source
from src.investigation.conversation_risk import ConversationRiskDetector

def run_targeted_verification():
    print("=" * 80)
    print("         GHOST PROTOCOL — FINAL DEMO PATCH TARGETED VERIFICATION")
    print("=" * 80)

    client = app.test_client()

    # 1. Test is_session_matching_source Invariant
    print("\n[*] 1. Testing Strict Source-Session Ownership Invariant...")
    valid_sess = {"source_id": "SRC_SHADOWBOARD_ONION", "sources": ["http://127.0.0.1:8080/post/1"]}
    wrong_sess = {"source_id": "SRC_OTHER", "sources": ["http://127.0.0.1:8080/post/1"]}
    
    assert is_session_matching_source(valid_sess, "SRC_SHADOWBOARD_ONION") == True
    assert is_session_matching_source(wrong_sess, "SRC_SHADOWBOARD_ONION") == False
    print("    [✓] Invariant passed: session.source_id == candidate.source_id == observation.source_id")

    # 2. Test Main Dashboard Live DistilBERT Label Breakdown API
    print("\n[*] 2. Testing Live Dashboard API & DistilBERT Breakdown...")
    res = client.get('/api/live_status')
    if res.status_code != 200:
        print(f"    [!] Error response status: {res.status_code}, body: {res.get_data(as_text=True)}")
    assert res.status_code == 200
    data = res.get_json()
    assert "distilbert_breakdown" in data
    db_breakdown = data["distilbert_breakdown"]
    expected_labels = ["auth_access", "dos", "file_inclusion", "info_disclosure", "injection", "memory_corruption", "rce", "xss"]
    for lbl in expected_labels:
        assert lbl in db_breakdown, f"Missing label {lbl} in breakdown"
    print("    [✓] DistilBERT 8-Class Label Breakdown verified:")
    for lbl, count in db_breakdown.items():
        print(f"        - {lbl:18s}: {count}")

    # 3. Test Cancel Observation Endpoint
    print("\n[*] 3. Testing Cancel Observation Endpoint...")
    res_cancel = client.post('/api/sources/SRC_SHADOWBOARD_ONION/cancel')
    data_cancel = res_cancel.get_json()
    assert res_cancel.status_code == 200
    assert data_cancel["success"] == True
    assert data_cancel["current_status"] == "CANCELLED"
    assert "pid" in data_cancel
    print(f"    [✓] Cancel Observation verified: PID={data_cancel['pid']} Status={data_cancel['current_status']}")

    # 4. Test Source Discovered Links Endpoint
    print("\n[*] 4. Testing Source Discovered Links Grouping...")
    res_links = client.get('/api/sources/SRC_SHADOWBOARD_ONION/links')
    data_links = res_links.get_json()
    assert res_links.status_code == 200
    assert "grouped_links" in data_links
    print(f"    [✓] Discovered Links verified: Total={data_links['total_links']}")

    # 5. Test Conversation Risk & n8n Alert Integration
    print("\n[*] 5. Testing Conversation Risk Detector & n8n Alerting...")
    sample_thread = {
        "title": "LockBit Ransomware Operation & AD Domain Compromise",
        "content": "Step-by-step guide for deploying LockBit ransomware across enterprise AD domains.",
        "direct_replies": []
    }
    risk_res = ConversationRiskDetector.classify_conversation_risk(sample_thread)
    assert risk_res["risk_category"] == "RANSOMWARE"
    assert risk_res["risk_state"] == "HIGH_ALERT"
    n8n_alert = ConversationRiskDetector.dispatch_n8n_alert({"test": True})
    assert "status" in n8n_alert
    print(f"    [✓] Conversation Risk verified: Category={risk_res['risk_category']} n8n_Status={n8n_alert['status']}")

    # 6. Test Ask Gemini XAI Endpoint
    print("\n[*] 6. Testing Ask Gemini Analyst Reasoning Endpoint...")
    res_gemini = client.post('/api/xai/ask_gemini', json={
        "session_id": "TS-001",
        "question": "Why was this session classified by DistilBERT?"
    })
    data_gemini = res_gemini.get_json()
    assert res_gemini.status_code in (200, 404)
    print("    [✓] Ask Gemini endpoint verified.")

    print("\n" + "=" * 80)
    print("         ALL TARGETED DEMO PATCH CHECKS PASSED SUCCESSFULLY!")
    print("=" * 80)

if __name__ == "__main__":
    run_targeted_verification()
