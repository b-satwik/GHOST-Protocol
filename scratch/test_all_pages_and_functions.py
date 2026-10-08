import os
import sys
import json

sys.path.insert(0, os.path.abspath("."))

from src.stage1_dashboard import app
from src.investigation.conversation_risk import ConversationRiskDetector

print("==================================================================")
print("     GHOST PROTOCOL — COMPREHENSIVE ALL-PAGE & ALL-FUNCTION TEST   ")
print("==================================================================")

client = app.test_client()
passed_tests = 0
failed_tests = 0

def run_test(name, func):
    global passed_tests, failed_tests
    print(f"\n[TEST] {name} ... ", end="")
    try:
        func()
        print("PASSED ✅")
        passed_tests += 1
    except Exception as ex:
        print(f"FAILED ❌: {ex}")
        failed_tests += 1

# 1. Main Dashboard UI Page (HTML)
def test_dashboard_html():
    res = client.get("/")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    html = res.get_data(as_text=True)
    assert "<title>GHOST PROTOCOL" in html, "HTML missing GHOST PROTOCOL title!"
    assert "DEDICATED CTI WORKSPACE" in html, "HTML missing CTI workspace!"
    assert "N8N GMAIL ALERTING SYSTEM" in html, "HTML missing n8n alerting panel!"
    assert "[ CONNECT ]" in html, "HTML missing CONNECT button!"

run_test("1. Dashboard HTML Interface (/)", test_dashboard_html)

# 2. Operational Telemetry HUD (/api/telemetry)
def test_telemetry():
    res = client.get("/api/telemetry")
    assert res.status_code == 200
    data = res.json
    assert "ghost_agent_state" in data, "Telemetry missing agent state!"
    assert "whonix_boundary" in data, "Telemetry missing whonix boundary!"
    assert "hm_tif_live_gauge" in data, "Telemetry missing HM-TIF gauge!"

run_test("2. Operational Telemetry HUD (/api/telemetry)", test_telemetry)

# 3. Sources Workspace List (/api/sources)
def test_sources_list():
    res = client.get("/api/sources")
    assert res.status_code == 200
    sources = res.json
    assert isinstance(sources, list) and len(sources) > 0, "No sources returned!"
    src = sources[0]
    assert "pid" in src, "Source entry missing PID!"
    assert "status_display" in src, "Source entry missing status_display!"

run_test("3. Sources Workspace List (/api/sources)", test_sources_list)

# 4. Sources Connect Endpoint (/api/sources/<id>/connect)
def test_source_connect():
    res = client.post("/api/sources/src_shadowboard_01/connect")
    assert res.status_code == 200
    data = res.json
    assert data["success"] is True
    assert data["current_status"] == "CONNECTED"
    assert "CONNECTED (PID:" in data["status_display"]

run_test("4. Sources Connect Endpoint (/api/sources/src_shadowboard_01/connect)", test_source_connect)

# 5. Sources Cancel Endpoint (/api/sources/<id>/cancel)
def test_source_cancel():
    res = client.post("/api/sources/src_shadowboard_01/cancel")
    assert res.status_code == 200
    data = res.json
    assert data["success"] is True
    assert data["current_status"] == "CANCELLED"

run_test("5. Sources Cancel Endpoint (/api/sources/src_shadowboard_01/cancel)", test_source_cancel)

# 6. Re-connect Source to restore active state
def test_source_reconnect():
    res = client.post("/api/sources/src_shadowboard_01/connect")
    assert res.status_code == 200

run_test("6. Restore Source Active State", test_source_reconnect)

# 7. Threat Sessions List (/api/threat_sessions)
def test_threat_sessions_list():
    res = client.get("/api/threat_sessions")
    assert res.status_code == 200
    sessions = res.json
    assert isinstance(sessions, list) and len(sessions) > 0, "No threat sessions returned!"

run_test("7. Threat Sessions List (/api/threat_sessions)", test_threat_sessions_list)

# 8. Threat Session Detail & Graph Scoping (/api/threat_sessions/TS-031)
def test_threat_session_detail():
    res = client.get("/api/threat_sessions/TS-031")
    assert res.status_code == 200
    data = res.json
    assert data["session_id"] == "TS-031"
    
    # Title Check
    root_title = data["root_post"]["title"]
    assert root_title and root_title != "Discussion thread", f"Invalid session title: {root_title}"
    
    # DistilBERT 8 Classes Check
    valid_8 = {"auth_access", "dos", "file_inclusion", "info_disclosure", "injection", "memory_corruption", "rce", "xss"}
    pred = data["distilbert_explanation"]["prediction"]
    assert pred in valid_8, f"DistilBERT prediction '{pred}' is not in the 8 official trained classes!"
    
    # HM-TIF Non-Zero Check
    hmtif_score = data["hm_tif_breakdown"]["fusion_risk_score"]
    assert hmtif_score > 0.0, "HM-TIF score must be non-zero!"
    
    # Scoped User Graph Check
    graph = data["relationship_graph"]
    user_nodes = [n for n in graph["nodes"] if n["type"] == "USER"]
    session_users = data["session_users"]
    assert len(user_nodes) == len(session_users), "Graph USER nodes must strictly match session participants count!"

run_test("8. Threat Session Detail & Scoped Graph (/api/threat_sessions/TS-031)", test_threat_session_detail)

# 9. Search Entities Endpoint (/api/search_entities?query=LockBit)
def test_search_entities_ransomware():
    res = client.get("/api/search_entities?query=LockBit")
    assert res.status_code == 200
    data = res.json
    assert data["entity_type"] == "RANSOMWARE / MALWARE"
    assert "matching_sessions" in data

run_test("9. Search Entities — Ransomware Query (/api/search_entities?query=LockBit)", test_search_entities_ransomware)

# 10. Search Entities Endpoint (/api/search_entities?query=CVE-2024-38877)
def test_search_entities_cve():
    res = client.get("/api/search_entities?query=CVE-2024-38877")
    assert res.status_code == 200
    data = res.json
    assert data["entity_type"] == "CVE / VULNERABILITY"

run_test("10. Search Entities — CVE Query (/api/search_entities?query=CVE-2024-38877)", test_search_entities_cve)

# 11. Search Entities Endpoint (/api/search_entities?query=user07)
def test_search_entities_user():
    res = client.get("/api/search_entities?query=user07")
    assert res.status_code == 200
    data = res.json
    assert data["username"] == "user07"

run_test("11. Search Entities — Username Query (/api/search_entities?query=user07)", test_search_entities_user)

# 12. CTI & ATT&CK Workspace (/api/cti_mitre_workspace)
def test_cti_workspace():
    res = client.get("/api/cti_mitre_workspace")
    assert res.status_code == 200
    data = res.json
    assert "observed_entities" in data
    assert "mitre_mappings" in data

run_test("12. CTI & ATT&CK Workspace (/api/cti_mitre_workspace)", test_cti_workspace)

# 13. n8n Gmail Alerting System Test — SESSION_USER_REPLY
def test_n8n_alert_reply():
    res = client.post("/api/alerts/trigger", json={
        "alert_type": "SESSION_USER_REPLY",
        "session_id": "TS-031",
        "username": "ViperSec",
        "content": "Automated payload reply test."
    })
    assert res.status_code == 200
    data = res.json
    assert data["alert_type"] == "SESSION_USER_REPLY"
    assert "n8n_result" in data

run_test("13. n8n Alerting — SESSION_USER_REPLY Trigger", test_n8n_alert_reply)

# 14. n8n Gmail Alerting System Test — SOURCE_ONLINE
def test_n8n_alert_online():
    res = client.post("/api/alerts/trigger", json={
        "alert_type": "SOURCE_ONLINE",
        "source_id": "src_shadowboard_01",
        "url": "http://shadowboard.lab"
    })
    assert res.status_code == 200
    data = res.json
    assert data["alert_type"] == "SOURCE_ONLINE"
    assert "n8n_result" in data

run_test("14. n8n Alerting — SOURCE_ONLINE Trigger", test_n8n_alert_online)

# 15. GHOST AI Analyst Console (/api/ghost_console/query)
def test_ghost_console():
    res = client.post("/api/ghost_console/query", json={"query": "/status"})
    assert res.status_code == 200
    data = res.json
    assert "output" in data or "response" in data or "result" in data or "status" in data

run_test("15. GHOST AI Analyst Console (/api/ghost_console/query)", test_ghost_console)

# 16. AI Brain Components (/api/ai_models)
def test_ai_models():
    res = client.get("/api/ai_models")
    assert res.status_code == 200
    data = res.json
    assert isinstance(data, list) and len(data) >= 4, "Expected at least 4 AI models!"

run_test("16. AI Brain Components (/api/ai_models)", test_ai_models)

# 17. Real-Time System Events (/api/events)
def test_system_events():
    res = client.get("/api/events")
    assert res.status_code == 200

run_test("17. Real-Time System Events (/api/events)", test_system_events)

print("\n==================================================================")
print(f"     TOTAL TESTS RUN: {passed_tests + failed_tests}")
print(f"     PASSED: {passed_tests} ✅")
print(f"     FAILED: {failed_tests} ❌")
print("==================================================================")
