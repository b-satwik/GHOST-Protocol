import os
import sys
import json

sys.path.insert(0, os.path.abspath("."))

from src.stage1_dashboard import app
from src.investigation.conversation_risk import ConversationRiskDetector

print("=== STARTING COMPREHENSIVE VERIFICATION ===")

client = app.test_client()

# 1. Test Session Detail (TS-031 & TS-001)
print("\n--- 1. Testing Threat Session Detail (/api/threat_sessions/TS-031) ---")
res = client.get("/api/threat_sessions/TS-031")
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
data = res.json

print(f"Session Title: {data['root_post']['title']}")
print(f"DistilBERT Prediction: {data['distilbert_explanation']['prediction']} ({data['distilbert_explanation']['threat_label']})")
print(f"HM-TIF Fusion Risk Score: {data['hm_tif_breakdown']['fusion_risk_score']}")
assert data['hm_tif_breakdown']['fusion_risk_score'] > 0.0, "HM-TIF score must be > 0.0!"

# Verify Graph Nodes & Edges
graph = data["relationship_graph"]
user_nodes = [n for n in graph["nodes"] if n["type"] == "USER"]
print(f"Scoped USER Nodes Count: {len(user_nodes)} -> {[u['label'] for u in user_nodes]}")
reply_edges = [e for e in graph["edges"] if e["label"] == "replied_to"]
print(f"Reply Edges Count: {len(reply_edges)} -> {reply_edges}")

# Verify 8 DistilBERT labels rule
valid_classes = {"auth_access", "dos", "file_inclusion", "info_disclosure", "injection", "memory_corruption", "rce", "xss"}
assert data['distilbert_explanation']['prediction'] in valid_classes, f"Class {data['distilbert_explanation']['prediction']} not in valid 8 trained classes!"

# 2. Test Sources Connect Endpoint & PID
print("\n--- 2. Testing Sources Connect Endpoint (/api/sources/src_shadowboard_01/connect) ---")
res = client.post("/api/sources/src_shadowboard_01/connect")
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
conn_data = res.json
print(f"Connect Response: {conn_data['status_display']} | PID: {conn_data['pid']}")
assert "CONNECTED (PID:" in conn_data['status_display'], "status_display must show CONNECTED (PID: ...)"

# Verify /api/sources list contains PID and status_display
res = client.get("/api/sources")
assert res.status_code == 200
sources = res.json
print(f"Enriched Source Entry Status: {sources[0]['status_display']} (PID: {sources[0]['pid']})")

# 3. Test Search Entities Endpoint
print("\n--- 3. Testing Search Entities (/api/search_entities?query=LockBit) ---")
res = client.get("/api/search_entities?query=LockBit")
assert res.status_code == 200
search_data = res.json
print(f"Search Query: {search_data['query']} | Entity Type: {search_data['entity_type']}")
print(f"Matching Sessions Count: {len(search_data['matching_sessions'])}")

res_cve = client.get("/api/search_entities?query=CVE-2024-38877")
assert res_cve.status_code == 200
print(f"CVE Search Entity Type: {res_cve.json['entity_type']} | Sessions: {len(res_cve.json['matching_sessions'])}")

# 4. Test n8n Gmail Alert Triggers
print("\n--- 4. Testing n8n Alert Triggers ---")
res_reply = client.post("/api/alerts/trigger", json={"alert_type": "SESSION_USER_REPLY", "session_id": "TS-031", "username": "ViperSec", "content": "Updated exploit code attached."})
assert res_reply.status_code == 200
print(f"Session User Reply Alert Dispatch: {res_reply.json['n8n_result']['message']}")

res_online = client.post("/api/alerts/trigger", json={"alert_type": "SOURCE_ONLINE", "source_id": "src_shadowboard_01", "url": "http://shadowboard.lab"})
assert res_online.status_code == 200
print(f"Source Online Alert Dispatch: {res_online.json['n8n_result']['message']}")

print("\n=== ALL VERIFICATION TESTS PASSED SUCCESSFULLY ===")
