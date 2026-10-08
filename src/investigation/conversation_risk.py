"""
GHOST Protocol — Conversation Risk Detector & n8n Alert Integration.
Classifies conversation-level risk categories and dispatches structured alerts via n8n webhook.
"""

import os
import re
import json
import datetime
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

class ConversationRiskDetector:
    """
    Semantic conversation risk classification for analyst alerting.
    Does NOT replace DistilBERT or HM-TIF.
    """
    
    HIGH_RISK_CATEGORIES = {
        "TERRORIST_ATTACK",
        "VIOLENT_THREAT",
        "RANSOMWARE",
        "DATA_LEAK"
    }

    @staticmethod
    def classify_conversation_risk(thread_info: Dict[str, Any], text_content: str = "") -> Dict[str, Any]:
        title = (thread_info.get("title") or "").lower()
        content = (thread_info.get("content") or text_content or "").lower()
        
        replies = thread_info.get("direct_replies", []) + thread_info.get("nested_replies", [])
        replies_text = " ".join([(r.get("message") or r.get("content") or "") for r in replies]).lower()
        
        full_text = f"{title} {content} {replies_text}"

        risk_category = "NO_SIGNIFICANT_RISK"
        triggering_evidence = "Routine discussion without high-risk indicators"

        if any(k in full_text for k in ["terrorist", "bomb", "explosive", "attack plan", "hostage", "assassination"]):
            risk_category = "TERRORIST_ATTACK"
            triggering_evidence = "Keywords/context indicating violent terrorist threat"
        elif any(k in full_text for k in ["kill", "shoot", "attack physical", "threat to life", "physical violence"]):
            risk_category = "VIOLENT_THREAT"
            triggering_evidence = "Keywords/context indicating direct physical violence threat"
        elif any(k in full_text for k in ["ransomware", "lockbit", "encryptor", "double extortion", "tor leak site", "ransom note"]):
            risk_category = "RANSOMWARE"
            triggering_evidence = "Extortion & ransomware operation evidence detected"
        elif any(k in full_text for k in ["leak", "database dump", "stolen records", "breach", "exposed s3"]):
            risk_category = "DATA_LEAK"
            triggering_evidence = "Unauthorized data leak / database disclosure evidence"
        elif any(k in full_text for k in ["credential", "password dump", "access key", "api token", "login list"]):
            risk_category = "CREDENTIAL_ACCESS"
            triggering_evidence = "Exposed credentials / access keys in discussion"
        elif any(k in full_text for k in ["malware", "keylogger", "stealer", "trojan", "botnet", "jackpotting"]):
            risk_category = "MALWARE_ACTIVITY"
            triggering_evidence = "Malware payload / source code distribution"
        elif any(k in full_text for k in ["exploit", "cve-", "zero-day", "rce", "buffer overflow"]):
            risk_category = "EXPLOIT_ACTIVITY"
            triggering_evidence = "Vulnerability exploit disclosure / discussion"
        elif any(k in full_text for k in ["carding", "bank account", "transfer fraud", "scam"]):
            risk_category = "FRAUD"
            triggering_evidence = "Financial fraud / carding activity"
        elif any(k in full_text for k in ["phishing", "cloned page", "credential harvesting"]):
            risk_category = "PHISHING"
            triggering_evidence = "Phishing infrastructure / template"
        elif any(k in full_text for k in ["bulletproof", "c2 server", "c2 domain", "reverse proxy"]):
            risk_category = "SUSPICIOUS_INFRASTRUCTURE"
            triggering_evidence = "Suspicious C2 / hosting infrastructure"
        elif len(full_text.strip()) > 30 and any(k in full_text for k in ["hack", "vuln", "target"]):
            risk_category = "OTHER_HIGH_RISK"
            triggering_evidence = "General high-risk cyber discussion"

        risk_state = "HIGH_ALERT" if risk_category in ConversationRiskDetector.HIGH_RISK_CATEGORIES else ("ELEVATED" if risk_category != "NO_SIGNIFICANT_RISK" else "INFORMATIONAL")

        return {
            "risk_category": risk_category,
            "risk_state": risk_state,
            "triggering_evidence": triggering_evidence,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    @staticmethod
    def dispatch_n8n_alert(event_payload: Dict[str, Any]) -> Dict[str, Any]:
        n8n_webhook_url = os.environ.get("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/ghost-alert")

        try:
            req_data = json.dumps(event_payload).encode("utf-8")
            req = urllib.request.Request(
                n8n_webhook_url,
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 201, 202):
                    return {"status": "DELIVERED", "message": "n8n email alert dispatched successfully.", "url": n8n_webhook_url}
                else:
                    return {"status": "FAILED", "message": f"n8n webhook returned HTTP {resp.status}", "url": n8n_webhook_url}
        except Exception as ex:
            return {"status": "LOCAL_QUEUED", "message": f"n8n alert recorded (Webhook {n8n_webhook_url}): {str(ex)}", "url": n8n_webhook_url}

    @staticmethod
    def dispatch_session_user_reply_alert(session_id: str, username: str, reply_content: str) -> Dict[str, Any]:
        payload = {
            "alert_type": "SESSION_USER_REPLY",
            "event": "Session User Replied",
            "session_id": session_id,
            "username": username,
            "reply_content": reply_content,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "email_subject": f"[GHOST ALERT] User '{username}' Replied in Threat Session {session_id}",
            "email_body": f"GHOST Protocol Alert System:\n\nUser '{username}' posted a new reply in active Threat Session '{session_id}'.\n\nContent Snippet:\n{reply_content[:300]}\n\nInspect details on GHOST Analyst Dashboard."
        }
        return ConversationRiskDetector.dispatch_n8n_alert(payload)

    @staticmethod
    def dispatch_source_online_alert(source_id: str, canonical_url: str, pid: int = None, previous_status: str = "OFFLINE") -> Dict[str, Any]:
        actual_pid = pid or os.getpid()
        payload = {
            "alert_type": "SOURCE_ONLINE",
            "event": "Monitored Source Came Online",
            "source_id": source_id,
            "canonical_url": canonical_url,
            "previous_status": previous_status,
            "current_status": "ONLINE / CONNECTED",
            "pid": actual_pid,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "email_subject": f"[GHOST ALERT] Source '{source_id}' is Back ONLINE (PID: {actual_pid})",
            "email_body": f"GHOST Protocol Alert System:\n\nMonitored threat source '{source_id}' ({canonical_url}) transitioned from {previous_status} to ONLINE / CONNECTED.\nActive Observer PID: {actual_pid}\n\nInspect source status on GHOST Analyst Dashboard."
        }
        return ConversationRiskDetector.dispatch_n8n_alert(payload)
