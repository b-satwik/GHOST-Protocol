"""
DarkWatch Local Test Lab Background Collector Adapter (Revised Architecture)
Silently ingests chat messages from controlled local services, extracts observation metadata
(Exit IP, Hash, Session, Tor/VPN Verification), and executes the DarkWatch pipeline in the background.
"""

import os
import sys
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from services.local_lab.db import get_connection, get_post_by_id
from src.pipeline.inference_engine import InferenceEngine

_engine_instance: Optional[InferenceEngine] = None

def get_inference_engine() -> InferenceEngine:
    global _engine_instance
    if _engine_instance is None:
        models_dir = os.path.join(repo_root, "models")
        _engine_instance = InferenceEngine(models_dir=models_dir)
    return _engine_instance

class LocalLabAdapter:
    """
    Background Observation Processor.
    Receives submitted content, creates an observation record with network path metadata,
    and silently processes it through the DarkWatch pipeline into SQLite storage.
    """

    @staticmethod
    def process_message(
        post_id: int,
        session_id: str = "sess_local",
        network_path: str = "DIRECT",
        tor_verified: bool = False,
        vpn_verified: bool = False,
        observed_exit_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        post = get_post_by_id(post_id)
        if not post:
            raise ValueError(f"Post ID {post_id} not found")

        conn = get_connection()
        cursor = conn.cursor()

        service_id = post["service_id"]
        obs_id = f"obs_{service_id}_{post_id:05d}"
        now = datetime.utcnow().isoformat() + "Z"
        
        # Calculate SHA256 content hash
        content_hash = hashlib.sha256(post["text"].encode("utf-8")).hexdigest()

        # 1. Create Background Observation Record
        cursor.execute("SELECT * FROM observations WHERE message_id = ?", (post_id,))
        obs_row = cursor.fetchone()
        if not obs_row:
            cursor.execute("""
                INSERT INTO observations (
                    observation_id, timestamp, service_id, network_path,
                    username, session_id, thread_id, message_id,
                    message_text, content_hash, tor_verified, vpn_verified, observed_exit_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                obs_id, now, service_id, network_path,
                post["author_handle"], session_id, post["thread_id"], post_id,
                post["text"], content_hash, int(tor_verified), int(vpn_verified), observed_exit_ip
            ))
            conn.commit()
        else:
            obs_id = obs_row["observation_id"]

        # 2. Execute Silent DarkWatch Pipeline Inference Engine
        engine = get_inference_engine()
        pipeline_input = {
            "text": post["text"],
            "sanitized_text": post["text"],
            "listing_name": post["thread_title"],
            "onion_address": f"http://127.0.0.1:{service_id}",
            "source_id": f"SERVICE_{service_id}"
        }

        try:
            result = engine.predict(pipeline_input, deep_explain=False, stix_bundle_id=f"bundle-{obs_id}")
        except Exception as e:
            result = {
                "error": str(e),
                "text_model": {"predicted_class": "ANALYSIS_ERROR", "confidence": 0.0},
                "cti_bridge": {"extracted_indicators": [], "enriched_mitre": []},
                "risk": {"severity": "UNKNOWN", "risk_score": 0.0},
                "xai": {"explanation": "Analysis unavailable.", "xai_status": "ERROR"}
            }

        text_model = result.get("text_model", {})
        predicted_class = text_model.get("predicted_class", "UNKNOWN")
        confidence = float(text_model.get("confidence", 0.0))

        cti_bridge = result.get("cti_bridge", {})
        indicators = cti_bridge.get("extracted_indicators", [])
        if isinstance(indicators, dict):
            indicators = [indicators]
        mitre_techs = cti_bridge.get("enriched_mitre", [])

        risk = result.get("risk", {})
        risk_score = float(risk.get("risk_score", result.get("fusion", {}).get("fusion_score", 0.0)))
        risk_severity = risk.get("severity", "LOW")

        xai = result.get("xai", {})
        xai_summary = xai.get("explanation", xai.get("xai_status", "Analysis completed."))

        # 3. Store Pipeline Outputs in SQLite Database silently
        cursor.execute("SELECT * FROM analysis_results WHERE observation_id = ?", (obs_id,))
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO analysis_results (
                    observation_id, prediction, confidence, severity,
                    risk_score, cti, mitre, xai, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                obs_id, predicted_class, confidence, risk_severity,
                risk_score, json.dumps(indicators), json.dumps(mitre_techs),
                str(xai_summary), now
            ))
            conn.commit()

        conn.close()

        return {
            "observation_id": obs_id,
            "service_id": service_id,
            "network_path": network_path,
            "tor_verified": tor_verified,
            "vpn_verified": vpn_verified,
            "content_hash": content_hash,
            "status": "stored_silently"
        }

    @staticmethod
    def process_all_unprocessed():
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT p.id FROM posts p LEFT JOIN observations o ON p.id = o.message_id WHERE o.id IS NULL")
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            LocalLabAdapter.process_message(row["id"])
