"""
DarkWatch Collector -> Preprocessing -> ML Pipeline Lab Bridge.
Connects live observation of controlled Docker laboratory endpoints to the DarkWatch ML Inference Engine.

Flow:
Authorized Docker / Whonix observation
        ↓
Collector / telemetry acquisition
        ↓
Boundary sanitization + deduplication
        ↓
DarkWatch ML inference
        ↓
HM-TIF fusion result
"""

import os
import sys
import time
import uuid
import datetime
import json
import argparse
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

# Ensure repository root is in sys.path
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.collector.sanitizer import ContentSanitizer
from src.deduplication.minhash_lsh import MinHashLSHDeduplicator
from src.dataset.schema import GoldRecord
from src.pipeline.inference_engine import InferenceEngine


class DarkWatchLabBridge:
    """
    Bridge module connecting the DarkWatch Docker Laboratory observation environment
    to the DarkWatch ML Inference & Risk Fusion Engine.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        models_dir: Optional[str] = None,
        jaccard_threshold: float = 0.85
    ):
        self.base_url = base_url.rstrip("/")
        self.sanitizer = ContentSanitizer()
        self.deduplicator = MinHashLSHDeduplicator(jaccard_threshold=jaccard_threshold)
        
        if models_dir is None:
            models_dir = os.path.join(repo_root, "models")
        self.engine = InferenceEngine(models_dir=models_dir)

    def observe_endpoint(
        self,
        endpoint_path_or_url: str,
        session_token: Optional[str] = None,
        network_telemetry: Optional[Dict[str, Any]] = None,
        temporal_telemetry: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end observation pipeline over a laboratory endpoint.
        
        Steps:
        1. Collector / Telemetry acquisition via HTTP GET
        2. Boundary sanitization using ContentSanitizer
        3. MinHash / LSH Deduplication & Provenance Tracking
        4. ML Data conversion & DarkWatch Inference Engine execution
        5. Return unified result object
        """
        # 1. Resolve Target URL
        if endpoint_path_or_url.startswith("http://") or endpoint_path_or_url.startswith("https://"):
            full_url = endpoint_path_or_url
            parts = endpoint_path_or_url.split("//", 1)[-1].split("/", 1)
            endpoint_path = "/" + parts[1] if len(parts) > 1 else "/"
        else:
            endpoint_path = endpoint_path_or_url if endpoint_path_or_url.startswith("/") else "/" + endpoint_path_or_url
            full_url = f"{self.base_url}{endpoint_path}"

        obs_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # 2. Collector / Telemetry Acquisition
        headers = {
            "User-Agent": "DarkWatch-LabBridge/1.0 (Authorized Laboratory Observer)"
        }
        if session_token:
            headers["Authorization"] = f"Bearer {session_token}"
            headers["Cookie"] = f"session_token={session_token}"

        raw_body = ""
        http_status = 0
        response_time_ms = 0
        fetch_error = None

        start_time = time.time()
        try:
            req = urllib.request.Request(full_url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                http_status = resp.status
                raw_bytes = resp.read()
                raw_body = raw_bytes.decode("utf-8", errors="replace")
                response_time_ms = int((time.time() - start_time) * 1000)
        except urllib.error.HTTPError as e:
            http_status = e.code
            response_time_ms = int((time.time() - start_time) * 1000)
            try:
                raw_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                raw_body = ""
            fetch_error = str(e)
        except Exception as e:
            http_status = 0
            response_time_ms = int((time.time() - start_time) * 1000)
            fetch_error = str(e)

        # 3. Boundary Sanitization
        sanitized_text = ""
        text_length = 0
        sha256_hash = ""
        text_status = "UNKNOWN"

        if http_status == 200:
            sanitized_text, text_length, sha256_hash = self.sanitizer.sanitize_html(raw_body)
            if text_length > 0:
                text_status = "CONTENT_ACCESSIBLE"
            else:
                text_status = "EMPTY_CONTENT"
        elif http_status == 503:
            text_status = "AUTOMATED_ACCESS_BLOCKED"
            sanitized_text = ""
            text_length = 0
            sha256_hash = self.sanitizer.compute_sha256("")
        elif http_status in (401, 403):
            text_status = "SESSION_GATED_ACCESS"
            sanitized_text = ""
            text_length = 0
            sha256_hash = self.sanitizer.compute_sha256("")
        else:
            text_status = f"UNAVAILABLE_HTTP_{http_status}" if http_status > 0 else "CONNECTION_FAILED"
            sanitized_text = ""
            text_length = 0
            sha256_hash = self.sanitizer.compute_sha256("")

        # 4. Deduplication Check (MinHash / LSH)
        is_duplicate = False
        duplicate_of = None
        dedup_stats = {}

        if text_length > 0:
            rec_id = f"obs_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            gold_rec = GoldRecord(
                sanitized_text=sanitized_text,
                provenance={
                    "source_id": endpoint_path,
                    "onion_address": full_url,
                    "timestamp": obs_timestamp,
                    "sanitized_sha256": sha256_hash,
                    "http_status": http_status
                },
                record_id=rec_id
            )

            canonical_recs, dedup_stats = self.deduplicator.process_records([gold_rec])
            if gold_rec.provenance.get("is_duplicate"):
                is_duplicate = True
                duplicate_of = gold_rec.provenance.get("duplicate_of")
                if text_status == "CONTENT_ACCESSIBLE":
                    dup_obs = gold_rec.provenance.get("duplicate_observations", [])
                    is_exact = dup_obs[-1].get("exact_match") if dup_obs else False
                    text_status = "EXACT_DUPLICATE" if is_exact else "NEAR_DUPLICATE_MIRROR"

        # 5. Convert Telemetry & Call DarkWatch ML Inference Pipeline
        ml_input = {
            "source_id": endpoint_path,
            "onion_address": full_url,
            "listing_name": f"Observation of {endpoint_path}",
            "http_status": http_status,
            "response_time_ms": response_time_ms
        }

        # Include text only if genuinely accessible
        if text_status in ("CONTENT_ACCESSIBLE", "NEAR_DUPLICATE_MIRROR", "EXACT_DUPLICATE") and text_length > 0:
            ml_input["text"] = sanitized_text
            ml_input["sanitized_text"] = sanitized_text
        else:
            ml_input["text"] = ""
            ml_input["sanitized_text"] = ""

        # Attach genuine temporal features if available
        if temporal_telemetry and isinstance(temporal_telemetry, dict):
            ml_input.update(temporal_telemetry)

        # Attach genuine network features if available
        if network_telemetry and isinstance(network_telemetry, dict):
            ml_input.update(network_telemetry)

        # Run Inference Engine
        pipeline_output = self.engine.predict(ml_input)

        # 6. Format Unified Result
        fusion_info = pipeline_output.get("fusion", {})
        risk_info = pipeline_output.get("risk", {})

        unified_result = {
            "source": full_url,
            "endpoint": endpoint_path,
            "observation_timestamp": obs_timestamp,
            "http_status": http_status,
            "response_time_ms": response_time_ms,
            "sanitized_text_status": text_status,
            "text_length": text_length,
            "sha256": sha256_hash,
            "sanitized_text": sanitized_text,
            "deduplication": {
                "is_duplicate": is_duplicate,
                "duplicate_of": duplicate_of,
                "stats": dedup_stats
            },
            "modality_availability": fusion_info.get("available_modalities", {}),
            "text_prediction": pipeline_output.get("text_model", {}),
            "network_prediction": pipeline_output.get("network_model", {}),
            "temporal_result": pipeline_output.get("temporal_model", {}),
            "behavior_result": pipeline_output.get("behavior_model", {}),
            "fusion_score": fusion_info.get("fusion_score", 0.0),
            "fusion_description": fusion_info.get("fusion_formula_description", ""),
            "risk_score": risk_info.get("risk_score", 0.0),
            "risk_severity": risk_info.get("severity", "LOW"),
            "cti_entities": pipeline_output.get("cti_entities", {}),
            "mitre_mappings": pipeline_output.get("mitre", []),
            "xai": pipeline_output.get("xai", {}),
            "alert": pipeline_output.get("alert", {})
        }

        if fetch_error:
            unified_result["fetch_error"] = fetch_error

        return unified_result


def main():
    parser = argparse.ArgumentParser(description="DarkWatch Laboratory Observation Bridge CLI")
    parser.add_argument("--base-url", type=str, default="http://127.0.0.1:8080", help="Base URL of Docker Lab")
    parser.add_argument("--endpoint", type=str, default="/forum", help="Lab endpoint to observe")
    parser.add_argument("--session-token", type=str, help="Optional session token for auth endpoints")
    parser.add_argument("--all", action="store_true", help="Observe all lab endpoints sequentially")
    args = parser.parse_args()

    bridge = DarkWatchLabBridge(base_url=args.base_url)

    if args.all:
        endpoints = ["/forum", "/market", "/paste", "/leak", "/barrier", "/session_gated", "/dynamic_forum", "/forum_mirror"]
        print(f"[+] Running observation across all {len(endpoints)} lab endpoints...")
        for ep in endpoints:
            res = bridge.observe_endpoint(ep)
            print(f"\n--- Endpoint: {ep} (HTTP {res['http_status']}) ---")
            print(f"Text Status:  {res['sanitized_text_status']}")
            print(f"Modalities:   {res['modality_availability']}")
            print(f"Text Class:   {res['text_prediction'].get('predicted_class')}")
            print(f"Fusion Score: {res['fusion_score']}")
    else:
        res = bridge.observe_endpoint(args.endpoint, session_token=args.session_token)
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
