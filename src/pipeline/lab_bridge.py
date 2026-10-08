"""
DarkWatch Collector -> Preprocessing -> ML Pipeline Lab Bridge.
Connects live observation of controlled Docker laboratory endpoints to the DarkWatch ML Inference Engine,
CTI Extraction, and STIX 2.1 Bundle serialization.

Flow:
Authorized Docker / Whonix observation
        ↓
Collector / telemetry acquisition
        ↓
Boundary sanitization + deduplication
        ↓
CTI Indicator extraction + STIX 2.1 Bundle generation
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
from src.cti.stix_extractor import STIXExtractor
from src.cti.stix_generator import STIXGenerator
from src.cti.misp_mitre_correlator import MISPMITRECorrelator
from src.cti.mitre_enricher import MITREEnricher
from src.cti.cti_store import CTIStore
from src.xai.conditional_xai import ConditionalXAIEngine
from src.pipeline.inference_engine import InferenceEngine


class DarkWatchLabBridge:
    """
    Bridge module connecting the DarkWatch Docker Laboratory observation environment
    to the DarkWatch CTI Extractor, STIX 2.1 Generator, MISP & MITRE ATT&CK Correlator,
    Local CTI Store, ML Inference & Two-Tier XAI Engine.
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
        self.stix_extractor = STIXExtractor()
        self.stix_generator = STIXGenerator()
        self.correlator = MISPMITRECorrelator()
        self.enricher = MITREEnricher(kb=self.correlator.mitre_mapper.kb)
        self.cti_store = CTIStore()
        self.xai_engine = ConditionalXAIEngine()
        
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
        4. CTI Indicator extraction & STIX 2.1 Bundle serialization
        5. ML Data conversion & DarkWatch Inference Engine execution
        6. Return unified result object
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

        # 5. CTI Extraction, Correlation, MITRE Mapping, CTI Store Lookup & STIX 2.1 Bundle Generation
        extracted_indicators = []
        correlated_indicators = []
        mitre_mappings = []
        enriched_mitre_techniques = []
        cti_lookup_results = []
        stix_bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": []}

        if text_status in ("CONTENT_ACCESSIBLE", "NEAR_DUPLICATE_MIRROR", "EXACT_DUPLICATE") and text_length > 0:
            # 5.1 Extract Indicators
            raw_indicators = self.stix_extractor.extract_indicators(sanitized_text)

            # 5.2 Correlate with MISP Taxonomies & MITRE ATT&CK KB
            correlation = self.correlator.correlate(raw_indicators, sanitized_text)
            correlated_indicators = correlation.get("correlated_indicators", [])
            mitre_mappings = correlation.get("mitre_mappings", [])

            # 5.3 MITRE Local Offline STIX 2.1 Enrichment
            enrichment_payload = {
                "sanitized_text": sanitized_text,
                "correlated_indicators": correlated_indicators,
                "mitre_mappings": mitre_mappings
            }
            enriched_cti = self.enricher.enrich_cti_observation(enrichment_payload)
            enriched_mitre_techniques = enriched_cti.get("enriched_mitre_techniques", [])

            # 5.4 Exact/Local CTI Store Lookup
            for ind in correlated_indicators:
                norm_val = ind.get("normalized_value", "")
                if norm_val:
                    prior_matches = self.cti_store.lookup_indicator(norm_val)
                    cti_lookup_results.append({
                        "indicator": norm_val,
                        "indicator_type": ind.get("indicator_type"),
                        "prior_matches_count": len(prior_matches),
                        "historical_evidence": prior_matches
                    })

            # 5.5 Generate STIX 2.1 Bundle with Attack Patterns & Mitigations
            effective_mitre = enriched_mitre_techniques if enriched_mitre_techniques else mitre_mappings
            stix_bundle = self.stix_generator.build_stix_bundle(
                onion_address=full_url,
                timestamp=obs_timestamp,
                correlated_indicators=correlated_indicators,
                mitre_mappings=effective_mitre
            )

            # 5.6 Save CTI Results to Local Store
            try:
                self.cti_store.save_cti_results(
                    source_record_id=1,
                    onion_address=full_url,
                    timestamp=obs_timestamp,
                    stix_bundle=stix_bundle,
                    correlated_indicators=correlated_indicators,
                    mitre_mappings=effective_mitre
                )
            except Exception:
                pass

            extracted_indicators = correlated_indicators

        # 6. Convert Telemetry & Call DarkWatch ML Inference Pipeline
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

        # 7. Format Unified Result
        fusion_info = pipeline_output.get("fusion", {})
        risk_info = pipeline_output.get("risk", {})

        # 8. Two-Tier XAI Explanation Generation
        xai_result = self.xai_engine.explain(
            record=ml_input,
            model_results=pipeline_output,
            risk_result=risk_info
        )

        stix_objects = stix_bundle.get("objects", [])
        stix_object_types = sorted(list(set(obj["type"] for obj in stix_objects)))

        effective_mitre = enriched_mitre_techniques if enriched_mitre_techniques else mitre_mappings

        unified_result = {
            "source": full_url,
            "endpoint": endpoint_path,
            "observation_timestamp": obs_timestamp,
            "data_provenance": "CONTROLLED_SYNTHETIC_LAB_RESEARCH",
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
            "cti": {
                "extracted_indicators_count": len(extracted_indicators),
                "indicators": extracted_indicators,
                "cti_entities": pipeline_output.get("cti_entities", {}),
                "cti_lookup": cti_lookup_results
            },
            "mitre_mapping": {
                "mapped_techniques_count": len(effective_mitre),
                "techniques": effective_mitre,
                "source_reference": "Official MITRE ATT&CK Enterprise STIX 2.1"
            },
            "stix": {
                "bundle_id": stix_bundle.get("id"),
                "spec_version": stix_bundle.get("spec_version", "2.1"),
                "stix_objects_count": len(stix_objects),
                "stix_object_types": stix_object_types,
                "bundle": stix_bundle
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
            "xai": xai_result
        }

        if fetch_error:
            unified_result["fetch_error"] = fetch_error

        return unified_result

    def process_stage1_observation(
        self,
        observation: Any,
        network_telemetry: Optional[Dict[str, Any]] = None,
        temporal_telemetry: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Processes a Stage 1 ObservationRecord object through the DarkWatch pipeline.
        
        Steps:
        1. Extract text and metadata from ObservationRecord
        2. Perform boundary sanitization via ContentSanitizer
        3. Execute MinHash/LSH Deduplication
        4. Run CTI Indicator extraction, MITRE mapping, & STIX 2.1 Bundle generation
        5. Invoke DarkWatch ML Inference Engine
        6. Return unified pipeline output
        """
        full_url = getattr(observation, "url", "http://127.0.0.1:8080/stage1")
        source_id = getattr(observation, "source_id", "stage1_source")
        raw_html = getattr(observation, "raw_html", "")
        clean_text_in = getattr(observation, "clean_text", "")
        obs_status = getattr(observation, "status", "CONTENT_ACCESSIBLE")
        obs_timestamp = getattr(observation, "timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

        # Sanitization
        if clean_text_in:
            sanitized_text = clean_text_in
            text_length = len(sanitized_text)
            sha256_hash = self.sanitizer.compute_sha256(sanitized_text)
        elif raw_html:
            sanitized_text, text_length, sha256_hash = self.sanitizer.sanitize_html(raw_html)
        else:
            sanitized_text = ""
            text_length = 0
            sha256_hash = self.sanitizer.compute_sha256("")

        text_status = obs_status if text_length > 0 else "EMPTY_CONTENT"

        # Deduplication
        is_duplicate = False
        duplicate_of = None
        dedup_stats = {}

        if text_length > 0:
            rec_id = f"obs_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            gold_rec = GoldRecord(
                sanitized_text=sanitized_text,
                provenance={
                    "source_id": source_id,
                    "onion_address": full_url,
                    "timestamp": obs_timestamp,
                    "sanitized_sha256": sha256_hash,
                    "http_status": 200
                },
                record_id=rec_id
            )
            canonical_recs, dedup_stats = self.deduplicator.process_records([gold_rec])
            if gold_rec.provenance.get("is_duplicate"):
                is_duplicate = True
                duplicate_of = gold_rec.provenance.get("duplicate_of")

        # CTI Extraction & STIX Generation
        extracted_indicators = []
        correlated_indicators = []
        mitre_mappings = []
        enriched_mitre_techniques = []
        cti_lookup_results = []
        stix_bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": []}

        if text_length > 0:
            raw_indicators = self.stix_extractor.extract_indicators(sanitized_text)
            correlation = self.correlator.correlate(raw_indicators, sanitized_text)
            correlated_indicators = correlation.get("correlated_indicators", [])
            mitre_mappings = correlation.get("mitre_mappings", [])

            enrichment_payload = {
                "sanitized_text": sanitized_text,
                "correlated_indicators": correlated_indicators,
                "mitre_mappings": mitre_mappings
            }
            enriched_cti = self.enricher.enrich_cti_observation(enrichment_payload)
            enriched_mitre_techniques = enriched_cti.get("enriched_mitre_techniques", [])

            stix_bundle = self.stix_generator.build_stix_bundle(
                onion_address=full_url,
                timestamp=obs_timestamp,
                correlated_indicators=correlated_indicators,
                mitre_mappings=enriched_mitre_techniques if enriched_mitre_techniques else mitre_mappings
            )
            extracted_indicators = correlated_indicators

        # ML Inference Engine call
        ml_input = {
            "source_id": source_id,
            "onion_address": full_url,
            "listing_name": f"Stage 1 Observation of {source_id}",
            "http_status": 200,
            "response_time_ms": 100,
            "text": sanitized_text if text_length > 0 else "",
            "sanitized_text": sanitized_text if text_length > 0 else ""
        }
        if temporal_telemetry:
            ml_input.update(temporal_telemetry)
        if network_telemetry:
            ml_input.update(network_telemetry)

        pipeline_output = self.engine.predict(ml_input)
        fusion_info = pipeline_output.get("fusion", {})
        risk_info = pipeline_output.get("risk", {})

        xai_result = self.xai_engine.explain(
            record=ml_input,
            model_results=pipeline_output,
            risk_result=risk_info
        )

        effective_mitre = enriched_mitre_techniques if enriched_mitre_techniques else mitre_mappings

        return {
            "source": full_url,
            "source_id": source_id,
            "observation_timestamp": obs_timestamp,
            "data_provenance": "GHOST_PROTOCOL_STAGE1_OBSERVATION",
            "http_status": 200,
            "sanitized_text_status": text_status,
            "text_length": text_length,
            "sha256": sha256_hash,
            "sanitized_text": sanitized_text,
            "deduplication": {
                "is_duplicate": is_duplicate,
                "duplicate_of": duplicate_of,
                "stats": dedup_stats
            },
            "cti": {
                "extracted_indicators_count": len(extracted_indicators),
                "indicators": extracted_indicators,
                "cti_entities": pipeline_output.get("cti_entities", {})
            },
            "mitre_mapping": {
                "mapped_techniques_count": len(effective_mitre),
                "techniques": effective_mitre
            },
            "stix": {
                "bundle_id": stix_bundle.get("id"),
                "stix_objects_count": len(stix_bundle.get("objects", [])),
                "bundle": stix_bundle
            },
            "modality_availability": fusion_info.get("available_modalities", {}),
            "text_prediction": pipeline_output.get("text_model", {}),
            "network_prediction": pipeline_output.get("network_model", {}),
            "temporal_result": pipeline_output.get("temporal_model", {}),
            "behavior_result": pipeline_output.get("behavior_model", {}),
            "fusion": fusion_info,
            "fusion_score": fusion_info.get("fusion_score", 0.0),
            "risk_score": risk_info.get("risk_score", 0.0),
            "risk_severity": risk_info.get("severity", "LOW"),
            "xai": xai_result
        }



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
            print(f"Indicators:   {res['cti']['extracted_indicators_count']} extracted")
            print(f"STIX Bundle:  {res['stix']['bundle_id']} ({res['stix']['stix_objects_count']} STIX objects)")
            print(f"Text Class:   {res['text_prediction'].get('predicted_class')}")
            print(f"Fusion Score: {res['fusion_score']}")
    else:
        res = bridge.observe_endpoint(args.endpoint, session_token=args.session_token)
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
