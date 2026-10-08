"""
Standard Alert Schema Generator for DarkWatch XAI.
Produces standardized JSON security analyst alert objects.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

class AlertGenerator:
    """
    Generates standardized JSON alerts for DarkWatch XAI security analysts.
    """
    
    @staticmethod
    def generate_alert(
        record: Dict[str, Any],
        model_results: Dict[str, Any],
        extracted_threats: Dict[str, Any],
        mitre_mappings: List[Dict[str, Any]],
        risk_result: Dict[str, Any],
        xai_result: Dict[str, Any],
        stix_bundle_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Produce a structured alert JSON dictionary.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        alert_id = f"DW-ALERT-{uuid.uuid4().hex[:8].upper()}"
        
        content = record.get("text", record.get("listing_name", record.get("sanitized_text", "Dark Web Content Record")))
        source = record.get("onion_address", record.get("marketplace", record.get("source", "Darknet Underground Market")))
        
        # Threat types
        entities = extracted_threats.get("entities", {})
        threat_types = []
        if entities.get("malware"):
            threat_types.append("Malware & RATs")
        if entities.get("vulnerabilities"):
            threat_types.append("Vulnerabilities & Exploits")
        if entities.get("credentials_access"):
            threat_types.append("Stolen Credentials & Access")
        if not threat_types:
            threat_types.append(model_results.get("text_prediction", {}).get("predicted_class", "Uncategorized Threat"))
            
        # Evidence items
        evidence = risk_result.get("contributing_factors", [])
        
        # Model Scores Summary
        text_pred = model_results.get("text_prediction", {})
        beh_res = model_results.get("behavioral_result", {})
        temp_res = model_results.get("temporal_result", {})
        
        beh_score = beh_res.get("anomaly_score")
        temp_score = temp_res.get("anomaly_score")
        
        alert_payload = {
            "alert_id": alert_id,
            "timestamp": now_iso,
            "source": source,
            "content": content,
            "risk_score": risk_result.get("risk_score", 0.0),
            "severity": risk_result.get("severity", "LOW"),
            "threat_types": threat_types,
            "indicators": entities,
            "mitre_matches": mitre_mappings,
            "evidence": evidence,
            "model_scores": {
                "text_predicted_class": text_pred.get("predicted_class", "OTHER_SEMANTIC"),
                "text_confidence": round(float(text_pred.get("confidence", 0.0)), 4),
                "behavioral_anomaly_score": round(float(beh_score), 4) if beh_score is not None else None,
                "behavioral_anomaly_flag": beh_res.get("is_anomaly_95"),
                "temporal_anomaly_score": round(float(temp_score), 4) if temp_score is not None else None,
                "temporal_anomaly_flag": temp_res.get("is_anomaly_95"),
                "tri_modal_fusion_score": round(float(model_results.get("fusion_result", {}).get("fusion_score", 0.0)), 4)
            },
            "xai": xai_result,
            "status": "NEW"
        }

        if stix_bundle_id:
            alert_payload["stix_bundle_id"] = stix_bundle_id
            
        return alert_payload

