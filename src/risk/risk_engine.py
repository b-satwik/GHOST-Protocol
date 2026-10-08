"""
Transparent Risk & Severity Engine for DarkWatch XAI.
Decouples raw ML model outputs from organizational risk policy rules.
Calculates transparent risk scores, severity levels (LOW, MODERATE, ELEVATED, HIGH),
and policy rationales using configurable weights.
"""

import json
import os
from typing import Dict, Any, List
from src.interfaces.base_interfaces import RiskEngineInterface

class RiskEngine(RiskEngineInterface):
    """
    Policy-based transparent risk calculation engine.
    """
    
    def __init__(self, policy_path: str = None):
        if policy_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            policy_path = os.path.join(base_dir, "config", "risk_policy.json")
            
        self.policy_path = policy_path
        self.policy = self._load_policy()
        
    def _load_policy(self) -> Dict[str, Any]:
        default_policy = {
            "policy_name": "DarkWatch XAI Transparent Analyst Risk Policy",
            "weights": {
                "ml_fusion_weight": 0.50,
                "mitre_cti_weight": 0.30,
                "entity_criticality_weight": 0.20
            },
            "severity_thresholds": {
                "LOW": 0.35,
                "MODERATE": 0.55,
                "ELEVATED": 0.75,
                "HIGH": 1.00
            }
        }
        if os.path.exists(self.policy_path):
            try:
                with open(self.policy_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return default_policy

    def evaluate_risk(
        self,
        fusion_score: float,
        text_prediction: Dict[str, Any],
        mitre_mappings: List[Dict[str, Any]],
        extracted_threats: Dict[str, Any],
        behavioral_result: Dict[str, Any],
        temporal_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate transparent risk score and severity band based on multi-source evidence.
        """
        weights = self.policy.get("weights", {})
        w_ml = weights.get("ml_fusion_weight", 0.50)
        w_cti = weights.get("mitre_cti_weight", 0.30)
        w_entity = weights.get("entity_criticality_weight", 0.20)
        
        contributing_factors = []
        
        # 1. ML Fusion Score Contribution
        ml_score = max(0.0, min(1.0, float(fusion_score)))
        contributing_factors.append(f"Tri-Modal ML Fusion Risk Score: {ml_score:.3f} (Weight: {w_ml:.2f})")
        
        # 2. CTI & MITRE Mapping Contribution
        num_mitre = len(mitre_mappings)
        cti_score = min(1.0, 0.25 * num_mitre)
        if num_mitre > 0:
            tech_ids = ", ".join([m["technique_id"] for m in mitre_mappings])
            contributing_factors.append(f"MITRE ATT&CK Techniques Matched: {num_mitre} [{tech_ids}] (CTI Score: {cti_score:.2f})")
        else:
            contributing_factors.append("No explicit MITRE ATT&CK techniques matched.")
            
        # 3. Entity Criticality Contribution
        entities = extracted_threats.get("entities", {})
        entity_score = 0.0
        
        if entities.get("cves"):
            entity_score += 0.35
            contributing_factors.append(f"Identified CVEs / Vulnerabilities: {', '.join(entities['cves'])}")
            
        if any("ransomware" in str(m).lower() for m in entities.get("malware", [])):
            entity_score += 0.35
            contributing_factors.append("High-Severity Malware Detected: Ransomware")
        elif entities.get("malware"):
            entity_score += 0.20
            contributing_factors.append(f"Malware/RAT Detected: {', '.join(entities['malware'])}")
            
        if entities.get("credentials_access"):
            entity_score += 0.20
            contributing_factors.append("Credential Harvest / Account Access Offerings Found")
            
        iocs = entities.get("iocs", {})
        if iocs.get("onion_domains") or iocs.get("ip_addresses") or iocs.get("hashes"):
            entity_score += 0.15
            contributing_factors.append("Actionable Technical Indicators (IOCs) Extracted")
            
        entity_score = min(1.0, entity_score)
        
        # Calculate Weighted Final Risk Score
        final_risk_score = (w_ml * ml_score) + (w_cti * cti_score) + (w_entity * entity_score)
        final_risk_score = round(max(0.0, min(1.0, final_risk_score)), 3)
        
        # Determine Severity Level
        thresholds = self.policy.get("severity_thresholds", {})
        if final_risk_score < thresholds.get("LOW", 0.35):
            severity = "LOW"
        elif final_risk_score < thresholds.get("MODERATE", 0.55):
            severity = "MODERATE"
        elif final_risk_score < thresholds.get("ELEVATED", 0.75):
            severity = "ELEVATED"
        else:
            severity = "HIGH"
            
        # Policy Rationale
        rationale = (
            f"Risk severity rated {severity} (Score: {final_risk_score:.3f}). "
            f"Calculated via transparent policy combining ML fusion ({ml_score:.2f}), "
            f"MITRE CTI correlation ({cti_score:.2f}), and critical threat entity presence ({entity_score:.2f})."
        )
        
        return {
            "risk_score": final_risk_score,
            "severity": severity,
            "components": {
                "ml_fusion_component": round(ml_score, 3),
                "cti_component": round(cti_score, 3),
                "entity_criticality_component": round(entity_score, 3)
            },
            "contributing_factors": contributing_factors,
            "policy_rationale": rationale,
            "policy_note": self.policy.get("note", "")
        }
