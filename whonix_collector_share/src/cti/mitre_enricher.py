"""
MITRE ATT&CK Local Enrichment Engine for DarkWatch CTI Pipeline.
Enriches CTI observations with official MITRE ATT&CK Enterprise STIX 2.1 metadata,
sub-technique parent resolution, tactics, descriptions, and related STIX mitigations.
"""

from typing import Dict, Any, List, Optional
from src.cti.mitre_kb import MITREKnowledgeBase


class MITREEnricher:
    """
    Local enrichment engine for MITRE ATT&CK Enterprise STIX 2.1 threat intelligence.
    """

    def __init__(self, kb: Optional[MITREKnowledgeBase] = None):
        self.kb = kb or MITREKnowledgeBase()

    def enrich_technique(
        self,
        technique_id: str,
        mapping_method: str = "EXPLICIT_EVIDENCE",
        confidence: float = 0.90,
        matched_evidence: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Enriches a single technique ID with official local STIX 2.1 metadata and mitigations.

        Args:
            technique_id (str): Technique ID (e.g. T1078 or T1078.004)
            mapping_method (str): "EXPLICIT_EVIDENCE" or "WEAK_KEYWORD_ASSOCIATION"
            confidence (float): Mapping confidence score
            matched_evidence (Optional[List[str]]): Evidence terms matched in raw text

        Returns:
            Optional[Dict[str, Any]]: Enriched MITRE object structure
        """
        tech_data = self.kb.get_technique_by_id(technique_id)
        if not tech_data:
            return None

        # Resolve parent technique info if this is a sub-technique
        parent_info = None
        if tech_data["is_subtechnique"] and tech_data.get("parent_technique_id"):
            parent_tech = self.kb.get_technique_by_id(tech_data["parent_technique_id"])
            if parent_tech:
                parent_info = {
                    "technique_id": parent_tech["technique_id"],
                    "technique_name": parent_tech["technique_name"],
                    "url": parent_tech["url"]
                }

        # Resolve related mitigations (courses of action)
        mitigations = self.kb.get_mitigations_for_technique(technique_id)

        # Build clean structured enrichment separating evidence, mapping, and knowledge
        enriched = {
            "technique_id": tech_data["technique_id"],
            "technique_name": tech_data["technique_name"],
            "is_subtechnique": tech_data["is_subtechnique"],
            "parent_technique": parent_info,
            "tactics": tech_data["tactics"],
            "description": tech_data["description"],
            "url": tech_data["url"],
            "darkwatch_mapping": {
                "mapping_method": mapping_method,
                "confidence": round(confidence, 2),
                "matched_evidence": matched_evidence or []
            },
            "mitigations": [
                {
                    "mitigation_id": m["mitigation_id"],
                    "name": m["name"],
                    "description": m["description"],
                    "url": m["url"]
                } for m in mitigations
            ]
        }

        return enriched

    def enrich_cti_observation(self, cti_observation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main enrichment API method.
        Enriches a complete CTI observation dictionary containing extracted indicators, text,
        or MITRE mappings.

        Args:
            cti_observation (Dict[str, Any]): CTI observation structure

        Returns:
            Dict[str, Any]: Enriched CTI observation payload
        """
        text = cti_observation.get("sanitized_text") or cti_observation.get("text", "")
        mitre_mappings = cti_observation.get("mitre_mappings", [])
        correlated_indicators = cti_observation.get("correlated_indicators", [])

        enriched_techniques = []
        seen_tech_ids = set()

        # 1. Enrich technique mappings passed in observation
        for m in mitre_mappings:
            tech_id = m.get("technique_id")
            if tech_id and tech_id not in seen_tech_ids:
                seen_tech_ids.add(tech_id)
                evidence = m.get("evidence", "")
                evidence_list = [e.strip() for e in evidence.split(",") if e.strip()] if isinstance(evidence, str) else []
                
                enriched_tech = self.enrich_technique(
                    technique_id=tech_id,
                    mapping_method=m.get("mapping_method", "EXPLICIT_EVIDENCE"),
                    confidence=m.get("confidence", 0.90),
                    matched_evidence=evidence_list
                )
                if enriched_tech:
                    enriched_techniques.append(enriched_tech)

        # 2. Extract and match additional sub-techniques or techniques based on extracted CVEs / terms
        for ind in correlated_indicators:
            val = ind.get("normalized_value", "").lower()
            ind_type = ind.get("indicator_type", "")
            
            # Map CVEs to T1190 Exploit Public-Facing Application
            if ind_type == "vulnerability-cve" and "T1190" not in seen_tech_ids:
                seen_tech_ids.add("T1190")
                enriched_tech = self.enrich_technique(
                    technique_id="T1190",
                    mapping_method="EXPLICIT_EVIDENCE",
                    confidence=0.95,
                    matched_evidence=[ind["normalized_value"]]
                )
                if enriched_tech:
                    enriched_techniques.append(enriched_tech)

        enriched_payload = dict(cti_observation)
        enriched_payload["enriched_mitre_techniques"] = enriched_techniques
        enriched_payload["mitre_enrichment_source"] = "Official MITRE ATT&CK Enterprise STIX 2.1"
        return enriched_payload
