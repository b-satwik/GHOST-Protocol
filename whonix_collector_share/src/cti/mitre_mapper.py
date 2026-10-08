"""
CTI & MITRE ATT&CK Mapping Module for DarkWatch XAI.
Correlates extracted threat entities and text with official MITRE ATT&CK Enterprise techniques.
Delegates to MITREKnowledgeBase for rich STIX 2.1 metadata and mitigations.
"""

import json
import os
from typing import Dict, Any, List
from src.interfaces.base_interfaces import CTIMapperInterface
from src.cti.mitre_kb import MITREKnowledgeBase


class MITREMapper(CTIMapperInterface):
    """
    Correlates extracted threat indicators with MITRE ATT&CK Enterprise STIX 2.1 techniques.
    """
    
    def __init__(self, kb_path: str = None):
        self.kb = MITREKnowledgeBase()
        if kb_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            kb_path = os.path.join(base_dir, "config", "mitre_knowledge_base.json")
            
        self.kb_path = kb_path
        self.techniques = self._load_knowledge_base()
        
    def _load_knowledge_base(self) -> List[Dict[str, Any]]:
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get("techniques", [])
            except Exception:
                pass
        return []

    def map_threats(self, extracted_entities: Dict[str, Any], text: str) -> List[Dict[str, Any]]:
        """
        Map threat information to MITRE ATT&CK techniques.
        Distinguishes EXPLICIT_EVIDENCE from WEAK_KEYWORD_ASSOCIATION.
        Enriches mappings with official STIX 2.1 descriptions and mitigations.
        """
        if not text or not isinstance(text, str):
            return []
            
        lower_text = text.lower()
        mappings = []
        seen_techniques = set()
        
        # Flatten explicit extracted entities for evidence checking
        entities_dict = extracted_entities.get("entities", {}) if isinstance(extracted_entities, dict) else {}
        explicit_entities = (
            entities_dict.get("cve_ids", []) +
            entities_dict.get("cves", []) +
            entities_dict.get("malware", []) +
            entities_dict.get("ransomware", []) +
            entities_dict.get("rat", []) +
            entities_dict.get("credentials", []) +
            entities_dict.get("credentials_access", []) +
            entities_dict.get("rdp_access", []) +
            entities_dict.get("onion_domains", []) +
            entities_dict.get("ipv4_addresses", []) +
            entities_dict.get("hashes", [])
        )
        explicit_terms_lower = [str(e).lower() for e in explicit_entities]
        
        # Generic weak keywords that trigger weak association
        weak_keywords = {"payload", "access", "tools", "data", "system", "file", "network", "code"}
        
        for tech in self.techniques:
            tech_id = tech["technique_id"]
            if tech_id in seen_techniques:
                continue
                
            keywords = tech.get("keywords", [])
            matched_evidence = []
            
            for kw in keywords:
                if kw in lower_text:
                    matched_evidence.append(kw)
                    
            if matched_evidence:
                seen_techniques.add(tech_id)
                
                # Determine mapping method and confidence
                has_explicit_entity = any(
                    any(exp_term in kw or kw in exp_term for exp_term in explicit_terms_lower)
                    for kw in matched_evidence
                )
                
                # Check if matches are purely weak keywords
                is_purely_weak = all(kw in weak_keywords for kw in matched_evidence)
                
                if has_explicit_entity or (not is_purely_weak and len(matched_evidence) >= 2):
                    mapping_method = "EXPLICIT_EVIDENCE"
                    confidence = 0.90 if has_explicit_entity else 0.75
                else:
                    mapping_method = "WEAK_KEYWORD_ASSOCIATION"
                    confidence = 0.50
                
                # Retrieve official STIX 2.1 details if available
                stix_data = self.kb.get_technique_by_id(tech_id)
                tactic_str = tech.get("tactic", "Unknown Tactic")
                description_str = tech.get("description", "")
                mitigations_list = []

                if stix_data:
                    if stix_data.get("tactics"):
                        tactic_str = " / ".join(stix_data["tactics"])
                    description_str = stix_data.get("description", description_str)
                    raw_mits = self.kb.get_mitigations_for_technique(tech_id)
                    mitigations_list = [
                        {
                            "mitigation_id": m["mitigation_id"],
                            "name": m["name"]
                        } for m in raw_mits
                    ]

                mappings.append({
                    "technique_id": tech_id,
                    "technique_name": stix_data.get("technique_name", tech["technique_name"]) if stix_data else tech["technique_name"],
                    "tactic": tactic_str,
                    "evidence": ", ".join(matched_evidence),
                    "mapping_method": mapping_method,
                    "confidence": round(confidence, 2),
                    "source_reference": "Official MITRE ATT&CK Enterprise STIX 2.1",
                    "description": description_str,
                    "mitigations": mitigations_list
                })
                
        return mappings
