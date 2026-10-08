"""
MISP Taxonomy & MITRE ATT&CK Correlator for DarkWatch CTI Pipeline.
Correlates extracted indicators with local MISP categories and MITRE ATT&CK Enterprise techniques.
Strictly distinguishes observed evidence from knowledge-base matches.
"""

from typing import Dict, Any, List
from src.cti.mitre_mapper import MITREMapper


class MISPMITRECorrelator:
    """
    Correlates extracted threat indicators with MISP taxonomies and MITRE ATT&CK techniques.
    """

    MISP_CATEGORY_MAPPING = {
        "onion-url": "Network activity",
        "onion-domain": "Network activity",
        "url": "Network activity",
        "domain-name": "Network activity",
        "ipv4-addr": "Network activity",
        "file-hash-md5": "Payload delivery",
        "file-hash-sha1": "Payload delivery",
        "file-hash-sha256": "Payload delivery",
        "vulnerability-cve": "External targeting",
        "malware-name": "Payload delivery",
        "tool-name": "Attack tools"
    }

    def __init__(self, kb_path: str = None):
        self.mitre_mapper = MITREMapper(kb_path=kb_path)

    def correlate(
        self,
        extracted_indicators: List[Dict[str, Any]],
        text: str
    ) -> Dict[str, Any]:
        """
        Correlates extracted indicators against MISP categories and MITRE ATT&CK techniques.

        Args:
            extracted_indicators (List[Dict[str, Any]]): List of indicator dicts from STIXExtractor
            text (str): Raw or sanitized text content

        Returns:
            Dict[str, Any]: Correlation result containing categorized indicators and MITRE mappings
        """
        correlated_indicators = []

        # 1. Apply MISP Taxonomy Categorization to Observed Evidence
        for ind in extracted_indicators:
            ind_type = ind.get("indicator_type", "unknown")
            misp_cat = self.MISP_CATEGORY_MAPPING.get(ind_type, "Other")
            
            item = dict(ind)
            item["misp_category"] = misp_cat
            item["is_observed"] = True
            correlated_indicators.append(item)

        # 2. Convert indicators to ThreatExtractor entity format for MITREMapper
        cves = [ind["normalized_value"] for ind in extracted_indicators if ind["indicator_type"] == "vulnerability-cve"]
        malware = [ind["normalized_value"] for ind in extracted_indicators if ind["indicator_type"] == "malware-name"]
        tools = [ind["normalized_value"] for ind in extracted_indicators if ind["indicator_type"] == "tool-name"]
        ips = [ind["normalized_value"] for ind in extracted_indicators if ind["indicator_type"] == "ipv4-addr"]
        onions = [ind["normalized_value"] for ind in extracted_indicators if ind["indicator_type"] in ["onion-url", "onion-domain"]]
        hashes = [ind["normalized_value"] for ind in extracted_indicators if ind["indicator_type"].startswith("file-hash")]

        extracted_entities = {
            "entities": {
                "cve_ids": cves,
                "malware": malware,
                "attack_tools": tools,
                "ipv4_addresses": ips,
                "onion_domains": onions,
                "hashes": hashes
            }
        }

        # 3. MITRE ATT&CK Mapping
        mitre_mappings = self.mitre_mapper.map_threats(extracted_entities, text)

        # Add explicit KB match flag to MITRE technique mappings
        for m in mitre_mappings:
            m["is_observed"] = False  # Derived Knowledge-Base Match

        return {
            "correlated_indicators": correlated_indicators,
            "mitre_mappings": mitre_mappings
        }
