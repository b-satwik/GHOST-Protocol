"""
Local MITRE ATT&CK Enterprise STIX 2.1 Knowledge Base Store for DarkWatch.
Parses, indexes, and serves offline lookups for official MITRE ATT&CK techniques,
sub-techniques, tactics, and STIX 2.1 mitigations (courses of action).
"""

import os
import json
from typing import Dict, Any, Optional, List


class MITREKnowledgeBase:
    """
    Offline indexed store for official MITRE ATT&CK Enterprise STIX 2.1 data.
    """

    def __init__(self, stix_json_path: Optional[str] = None):
        if stix_json_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            stix_json_path = os.path.join(base_dir, "config", "enterprise_attack_stix_2.1.json")

        self.stix_json_path = stix_json_path
        self.techniques_by_id: Dict[str, Dict[str, Any]] = {}
        self.techniques_by_stix_id: Dict[str, Dict[str, Any]] = {}
        self.subtechniques_by_parent: Dict[str, List[Dict[str, Any]]] = {}
        self.tactics_by_id: Dict[str, Dict[str, Any]] = {}
        self.tactics_by_shortname: Dict[str, Dict[str, Any]] = {}
        self.mitigations_by_id: Dict[str, Dict[str, Any]] = {}
        self.mitigations_by_stix_id: Dict[str, Dict[str, Any]] = {}
        self.mitigations_per_technique: Dict[str, List[Dict[str, Any]]] = {}

        self._load_and_index_kb()

    def _load_and_index_kb(self) -> None:
        """Parses and indexes the STIX 2.1 bundle objects."""
        if not os.path.exists(self.stix_json_path):
            return

        try:
            with open(self.stix_json_path, 'r', encoding='utf-8') as f:
                bundle = json.load(f)
        except Exception:
            return

        objects = bundle.get("objects", [])

        # Pass 1: Index Tactics, Mitigations, and Techniques
        stix_id_to_mitre_id: Dict[str, str] = {}

        for obj in objects:
            ot = obj.get("type")
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            ext_refs = obj.get("external_references", [])
            mitre_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), {})
            ext_id = mitre_ref.get("external_id", "")
            stix_id = obj.get("id", "")

            if ext_id and stix_id:
                stix_id_to_mitre_id[stix_id] = ext_id

            if ot == "attack-pattern":
                is_sub = obj.get("x_mitre_is_subtechnique", False)
                parent_id = None
                if is_sub and "." in ext_id:
                    parent_id = ext_id.split(".")[0]

                tactic_names = []
                tactic_shortnames = []
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") in ["mitre-attack", "mitre-enterprise-attack"]:
                        shortname = phase.get("phase_name", "")
                        tactic_shortnames.append(shortname)
                        # Format title name (e.g. "initial-access" -> "Initial Access")
                        title_name = shortname.replace("-", " ").title()
                        tactic_names.append(title_name)

                tech_data = {
                    "stix_id": stix_id,
                    "technique_id": ext_id,
                    "technique_name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "is_subtechnique": is_sub,
                    "parent_technique_id": parent_id,
                    "tactics": tactic_names,
                    "tactic_shortnames": tactic_shortnames,
                    "url": mitre_ref.get("url", f"https://attack.mitre.org/techniques/{ext_id}/")
                }

                self.techniques_by_id[ext_id] = tech_data
                self.techniques_by_stix_id[stix_id] = tech_data

                if is_sub and parent_id:
                    if parent_id not in self.subtechniques_by_parent:
                        self.subtechniques_by_parent[parent_id] = []
                    self.subtechniques_by_parent[parent_id].append(tech_data)

            elif ot == "x-mitre-tactic":
                shortname = obj.get("x_mitre_shortname", "")
                tac_data = {
                    "stix_id": stix_id,
                    "tactic_id": ext_id,
                    "name": obj.get("name", ""),
                    "shortname": shortname,
                    "description": obj.get("description", ""),
                    "url": mitre_ref.get("url", f"https://attack.mitre.org/tactics/{ext_id}/")
                }
                self.tactics_by_id[ext_id] = tac_data
                if shortname:
                    self.tactics_by_shortname[shortname] = tac_data

            elif ot == "course-of-action":
                mit_data = {
                    "stix_id": stix_id,
                    "mitigation_id": ext_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "url": mitre_ref.get("url", f"https://attack.mitre.org/mitigations/{ext_id}/")
                }
                self.mitigations_by_id[ext_id] = mit_data
                self.mitigations_by_stix_id[stix_id] = mit_data

        # Pass 2: Index STIX "mitigates" Relationships
        for obj in objects:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
                source_stix_id = obj.get("source_ref")
                target_stix_id = obj.get("target_ref")

                mitigation = self.mitigations_by_stix_id.get(source_stix_id)
                tech_id = stix_id_to_mitre_id.get(target_stix_id)

                if mitigation and tech_id:
                    if tech_id not in self.mitigations_per_technique:
                        self.mitigations_per_technique[tech_id] = []
                    # Append unique mitigation
                    if not any(m["mitigation_id"] == mitigation["mitigation_id"] for m in self.mitigations_per_technique[tech_id]):
                        self.mitigations_per_technique[tech_id].append(mitigation)

    def get_technique_by_id(self, tech_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves technique or sub-technique details by ATT&CK ID (e.g., T1078 or T1078.004)."""
        if not tech_id:
            return None
        return self.techniques_by_id.get(tech_id.upper())

    def get_subtechniques(self, parent_id: str) -> List[Dict[str, Any]]:
        """Retrieves child sub-techniques for a parent technique ID."""
        return self.subtechniques_by_parent.get(parent_id.upper(), [])

    def get_tactics_for_technique(self, tech_id: str) -> List[Dict[str, Any]]:
        """Retrieves tactic details for a technique."""
        tech = self.get_technique_by_id(tech_id)
        if not tech:
            return []

        res = []
        for sn in tech.get("tactic_shortnames", []):
            tac = self.tactics_by_shortname.get(sn)
            if tac:
                res.append(tac)
        return res

    def get_mitigations_for_technique(self, tech_id: str) -> List[Dict[str, Any]]:
        """Retrieves related STIX 2.1 mitigations (courses of action) for a technique ID."""
        tech_id_upper = tech_id.upper()
        # Direct mitigations for sub-technique or technique
        mitigations = list(self.mitigations_per_technique.get(tech_id_upper, []))

        # If sub-technique, also include parent mitigations if not already present
        if "." in tech_id_upper:
            parent_id = tech_id_upper.split(".")[0]
            parent_mits = self.mitigations_per_technique.get(parent_id, [])
            for pm in parent_mits:
                if not any(m["mitigation_id"] == pm["mitigation_id"] for m in mitigations):
                    mitigations.append(pm)

        return mitigations

    def search_techniques(self, query: str) -> List[Dict[str, Any]]:
        """Searches techniques by name or ID substring."""
        if not query:
            return []
        q_lower = query.lower()
        results = []
        for tech in self.techniques_by_id.values():
            if q_lower in tech["technique_id"].lower() or q_lower in tech["technique_name"].lower():
                results.append(tech)
        return results
