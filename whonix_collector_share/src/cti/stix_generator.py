"""
STIX 2.1 Object & Bundle Generator for DarkWatch CTI Pipeline.
Serializes extracted indicators, vulnerabilities, malware, attack tools, MITRE techniques,
and STIX 2.1 courses of action (mitigations) into valid STIX 2.1 JSON objects and Bundles.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class STIXGenerator:
    """
    Generates standard STIX 2.1 objects and bundles.
    """

    @staticmethod
    def _generate_uuid(prefix: str) -> str:
        return f"{prefix}--{str(uuid.uuid4())}"

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def build_stix_bundle(
        self,
        onion_address: str,
        timestamp: str,
        correlated_indicators: List[Dict[str, Any]],
        mitre_mappings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Builds a complete STIX 2.1 Bundle containing SCOs, SDOs, Courses of Action, and Relationships.

        Args:
            onion_address (str): Target onion source address
            timestamp (str): Observation timestamp
            correlated_indicators (List[Dict[str, Any]]): Extracted indicators with MISP category
            mitre_mappings (List[Dict[str, Any]]): MITRE ATT&CK technique mappings with mitigations

        Returns:
            Dict[str, Any]: STIX 2.1 JSON Bundle
        """
        now = self._now_iso()
        stix_objects: List[Dict[str, Any]] = []

        # Maps to track created STIX IDs for relationship linking
        created_stix_map: Dict[str, str] = {}
        attack_pattern_stix_map: Dict[str, str] = {}
        mitigation_stix_map: Dict[str, str] = {}

        # 1. Generate STIX Indicators & SDOs for Extracted Evidence
        for ind in correlated_indicators:
            ind_type = ind["indicator_type"]
            val = ind["normalized_value"]
            misp_cat = ind.get("misp_category", "Other")

            if ind_type in ["onion-url", "url"]:
                pattern = f"[url:value = '{val}']"
                stix_id = self._generate_uuid("indicator")
                obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": now,
                    "modified": now,
                    "name": f"Observed URL: {val}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "labels": [misp_cat.lower().replace(" ", "-")]
                }
                stix_objects.append(obj)
                created_stix_map[val] = stix_id

            elif ind_type in ["onion-domain", "domain-name"]:
                pattern = f"[domain-name:value = '{val}']"
                stix_id = self._generate_uuid("indicator")
                obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": now,
                    "modified": now,
                    "name": f"Observed Domain: {val}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "labels": [misp_cat.lower().replace(" ", "-")]
                }
                stix_objects.append(obj)
                created_stix_map[val] = stix_id

            elif ind_type == "ipv4-addr":
                pattern = f"[ipv4-addr:value = '{val}']"
                stix_id = self._generate_uuid("indicator")
                obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": now,
                    "modified": now,
                    "name": f"Observed IPv4: {val}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "labels": [misp_cat.lower().replace(" ", "-")]
                }
                stix_objects.append(obj)
                created_stix_map[val] = stix_id

            elif ind_type.startswith("file-hash"):
                hash_type_str = "SHA-256" if "sha256" in ind_type else ("SHA-1" if "sha1" in ind_type else "MD5")
                pattern = f"[file:hashes.'{hash_type_str}' = '{val}']"
                stix_id = self._generate_uuid("indicator")
                obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": now,
                    "modified": now,
                    "name": f"Observed File Hash ({hash_type_str}): {val}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now,
                    "labels": [misp_cat.lower().replace(" ", "-")]
                }
                stix_objects.append(obj)
                created_stix_map[val] = stix_id

            elif ind_type == "vulnerability-cve":
                stix_id = self._generate_uuid("vulnerability")
                obj = {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": now,
                    "modified": now,
                    "name": val,
                    "external_references": [
                        {
                            "source_name": "cve",
                            "external_id": val
                        }
                    ]
                }
                stix_objects.append(obj)
                created_stix_map[val] = stix_id

            elif ind_type == "malware-name":
                stix_id = self._generate_uuid("malware")
                obj = {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": now,
                    "modified": now,
                    "name": val,
                    "is_family": False,
                    "malware_types": ["unknown"]
                }
                stix_objects.append(obj)
                created_stix_map[val] = stix_id

            elif ind_type == "tool-name":
                stix_id = self._generate_uuid("tool")
                obj = {
                    "type": "tool",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": now,
                    "modified": now,
                    "name": val,
                    "tool_types": ["exploitation"]
                }
                stix_objects.append(obj)
                created_stix_map[val] = stix_id

        # 2. Generate STIX Attack Patterns & Courses of Action (Mitigations)
        for m in mitre_mappings:
            tech_id = m["technique_id"]
            stix_id = self._generate_uuid("attack-pattern")
            obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": stix_id,
                "created": now,
                "modified": now,
                "name": m["technique_name"],
                "description": m.get("description", ""),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id}/"
                    }
                ]
            }
            stix_objects.append(obj)
            attack_pattern_stix_map[tech_id] = stix_id

            # Generate course-of-action objects for related mitigations
            for mit in m.get("mitigations", []):
                mit_id = mit.get("mitigation_id")
                if mit_id and mit_id not in mitigation_stix_map:
                    coa_stix_id = self._generate_uuid("course-of-action")
                    coa_obj = {
                        "type": "course-of-action",
                        "spec_version": "2.1",
                        "id": coa_stix_id,
                        "created": now,
                        "modified": now,
                        "name": f"{mit_id}: {mit.get('name', 'Mitigation')}",
                        "description": mit.get("description", ""),
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": mit_id,
                                "url": f"https://attack.mitre.org/mitigations/{mit_id}/"
                            }
                        ]
                    }
                    stix_objects.append(coa_obj)
                    mitigation_stix_map[mit_id] = coa_stix_id

                # Generate STIX "mitigates" Relationship (Course of Action -> Attack Pattern)
                coa_stix_id = mitigation_stix_map.get(mit_id)
                if coa_stix_id:
                    rel_id = self._generate_uuid("relationship")
                    rel_obj = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": rel_id,
                        "created": now,
                        "modified": now,
                        "relationship_type": "mitigates",
                        "source_ref": coa_stix_id,
                        "target_ref": stix_id,
                        "description": f"Mitigation {mit_id} addresses ATT&CK technique {tech_id}"
                    }
                    stix_objects.append(rel_obj)

        # 3. Generate STIX Relationships for Extracted Evidence (Indicator -> Attack Pattern)
        for m in mitre_mappings:
            tech_id = m["technique_id"]
            ap_stix_id = attack_pattern_stix_map.get(tech_id)
            if not ap_stix_id:
                continue

            evidence_terms = [t.strip().lower() for t in m.get("evidence", "").split(",")]
            for val, ind_stix_id in created_stix_map.items():
                val_lower = val.lower()
                if any(term in val_lower or val_lower in term for term in evidence_terms if term):
                    rel_id = self._generate_uuid("relationship")
                    rel_obj = {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": rel_id,
                        "created": now,
                        "modified": now,
                        "relationship_type": "indicates",
                        "source_ref": ind_stix_id,
                        "target_ref": ap_stix_id,
                        "description": f"Extracted indicator '{val}' provides evidence for {tech_id}"
                    }
                    stix_objects.append(rel_obj)

        # 4. Wrap into STIX 2.1 Bundle
        bundle_id = self._generate_uuid("bundle")
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": stix_objects
        }
        return bundle
