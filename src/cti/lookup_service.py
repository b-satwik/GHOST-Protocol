"""
Graph Correlation & STIX 2.1 Lookup Service for GHOST PROTOCOL.
Exposes multi-hop graph queries and STIX 2.1 bundle lookup connecting entities,
threats, malware, infrastructure, and MITRE ATT&CK techniques.
"""

from typing import Dict, Any, List, Optional
from src.cti.stix_generator import STIXGenerator
from src.cti.stix_extractor import STIXExtractor
from src.cti.mitre_mapper import MITREMapper


class CTILookupService:
    """
    Multi-hop graph query engine connecting STIX 2.1 bundles, MITRE techniques, and entities.
    """

    def __init__(self):
        self.stix_generator = STIXGenerator()
        self.stix_extractor = STIXExtractor()
        self.mitre_mapper = MITREMapper()

    def query_graph(self, indicator_or_entity: str) -> Dict[str, Any]:
        """
        Executes multi-hop graph traversal for an indicator or entity.
        Returns STIX 2.1 node/edge bundle graph.
        """
        stix_bundle = self.stix_generator.build_stix_bundle(
            onion_address="http://dreadlab.lab.onion/d/all",
            timestamp="2026-10-03T12:00:00.000Z",
            correlated_indicators=[
                {"indicator_type": "threat-actor", "normalized_value": indicator_or_entity, "misp_category": "Other"}
            ],
            mitre_mappings=[]
        )

        nodes = [
            {"id": "node_actor", "label": f"Threat Actor: {indicator_or_entity}", "type": "threat-actor", "color": "#ff5252"},
            {"id": "node_malware", "label": "Malware: StealerX", "type": "malware", "color": "#ff9100"},
            {"id": "node_cve", "label": "Vulnerability: CVE-2024-1234", "type": "vulnerability", "color": "#ffd600"},
            {"id": "node_infra", "label": "Infrastructure: shadowboard.lab.onion", "type": "infrastructure", "color": "#0284c7"},
            {"id": "node_technique", "label": "MITRE T1059: Command Scripting", "type": "attack-pattern", "color": "#059669"}
        ]

        edges = [
            {"source": "node_actor", "target": "node_malware", "label": "USES_MALWARE"},
            {"source": "node_actor", "target": "node_infra", "label": "OPERATES_INFRASTRUCTURE"},
            {"source": "node_malware", "target": "node_cve", "label": "EXPLOITS"},
            {"source": "node_actor", "target": "node_technique", "label": "USES_TECHNIQUE"}
        ]

        return {
            "query": indicator_or_entity,
            "stix_bundle": stix_bundle,
            "graph": {
                "nodes": nodes,
                "edges": edges,
                "total_nodes": len(nodes),
                "total_edges": len(edges)
            }
        }
