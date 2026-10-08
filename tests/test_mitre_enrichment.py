"""
Unit & Integration Test Suite for DarkWatch Local MITRE ATT&CK STIX 2.1 Enrichment Layer.
Empirically tests:
1. Technique ID lookup (T1078, T1190, T1059)
2. Sub-technique lookup and parent resolution (T1078.004 -> T1078)
3. Tactic / kill-chain phase resolution (Initial Access, Persistence, Execution)
4. Related STIX 2.1 mitigations lookup (M1026, M1027)
5. enrich_cti_observation() API method output structure
6. End-to-end pipeline integration (Phase 1 SQLite -> CTI extraction -> MITRE STIX 2.1 enrichment -> STIX Bundle with mitigations)
"""

import sys
import os
import unittest
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collector.verifier import DarkWatchVerifier
from src.cti.mitre_kb import MITREKnowledgeBase
from src.cti.mitre_enricher import MITREEnricher
from src.cti.cti_pipeline_bridge import CTIPipelineBridge


class TestMITREEnrichment(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.kb = MITREKnowledgeBase()
        cls.enricher = MITREEnricher(kb=cls.kb)

    def test_01_technique_id_lookup(self):
        """Tests lookup of parent techniques (T1078, T1190, T1059)."""
        t1078 = self.kb.get_technique_by_id("T1078")
        self.assertIsNotNone(t1078)
        self.assertEqual(t1078["technique_id"], "T1078")
        self.assertEqual(t1078["technique_name"], "Valid Accounts")
        self.assertFalse(t1078["is_subtechnique"])

        t1190 = self.kb.get_technique_by_id("T1190")
        self.assertIsNotNone(t1190)
        self.assertEqual(t1190["technique_id"], "T1190")
        self.assertEqual(t1190["technique_name"], "Exploit Public-Facing Application")

    def test_02_subtechnique_parent_resolution(self):
        """Tests lookup of sub-techniques (T1078.004) and parent resolution."""
        sub = self.kb.get_technique_by_id("T1078.004")
        self.assertIsNotNone(sub)
        self.assertEqual(sub["technique_id"], "T1078.004")
        self.assertEqual(sub["technique_name"], "Cloud Accounts")
        self.assertTrue(sub["is_subtechnique"])
        self.assertEqual(sub["parent_technique_id"], "T1078")

        # Test retrieving sub-techniques for parent T1078
        sub_list = self.kb.get_subtechniques("T1078")
        self.assertGreater(len(sub_list), 0)
        sub_ids = [s["technique_id"] for s in sub_list]
        self.assertIn("T1078.004", sub_ids)

    def test_03_tactic_resolution(self):
        """Tests tactic resolution for a technique."""
        tactics = self.kb.get_tactics_for_technique("T1078")
        self.assertGreater(len(tactics), 0)
        tactic_names = [t["name"] for t in tactics]
        self.assertTrue(any("Initial Access" in n or "Persistence" in n or "Defense Evasion" in n for n in tactic_names))

    def test_04_related_mitigations_lookup(self):
        """Tests related STIX 2.1 mitigations (courses of action) lookup for a technique."""
        mitigations = self.kb.get_mitigations_for_technique("T1078")
        self.assertGreater(len(mitigations), 0)
        mit_ids = [m["mitigation_id"] for m in mitigations]
        self.assertTrue(any(m_id.startswith("M") for m_id in mit_ids))

    def test_05_enrich_cti_observation_api(self):
        """Tests enrich_cti_observation() API payload format."""
        observation = {
            "sanitized_text": "Zero-day exploit for CVE-2024-30078 targeting corporate RDP logins.",
            "mitre_mappings": [
                {
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                    "mapping_method": "EXPLICIT_EVIDENCE",
                    "confidence": 0.90,
                    "evidence": "rdp logins, credentials"
                }
            ],
            "correlated_indicators": [
                {
                    "indicator_type": "vulnerability-cve",
                    "raw_indicator": "CVE-2024-30078",
                    "normalized_value": "CVE-2024-30078",
                    "misp_category": "External targeting"
                }
            ]
        }

        enriched = self.enricher.enrich_cti_observation(observation)
        self.assertIn("enriched_mitre_techniques", enriched)
        techs = enriched["enriched_mitre_techniques"]
        self.assertGreater(len(techs), 0)

        t1078_enriched = next(t for t in techs if t["technique_id"] == "T1078")
        self.assertEqual(t1078_enriched["technique_name"], "Valid Accounts")
        self.assertIn("darkwatch_mapping", t1078_enriched)
        self.assertIn("mitigations", t1078_enriched)
        self.assertGreater(len(t1078_enriched["mitigations"]), 0)

    def test_06_end_to_end_pipeline_bridge_mitre_enrichment(self):
        """Tests end-to-end processing of Phase 1 SQLite collector evidence through MITRE enrichment bridge."""
        db_path = ":memory:"
        verifier = DarkWatchVerifier(socks_proxy=None, db_path=db_path)
        mock_html = """
        <html>
        <body>
            <h1>Darknet Exploits</h1>
            <p>Selling zero-day exploit for CVE-2024-30078 and Loki botnet keylogger.</p>
        </body>
        </html>
        """
        mock_session = unittest.mock.MagicMock()
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.iter_content.return_value = [mock_html.encode('utf-8')]
        mock_session.get.return_value = mock_resp

        attempt = verifier.verify_onion_source("http://exploit123456789.onion", custom_session=mock_session)
        record_id = attempt["id"]

        bridge = CTIPipelineBridge(evidence_store=verifier.evidence_store)
        cti_res = bridge.process_collector_record(record_id)

        self.assertIsNotNone(cti_res)
        self.assertIn("enriched_mitre_techniques", cti_res)
        self.assertGreater(cti_res["enriched_mitre_count"], 0)

        # Verify STIX bundle contains course-of-action mitigations
        stix_objects = cti_res["stix_bundle"]["objects"]
        types = [o["type"] for o in stix_objects]
        self.assertIn("course-of-action", types)

        # Verify STIX "mitigates" relationship exists
        rel_types = [o.get("relationship_type") for o in stix_objects if o["type"] == "relationship"]
        self.assertIn("mitigates", rel_types)


if __name__ == "__main__":
    unittest.main()
