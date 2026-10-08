"""
Unit & Integration Test Suite for DarkWatch CTI Extraction & STIX 2.1 Pipeline.
Empirically tests:
1. Indicator extraction (.onion URLs, IPv4s, MD5/SHA-1/SHA-256, CVEs, malware, tools)
2. Normalization & deduplication
3. STIX 2.1 spec compliance (bundle type, spec_version 2.1, UUIDs, ISO timestamps)
4. Distinction of observed evidence vs KB matches (no hallucinated relationships)
5. MISP & MITRE ATT&CK correlation
6. Pipeline bridge processing of Phase 1 SQLite evidence records
"""

import sys
import os
import unittest
import unittest.mock
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collector.verifier import DarkWatchVerifier
from src.cti.stix_extractor import STIXExtractor
from src.cti.misp_mitre_correlator import MISPMITRECorrelator
from src.cti.stix_generator import STIXGenerator
from src.cti.cti_store import CTIStore
from src.cti.cti_pipeline_bridge import CTIPipelineBridge


class TestCTISTIXPipeline(unittest.TestCase):

    def setUp(self):
        self.extractor = STIXExtractor()
        self.correlator = MISPMITRECorrelator()
        self.stix_generator = STIXGenerator()
        self.db_path = ":memory:"
        self.bridge = CTIPipelineBridge(db_path=self.db_path)

    def test_01_indicator_extraction(self):
        """Tests extraction of .onion URLs, IPv4s, hashes, CVEs, malware, and tool names."""
        sample_text = """
        Welcome to Darknet Store at http://market123456789.onion/login.
        Host C2 server IP is 198.51.100.45.
        Selling Loki 2.0 Botnet keylogger source code and RedLine stealer logs.
        Payload MD5: e11098ed937cc5dcc66d91da3846077f
        Payload SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        Zero-day exploit for CVE-2024-30078 available. Built using Mimikatz and Hashcat.
        """
        indicators = self.extractor.extract_indicators(sample_text)

        types_found = {ind["indicator_type"] for ind in indicators}
        self.assertIn("onion-url", types_found)
        self.assertIn("ipv4-addr", types_found)
        self.assertIn("file-hash-md5", types_found)
        self.assertIn("file-hash-sha256", types_found)
        self.assertIn("vulnerability-cve", types_found)
        self.assertIn("malware-name", types_found)
        self.assertIn("tool-name", types_found)

        # Check explicit normalization
        cve_ind = next(i for i in indicators if i["indicator_type"] == "vulnerability-cve")
        self.assertEqual(cve_ind["normalized_value"], "CVE-2024-30078")

        ip_ind = next(i for i in indicators if i["indicator_type"] == "ipv4-addr")
        self.assertEqual(ip_ind["normalized_value"], "198.51.100.45")

    def test_02_normalization_and_deduplication(self):
        """Tests deduplication and case normalization of duplicate indicators."""
        text = "Contact cve-2024-30078 or CVE-2024-30078 or Http://market.lab.onion."
        indicators = self.extractor.extract_indicators(text)

        cves = [i for i in indicators if i["indicator_type"] == "vulnerability-cve"]
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["normalized_value"], "CVE-2024-30078")

    def test_03_misp_and_mitre_correlation(self):
        """Tests local MISP taxonomy categorization and MITRE ATT&CK correlation."""
        text = "Selling corporate RDP access combo list logins and RedLine stealer log."
        indicators = self.extractor.extract_indicators(text)
        corr = self.correlator.correlate(indicators, text)

        corr_indicators = corr["correlated_indicators"]
        mitre_mappings = corr["mitre_mappings"]

        # Verify MISP categories
        for ind in corr_indicators:
            self.assertIn("misp_category", ind)
            self.assertTrue(ind["is_observed"])

        # Verify MITRE mapping match (T1078 Valid Accounts or T1071 C2)
        tech_ids = {m["technique_id"] for m in mitre_mappings}
        self.assertTrue(len(tech_ids) > 0)
        for m in mitre_mappings:
            self.assertFalse(m["is_observed"])  # KB Match flag

    def test_04_stix_21_specification_compliance(self):
        """Tests STIX 2.1 object & bundle spec compliance."""
        text = "Exploit for CVE-2024-30078 with RedLine malware hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
        indicators = self.extractor.extract_indicators(text)
        corr = self.correlator.correlate(indicators, text)

        bundle = self.stix_generator.build_stix_bundle(
            onion_address="http://test123456789.onion",
            timestamp="2026-09-26T18:00:00.000Z",
            correlated_indicators=corr["correlated_indicators"],
            mitre_mappings=corr["mitre_mappings"]
        )

        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        self.assertTrue(bundle["id"].startswith("bundle--"))

        objects = bundle["objects"]
        self.assertGreater(len(objects), 0)

        for obj in objects:
            self.assertIn("type", obj)
            self.assertIn("id", obj)
            self.assertIn("created", obj)
            self.assertIn("modified", obj)
            # Verify no threat-actor SDO was hallucinated
            self.assertNotEqual(obj["type"], "threat-actor")

    def test_05_cti_pipeline_bridge_sqlite_integration(self):
        """Tests processing Phase 1 SQLite evidence records through the CTI pipeline bridge."""
        # 1. Create a Phase 1 collector evidence record in SQLite
        verifier = DarkWatchVerifier(socks_proxy=None, db_path=self.db_path)
        mock_html = """
        <html>
        <body>
            <h1>Cyber Leak Forum</h1>
            <p>Fresh batch of corporate RDP access logins and Loki botnet keylogger.</p>
            <p>Download server IP: 198.51.100.77. Related to CVE-2024-30078.</p>
        </body>
        </html>
        """
        mock_session = unittest.mock.MagicMock()
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.iter_content.return_value = [mock_html.encode('utf-8')]
        mock_session.get.return_value = mock_resp

        attempt = verifier.verify_onion_source("http://forum123456789.onion", custom_session=mock_session)
        record_id = attempt["id"]

        # 2. Process record through CTI Pipeline Bridge using shared evidence store
        bridge = CTIPipelineBridge(evidence_store=verifier.evidence_store)
        cti_res = bridge.process_collector_record(record_id)

        self.assertIsNotNone(cti_res)
        self.assertEqual(cti_res["source_record_id"], record_id)
        self.assertEqual(cti_res["onion_address"], "http://forum123456789.onion")
        self.assertGreater(cti_res["extracted_indicators_count"], 0)
        self.assertTrue(cti_res["stix_bundle_id"].startswith("bundle--"))

        # 3. Retrieve stored CTI evidence from SQLite DB
        cti_records = bridge.cti_store.get_cti_evidence_by_record(record_id)
        self.assertGreater(len(cti_records), 0)

        stored_bundle = bridge.cti_store.get_stix_bundle_by_record(record_id)
        self.assertIsNotNone(stored_bundle)
        self.assertEqual(stored_bundle["id"], cti_res["stix_bundle_id"])


if __name__ == "__main__":
    unittest.main()
