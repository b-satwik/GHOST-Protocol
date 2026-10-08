"""
Test Suite for .onion Link Observation & GHOST Protocol Intelligence Processing.
Tests:
1. .onion URL canonicalization & LinkExtractor detection (v2 & v3 onion URLs)
2. SourceRegistry registration & transport routing for .onion targets
3. ThreatFilter gate evaluation on .onion threat content
4. Frozen DistilBERT model inference on .onion observations
5. CTI, STIX 2.1, MITRE ATT&CK, & XAI generation for .onion observations
6. GhostToolDispatcher natural language commands over .onion evidence
"""

import sys
import os
import unittest
import json
import time
from unittest.mock import patch, MagicMock

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.discovery.link_extractor import LinkExtractor
from src.discovery.source_registry import SourceRegistry
from src.pipeline.threat_filter import ThreatFilter
from src.pipeline.inference_engine import InferenceEngine
from src.stage1_continuous_observer import Stage1ContinuousObserver
from src.agent.ghost_tool_dispatcher import GhostToolDispatcher


class TestOnionLinkObservation(unittest.TestCase):

    def setUp(self):
        self.test_reg_db = f"data/test_onion_reg_{int(time.time()*1000)}.db"
        self.test_hist_db = f"data/test_onion_hist_{int(time.time()*1000)}.db"

        self.link_extractor = LinkExtractor()
        self.threat_filter = ThreatFilter()
        self.engine = InferenceEngine()
        self.continuous_observer = Stage1ContinuousObserver(
            registry_db=self.test_reg_db,
            history_db=self.test_hist_db
        )
        self.dispatcher = GhostToolDispatcher(self.continuous_observer)

    def tearDown(self):
        for path in (self.test_reg_db, self.test_hist_db):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

    def test_01_onion_url_extraction_and_canonicalization(self):
        """Verify extraction and canonicalization of .onion v3 and v2 addresses."""
        raw_text = """
        New underground leak portal mirror announced at:
        http://leaklocker.lab.onion/leak
        Old v2 onion mirror was http://loki2botnet12345.onion
        """
        urls = self.link_extractor.extract_links(raw_text)

        self.assertIn("http://leaklocker.lab.onion/leak", urls)
        self.assertIn("http://loki2botnet12345.onion", urls)

    def test_02_source_registry_onion_collector_routing(self):
        """Verify SourceRegistry registration and collector assignment for .onion URLs."""
        onion_url = f"http://leaklocker.lab.onion/leak_{int(time.time()*1000)}"
        source_id = f"src_onion_{int(time.time()*1000)}"

        success = self.continuous_observer.registry.add_source(
            source_id=source_id,
            url=onion_url,
            source_type="ONION_WEBSITE",
            collector_type="TOR_BROWSER",
            discovered_via="TEST_SUITE"
        )
        self.assertTrue(success)

        entry = self.continuous_observer.registry.get_source_by_id(source_id)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["canonical_url"], onion_url)
        self.assertEqual(entry["collector_type"], "TOR_BROWSER")

    def test_03_threat_filter_gate_on_onion_content(self):
        """Verify ThreatFilter correctly routes routine vs threat-relevant .onion content."""
        routine_text = "Welcome to the underground tech discussion board. What is your favorite Linux distro?"
        threat_text = "Selling remote code execution zero-day exploit payload for enterprise VPN gateway. CVE-2024-1234 system command execution."

        eval_routine = self.threat_filter.evaluate(routine_text)
        self.assertFalse(eval_routine["is_threat"])
        self.assertEqual(eval_routine["decision"], "ROUTINE_CONTENT")

        eval_threat = self.threat_filter.evaluate(threat_text)
        self.assertTrue(eval_threat["is_threat"])
        self.assertEqual(eval_threat["decision"], "THREAT_RELEVANT")

    def test_04_frozen_distilbert_inference_on_onion_observation(self):
        """Verify full DarkWatch pipeline execution over .onion observation using frozen DistilBERT."""
        onion_url = f"http://leaklocker.lab.onion/leak_{int(time.time()*1000)}"

        mock_res = {
            "success": True,
            "http_status": 200,
            "raw_html": """
            <html>
            <head><title>Underground Exploit Market</title></head>
            <body>
                <h1>RCE EXPLOIT FOR SALE</h1>
                <p>Unpatched Remote Code Execution zero-day exploit payload targeting web application gateways.</p>
                <p>Allows system command execution and administrator access.</p>
            </body>
            </html>
            """,
            "clean_text": "RCE EXPLOIT FOR SALE Unpatched Remote Code Execution zero-day exploit payload targeting web application gateways. Allows system command execution and administrator access.",
            "nav_error": None
        }

        with patch.object(self.continuous_observer.tor_browser, "navigate_and_observe", return_value=mock_res):
            source_entry = {
                "source_id": f"src_onion_rce_{int(time.time()*1000)}",
                "canonical_url": onion_url,
                "source_type": "ONION_WEBSITE",
                "collector_type": "TOR_BROWSER",
                "polling_interval_mins": 10
            }

            obs_result = self.continuous_observer.observe_source_entry(source_entry)
            self.assertEqual(obs_result["status"], "CONTENT_ACCESSIBLE")

            bridge_output = obs_result["bridge_output"]
            self.assertIsNotNone(bridge_output)

            text_pred = bridge_output["text_prediction"]
            self.assertEqual(text_pred["predicted_class"], "rce")
            self.assertGreater(text_pred["confidence"], 0.90)

            # Check Risk & Severity
            self.assertGreater(bridge_output["fusion_score"], 0.40)
            self.assertIn(bridge_output["risk_severity"], ("ELEVATED", "HIGH", "CRITICAL"))

            # Check CTI & STIX
            cti = bridge_output["cti"]
            self.assertIsNotNone(cti)
            stix = bridge_output["stix"]
            self.assertIn("bundle", stix)
            self.assertEqual(stix["bundle"]["type"], "bundle")

    def test_05_ghost_tool_dispatcher_onion_commands(self):
        """Verify GhostToolDispatcher executes tools over .onion evidence."""
        query_history = self.dispatcher.dispatch("show me previous observations")
        self.assertEqual(query_history["status"], "SUCCESS")

        query_explain = self.dispatcher.dispatch("explain model decision")
        self.assertTrue("xai_summary" in query_explain or "answer" in query_explain)


if __name__ == "__main__":
    unittest.main()
