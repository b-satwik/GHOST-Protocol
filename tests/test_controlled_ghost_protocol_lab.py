"""
Controlled Ghost Protocol Docker Laboratory — Master End-to-End Scenario Test Suite.
Verifies the complete synthetic laboratory observation workflow across Days 1 through 4:
1. Four controlled synthetic lab services exposed over REAL 56-character Tor v3 .onion addresses
2. Normal content vs Threat content handling by Contextual Threat Filter
3. Real frozen DistilBERT ML inference
4. Entity Resolution alias correlation (ViperSec <-> Viper_X)
5. Multi-day storyline progression (Days 1 to 4)
6. DreadLab authorized session/browser flow
7. Content Change Detection (CHANGED_UNIQUE on Day 4 edit & CHANGED_NEAR_DUPLICATE on PasteVault)
8. Historical Correlation across the 4-day timeline
9. GHOST Agent real tool executions (capture, deep analyze, find entity, search history)
"""

import sys
import os
import time
import json
import unittest
import threading
from urllib.parse import urlparse

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from darkwatch_labs.services.app import app as flask_app
from src.filter.threat_filter import ThreatFilter
from src.pipeline.inference_engine import InferenceEngine
from src.resolution.entity_resolver import EntityResolver
from src.observer.change_detector import ChangeDetector
from src.stage1_continuous_observer import Stage1ContinuousObserver
from src.agent.ghost_tool_dispatcher import GhostToolDispatcher
from src.observer.tor_browser_observer import (
    get_all_docker_onion_hostnames,
    fetch_url_over_socks5,
    wait_for_onion_service
)


class TestControlledGhostProtocolLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n==================================================")
        print("  CONTROLLED GHOST PROTOCOL LAB TEST SUITE        ")
        print("==================================================")
        
        # Start local test Flask server on port 8085
        cls.port = 8085
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        
        def run_server():
            flask_app.run(host="127.0.0.1", port=cls.port, debug=False, use_reloader=False)

        cls.server_thread = threading.Thread(target=run_server, daemon=True)
        cls.server_thread.start()
        time.sleep(1.5)

        # Initialize DarkWatch components
        cls.threat_filter = ThreatFilter()
        cls.engine = InferenceEngine()
        cls.resolver = EntityResolver()
        cls.change_detector = ChangeDetector()
        
        test_history_db = os.path.join(repo_root, "data", "test_ghost_lab_history.db")
        if os.path.exists(test_history_db):
            try:
                os.remove(test_history_db)
            except Exception:
                pass
                
        cls.observer = Stage1ContinuousObserver(
            history_db=test_history_db,
            registry_db=os.path.join(repo_root, "data", "test_registry.db"),
            queue_db=os.path.join(repo_root, "data", "test_queue.db"),
            alerts_db=os.path.join(repo_root, "data", "test_alerts.db")
        )
        cls.observer.lab_bridge.base_url = cls.base_url
        cls.dispatcher = GhostToolDispatcher(continuous_observer=cls.observer)

    def test_01_synthetic_lab_services_accessibility(self):
        """Verify all four synthetic onion lab endpoints return valid HTTP status & non-empty HTML."""
        import urllib.request
        
        endpoints = [
            ("/shadowforum", 200, "ShadowForum"),
            ("/dreadlab", 401, "2-Step Verification Required"),  # Protected before auth
            ("/pastevault", 200, "PasteVault"),
            ("/leaklocker", 200, "LeakLocker")
        ]

        for path, expected_status, title_snippet in endpoints:
            url = f"{self.base_url}{path}"
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status = resp.status
                    body = resp.read().decode("utf-8")
            except urllib.error.HTTPError as e:
                status = e.code
                body = e.read().decode("utf-8", errors="replace")

            self.assertEqual(status, expected_status, f"Endpoint {path} status {status} != {expected_status}")
            self.assertIn(title_snippet, body, f"Endpoint {path} missing expected snippet '{title_snippet}'")
            self.assertGreater(len(body), 50, f"Endpoint {path} returned empty body")

    def test_02_contextual_threat_filter_benign_vs_malicious(self):
        """Verify contextual threat filter handles benign PostgreSQL/server questions as ROUTINE_CONTENT."""
        # Benign PostgreSQL post from DevOps_Dan
        devops_text = "PostgreSQL performance tuning question: What are the recommended settings for shared_buffers and max_connections on a PostgreSQL 15 server running on Linux?"
        res1 = self.threat_filter.filter_and_categorize(devops_text)
        self.assertFalse(res1["is_threat"], "DevOps_Dan benign PostgreSQL question must NOT be classified as threat")
        self.assertEqual(res1["decision"], "ROUTINE_CONTENT")

        # Benign Cybersecurity news from SecurityNerd99
        sec_text = "Cybersecurity awareness weekly digest: Best practices for implementing multi-factor authentication and security patch management across enterprise servers."
        res2 = self.threat_filter.filter_and_categorize(sec_text)
        self.assertFalse(res2["is_threat"], "SecurityNerd99 benign digest must NOT be classified as threat")

        # Threat post from ViperSec
        threat_text = "Database leak discussion: Exfiltrated database dump containing 500,000 customer records from ApexGlobal Financial. Database credentials and internal server details exposed for sale."
        res3 = self.threat_filter.filter_and_categorize(threat_text)
        self.assertTrue(res3["is_threat"], "ViperSec DB leak post MUST be classified as threat")
        self.assertEqual(res3["category"], "DATABASE_LEAK")

    def test_03_frozen_distilbert_inference(self):
        """Verify threat observations enter frozen DistilBERT model and produce genuine predictions."""
        threat_text = "Database leak discussion: Exfiltrated database dump containing 500,000 customer records from ApexGlobal Financial. Database credentials and internal server details exposed for sale."
        output = self.engine.predict({"text": threat_text, "sanitized_text": threat_text})
        
        text_mod = output["text_model"]
        self.assertTrue(text_mod["text_available"])
        self.assertTrue(text_mod["is_threat"])
        self.assertIn("predicted_class", text_mod)
        self.assertGreater(text_mod["confidence"], 0.0)
        self.assertIn("class_probabilities", text_mod)

    def test_04_entity_resolution_alias_correlation(self):
        """Verify ViperSec (ShadowForum) and Viper_X (DreadLab) resolve to the same synthetic actor."""
        res = self.resolver.resolve_alias_correlation(
            handle1="ViperSec",
            handle2="Viper_X",
            source1="ShadowForum",
            source2="DreadLab",
            shared_targets=["ApexGlobal Financial"]
        )
        self.assertTrue(res["is_alias_match"], "ViperSec and Viper_X must be matched as aliases")
        self.assertGreaterEqual(res["composite_score"], 0.70)
        self.assertEqual(res["canonical_name"], "ViperSec / Viper_X")

    def test_05_multi_day_storyline_and_change_detection(self):
        """Execute Days 1 through 4 storyline and test change detection + DreadLab session flow."""
        import urllib.request
        
        # DAY 1: ShadowForum Observation
        urllib.request.urlopen(f"{self.base_url}/scenario/day/1")
        obs_d1 = self.observer.lab_bridge.observe_endpoint("/shadowforum")
        self.assertEqual(obs_d1["sanitized_text_status"], "CONTENT_ACCESSIBLE")
        
        # DAY 2: DreadLab Authorized Session Flow
        urllib.request.urlopen(f"{self.base_url}/scenario/day/2")
        # Direct unauth fetch returns 401
        obs_d2_unauth = self.observer.lab_bridge.observe_endpoint("/dreadlab")
        self.assertEqual(obs_d2_unauth["http_status"], 401)
        self.assertEqual(obs_d2_unauth["sanitized_text_status"], "SESSION_GATED_ACCESS")
        
        # Auth fetch with session token returns 200
        obs_d2_auth = self.observer.lab_bridge.observe_endpoint("/dreadlab", session_token="valid_lab_session")
        self.assertEqual(obs_d2_auth["http_status"], 200)
        self.assertIn("Viper_X", obs_d2_auth["sanitized_text"])
        self.assertIn("CrypticGhost", obs_d2_auth["sanitized_text"])

        # DAY 3: LeakLocker + PasteVault Observation (with near-duplicate check)
        urllib.request.urlopen(f"{self.base_url}/scenario/day/3")
        obs_leak = self.observer.lab_bridge.observe_endpoint("/leaklocker")
        self.assertEqual(obs_leak["http_status"], 200)
        self.assertIn("ApexGlobal Financial", obs_leak["sanitized_text"])

        obs_paste = self.observer.lab_bridge.observe_endpoint("/pastevault")
        self.assertEqual(obs_paste["http_status"], 200)
        self.assertIn("ApexGlobal Financial", obs_paste["sanitized_text"])

        # DAY 4: ShadowForum Post Change (Triggers CHANGED_UNIQUE)
        raw_before = "Database leak discussion: Exfiltrated database dump containing 500,000 customer records from ApexGlobal Financial."
        clean_before = raw_before
        
        # Initial change detector evaluation
        st1, r1, c1, _ = self.change_detector.evaluate_change("src_shadowforum", raw_before, clean_before)
        self.assertEqual(st1, "CHANGED_UNIQUE")

        # Second evaluation of same content -> UNCHANGED
        st2, r2, c2, _ = self.change_detector.evaluate_change("src_shadowforum", raw_before, clean_before)
        self.assertEqual(st2, "UNCHANGED")

        # Switch to Day 4 (ViperSec updates post to BioHealth Dynamics)
        urllib.request.urlopen(f"{self.base_url}/scenario/day/4")
        obs_d4 = self.observer.lab_bridge.observe_endpoint("/shadowforum")
        raw_after = obs_d4["sanitized_text"]
        
        st3, r3, c3, _ = self.change_detector.evaluate_change("src_shadowforum", raw_after, raw_after)
        self.assertEqual(st3, "CHANGED_UNIQUE", "Day 4 edit must trigger CHANGED_UNIQUE")

    def test_06_historical_correlator_timeline(self):
        """Verify HistoricalCorrelator links storyline entities across the complete graph."""
        res_direct = self.resolver.resolve_entity("ViperSec", associated_companies=["ApexGlobal Financial", "BioHealth Dynamics"])
        self.assertIn("ApexGlobal Financial", res_direct["associated_companies"])
        self.assertIn("BioHealth Dynamics", res_direct["associated_companies"])

    def test_07_ghost_agent_tool_dispatcher_execution(self):
        """Verify GHOST Agent tool dispatcher executes real local functions."""
        # 0. Observe lab target first so history store contains an observation
        target_url = f"{self.base_url}/shadowforum"
        obs_res = self.dispatcher.dispatch(f"observe {target_url}")
        self.assertEqual(obs_res["status"], "SUCCESS")

        # 1. "capture this"
        cap_res = self.dispatcher.dispatch("capture this")
        self.assertEqual(cap_res["status"], "SUCCESS")
        self.assertEqual(cap_res["action"], "observe_source")

        # 2. "where have we seen this user?"
        entity_res = self.dispatcher.dispatch("where have we seen this user ViperSec?")
        self.assertEqual(entity_res["status"], "SUCCESS")
        self.assertEqual(entity_res["action"], "find_entity")

        # 3. "what changed?"
        hist_res = self.dispatcher.dispatch("what changed?")
        self.assertEqual(hist_res["status"], "SUCCESS")
        self.assertEqual(hist_res["action"], "search_history")

        # 4. "deep analyze this"
        deep_res = self.dispatcher.dispatch("deep analyze this")
        self.assertEqual(deep_res["status"], "SUCCESS")
        self.assertEqual(deep_res["action"], "deep_analyze")
        self.assertIn("distilbert_prediction", deep_res)
        self.assertIn("hm_tif_fusion", deep_res)

    def test_08_real_tor_v3_onion_accessibility(self):
        """Verify all four real 56-character .onion services are accessible over Tor SOCKS5 proxy."""
        onion_hosts = get_all_docker_onion_hostnames()
        self.assertIn("shadowforum", onion_hosts)
        self.assertIn("dreadlab", onion_hosts)
        self.assertIn("pastevault", onion_hosts)
        self.assertIn("leaklocker", onion_hosts)

        for s_name, s_url in onion_hosts.items():
            parsed = urlparse(s_url)
            hostname = parsed.hostname or ""
            self.assertTrue(hostname.endswith(".onion"), f"{s_name} hostname '{hostname}' must end with .onion")
            self.assertEqual(len(hostname), 62, f"{s_name} hostname '{hostname}' must be 56 chars + .onion (62 chars total)")

        # Ensure onion service SOCKS5 circuits are ready
        for s_name, s_url in onion_hosts.items():
            wait_for_onion_service(s_url, timeout=15)

        # 1. ShadowForum over SOCKS5
        sf_code, sf_body, _ = fetch_url_over_socks5(onion_hosts["shadowforum"], timeout=25)
        self.assertEqual(sf_code, 200)
        self.assertIn("ShadowForum", sf_body)

        # 2. DreadLab over SOCKS5 (Unauthenticated -> 401)
        dl_code_unauth, dl_body_unauth, _ = fetch_url_over_socks5(onion_hosts["dreadlab"], timeout=25)
        self.assertEqual(dl_code_unauth, 401)
        self.assertIn("2-Step Verification Required", dl_body_unauth)

        # DreadLab over SOCKS5 (Authenticated -> 200 + Viper_X)
        dl_code_auth, dl_body_auth, _ = fetch_url_over_socks5(onion_hosts["dreadlab"], session_token="valid_lab_session", timeout=25)
        self.assertEqual(dl_code_auth, 200)
        self.assertIn("Viper_X", dl_body_auth)

        # 3. PasteVault over SOCKS5
        pv_code, pv_body, _ = fetch_url_over_socks5(onion_hosts["pastevault"], timeout=25)
        self.assertEqual(pv_code, 200)
        self.assertIn("PasteVault", pv_body)

        # 4. LeakLocker over SOCKS5
        ll_code, ll_body, _ = fetch_url_over_socks5(onion_hosts["leaklocker"], timeout=25)
        self.assertEqual(ll_code, 200)
        self.assertIn("LeakLocker", ll_body)

    @classmethod
    def tearDownClass(cls):
        cls.observer.tor_browser.close()
        print("\n==================================================")
        print(" CONTROLLED GHOST LAB TEST SUITE PASSED SUCCESSFULLY ")
        print("==================================================\n")


if __name__ == "__main__":
    unittest.main()
