"""
Automated Test Suite for Stage 1 Analyst Dashboard & Tor Browser Observer Backend.
"""

import unittest
import os
import sys
import json

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import time
from src.stage1_dashboard import app, continuous_observer
from src.observer.tor_browser_observer import TorBrowserObserver
from src.discovery.source_registry import SourceRegistry
tor_observer = TorBrowserObserver()


from unittest.mock import patch, MagicMock

class TestStage1DashboardTorBrowser(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Mock TorBrowserObserver navigate_and_observe
        self.tor_nav_patcher = patch("src.observer.tor_browser_observer.TorBrowserObserver.navigate_and_observe")
        self.mock_tor_nav = self.tor_nav_patcher.start()
        self.mock_tor_nav.return_value = {
            "success": True,
            "http_status": 200,
            "raw_html": "<html><body><h1>SYNTHETIC UNDERGROUND RANSOMWARE FEED</h1><p>Selling Loki 2.0 Botnet keylogger source code and stolen database dumps for target enterprise networks.</p><p>Exploit payload: CVE-2024-1234 remote code execution in unpatched gateway.</p><a href='http://leaklocker.lab.onion/leak'>Mirror 1</a><a href='http://leaklocker.lab.onion/forum'>Mirror 2</a></body></html>",
            "clean_text": "SYNTHETIC UNDERGROUND RANSOMWARE FEED Selling Loki 2.0 Botnet keylogger source code and stolen database dumps for target enterprise networks. Exploit payload: CVE-2024-1234 remote code execution in unpatched gateway.",
            "nav_error": None
        }

        # Mock urllib.request.urlopen for HTTP cleartext tests
        self.urlopen_patcher = patch("urllib.request.urlopen")
        self.mock_urlopen = self.urlopen_patcher.start()
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"<html><body><h1>SYNTHETIC UNDERGROUND RANSOMWARE FEED</h1><p>Selling Loki 2.0 Botnet keylogger source code and stolen database dumps for target enterprise networks.</p><p>Exploit payload: CVE-2024-1234 remote code execution in unpatched gateway.</p><a href='http://leaklocker.lab.onion/leak'>Mirror</a></body></html>"
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        self.mock_urlopen.return_value = mock_resp

    def tearDown(self):
        self.tor_nav_patcher.stop()
        self.urlopen_patcher.stop()

    def test_tor_browser_launch_api(self):
        resp = self.app.post("/api/tor_browser/launch")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])
        self.assertTrue(data["status"]["browser_running"])
        self.assertFalse(data["status"]["javascript_enabled"])

    def test_tor_browser_status_api(self):
        resp = self.app.get("/api/tor_browser/status")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn("browser_running", data)
        self.assertEqual(data["javascript_enabled"], False)

    def test_tor_browser_close_api(self):
        resp = self.app.post("/api/tor_browser/close")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertTrue(data["success"])

    def test_tor_browser_security_policy_and_navigation(self):
        # 1. Verify Security Policy when JS is disabled (default)
        self.app.post("/api/tor_browser/launch")
        status_resp = self.app.get("/api/tor_browser/status")
        status_data = json.loads(status_resp.data)
        self.assertTrue(status_data["security_policy_verified"])
        self.assertFalse(status_data["javascript_enabled"])

        # 2. Verify Security Policy Enforcement when JS is enabled -> ABORTED
        continuous_observer.tor_browser.javascript_enabled = True
        payload = {
            "url": "http://127.0.0.1:5000/synthetic_test_feed",
            "source_type": "DREAD_SESSION_GATED"
        }
        resp_violation = self.app.post("/api/tor_browser/observe", json=payload)
        data_violation = json.loads(resp_violation.data)
        self.assertTrue(data_violation["security_policy_violation"])
        self.assertIn("SECURITY POLICY", data_violation["error"])

        # Restore security policy (JS: DISABLED)
        continuous_observer.tor_browser.javascript_enabled = False

        # 3. Verify actual URL navigation and ObservationRecord generation
        resp = self.app.post("/api/tor_browser/observe", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)

        self.assertTrue(data["success"])
        self.assertFalse(data["security_policy_violation"])
        self.assertEqual(data["http_status"], 200)
        self.assertGreater(data["text_length"], 0)
        self.assertGreaterEqual(data["extracted_links_count"], 2)

        # Check downstream bridge handoff & ML inference output
        self.assertIsNotNone(data["bridge_output"])
        self.assertIn("risk_score", data["bridge_output"])
        self.assertIn("cti", data["bridge_output"])
        self.assertIn("stix", data["bridge_output"])

    def test_source_registration_and_observe_now(self):
        # 1. Register synthetic test feed via dashboard POST /api/sources
        reg_payload = {
            "url": "http://127.0.0.1:5000/synthetic_test_feed",
            "source_type": "GENERIC_WEBSITE",
            "collector_type": "HTTP_CLEARNET",
            "polling_interval_sec": 10,
            "active": True
        }
        resp_reg = self.app.post("/api/sources", json=reg_payload)
        self.assertEqual(resp_reg.status_code, 200)
        reg_data = json.loads(resp_reg.data)
        self.assertTrue(reg_data["success"])
        source_id = reg_data["source_id"]
        self.assertTrue(source_id.startswith("src_"))

        # Verify active HTTP source created in registry
        src_entry = continuous_observer.registry.get_source_by_id(source_id)
        self.assertIsNotNone(src_entry)
        self.assertEqual(src_entry["validation_status"], "ACTIVE")
        self.assertEqual(src_entry["collector_type"], "HTTP_CLEARNET")

        # 2. Verify continuous observer can see the registered source in active sources
        active_sources = continuous_observer.registry.get_active_sources()
        active_urls = [s["canonical_url"] for s in active_sources]
        self.assertIn("http://127.0.0.1:5000/synthetic_test_feed", active_urls)

        # 3. Verify "Observe Now" triggers one immediate observation
        resp_obs_now = self.app.post(f"/api/sources/{source_id}/observe_now")
        self.assertEqual(resp_obs_now.status_code, 200)
        obs_data = json.loads(resp_obs_now.data)
        self.assertTrue(obs_data["success"])
        self.assertIn("observation", obs_data)
        obs_res = obs_data["observation"]
        self.assertEqual(obs_res["source_id"], source_id)
        self.assertEqual(obs_res["status"], "CONTENT_ACCESSIBLE")

    def test_idempotent_duplicate_registration_and_canonical_url_reuse(self):
        url = f"http://127.0.0.1:5000/idempotent_test_{int(time.time()*1000)}"
        reg_payload = {
            "url": url,
            "source_type": "GENERIC_WEBSITE",
            "collector_type": "HTTP_CLEARNET",
            "polling_interval_sec": 10,
            "active": True
        }

        # First registration -> CREATED
        resp1 = self.app.post("/api/sources", json=reg_payload)
        self.assertEqual(resp1.status_code, 200)
        data1 = json.loads(resp1.data)
        self.assertTrue(data1["success"])
        self.assertTrue(data1["created"])
        self.assertFalse(data1["already_exists"])
        original_source_id = data1["source_id"]

        # Second registration with trailing slash -> REUSED (same source_id)
        reg_payload2 = dict(reg_payload, url=url + "/")
        resp2 = self.app.post("/api/sources", json=reg_payload2)
        self.assertEqual(resp2.status_code, 200)
        data2 = json.loads(resp2.data)
        self.assertTrue(data2["success"])
        self.assertFalse(data2["created"])
        self.assertTrue(data2["already_exists"])
        self.assertEqual(data2["source_id"], original_source_id)
        self.assertEqual(data2["message"], "Source already registered — existing source reused.")

        # Confirm only 1 database entry exists for this canonical URL
        all_sources = continuous_observer.registry.get_all_sources()
        matching = [s for s in all_sources if s["canonical_url"] == url]
        self.assertEqual(len(matching), 1)

    def test_duplicate_source_cleanup(self):
        import tempfile
        import sqlite3

        temp_db = os.path.join(tempfile.gettempdir(), "test_cleanup_dedup.db")
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE sources_registry (
                source_id TEXT PRIMARY KEY,
                canonical_url TEXT NOT NULL,
                source_type TEXT NOT NULL,
                collector_type TEXT NOT NULL DEFAULT 'HTTP_CLEARNET',
                validation_status TEXT NOT NULL DEFAULT 'ACTIVE',
                polling_interval_mins INTEGER NOT NULL DEFAULT 30,
                discovery_timestamp_utc TEXT NOT NULL,
                discovered_via TEXT NOT NULL
            );
        """)
        # Insert 1 canonical source and 2 duplicate rows for same URL
        cursor.execute("INSERT INTO sources_registry (source_id, canonical_url, source_type, discovery_timestamp_utc, discovered_via) VALUES ('src_orig', 'http://cleanup-test.com', 'GENERIC_WEBSITE', '2026-10-01T00:00:00Z', 'TEST')")
        cursor.execute("INSERT INTO sources_registry (source_id, canonical_url, source_type, discovery_timestamp_utc, discovered_via) VALUES ('src_dup1', 'http://cleanup-test.com', 'GENERIC_WEBSITE', '2026-10-02T00:00:00Z', 'TEST')")
        cursor.execute("INSERT INTO sources_registry (source_id, canonical_url, source_type, discovery_timestamp_utc, discovered_via) VALUES ('src_dup2', 'http://cleanup-test.com', 'GENERIC_WEBSITE', '2026-10-03T00:00:00Z', 'TEST')")
        conn.commit()
        conn.close()

        # Instantiating SourceRegistry auto-executes clean_duplicate_sources() during init_db()
        reg = SourceRegistry(db_path=temp_db)
        sources = reg.get_all_sources()
        matching = [s for s in sources if s["canonical_url"] == "http://cleanup-test.com"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["source_id"], "src_orig")

        # Explicit call on database returns exact count of deleted duplicates
        with reg._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO sources_registry (source_id, canonical_url, source_type, discovery_timestamp_utc, discovered_via) VALUES ('src_dup3', 'http://cleanup-test.com', 'GENERIC_WEBSITE', '2026-10-04T00:00:00Z', 'TEST')")
            conn.commit()

        deleted = reg.clean_duplicate_sources()
        self.assertEqual(deleted, 1)

        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
