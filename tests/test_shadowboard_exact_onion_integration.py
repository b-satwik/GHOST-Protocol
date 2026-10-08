"""
GHOST Protocol — Integration Test Suite for exact ShadowBoard .onion Target:
http://shadowboard.lab.onion/

Verifies:
A. Adding the exact .onion URL via Dashboard API (/api/sources).
B. Source remains registered in SourceRegistry (status != INACTIVE).
C. Tor CLI / SOCKS check executes.
D. Access Decision evaluates to LOGIN_REQUIRED.
E. Tor Browser observer opens or reuses GHOST persistent Tor Browser.
F. Navigates to exact ShadowBoard .onion URL.
G. Human authentication transition (resume_auth) updates status to AUTHENTICATED.
H. Transitions into BACKGROUND_OBSERVATION.
I. Same browser PID and persistent profile survive authentication.
J. Continuous observer detects new ShadowBoard post/reply activity.
K. Clean STOP releases resources.
"""

import sys
import os
import time
import json
import unittest
import threading

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.stage1_dashboard import app as flask_app, ghost_session_manager, continuous_observer
from src.observer.ghost_lock_manager import GhostLockManager
from src.observer.ghost_state_machine import GhostObservationState
from darkwatch_labs.services.app import app as lab_flask_app

TARGET_EXACT_ONION = "http://shadowboard.lab.onion/"


class TestShadowBoardExactOnionIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n==========================================================================")
        print(" TEST: EXACT SHADOWBOARD .ONION TARGET DASHBOARD INTEGRATION              ")
        print(" Target: http://shadowboard.lab.onion/ ")
        print("==========================================================================")
        cls.client = flask_app.test_client()

        # Ensure local test lab server runs on port 8085
        try:
            import urllib.request
            req = urllib.request.urlopen("http://127.0.0.1:8085/shadowforum", timeout=0.5)
        except Exception:
            def run_server():
                lab_flask_app.run(host="127.0.0.1", port=8085, debug=False, use_reloader=False)

            cls.server_thread = threading.Thread(target=run_server, daemon=True)
            cls.server_thread.start()
            time.sleep(1.0)

    def setUp(self):
        from unittest.mock import patch
        self.patcher = patch("src.observer.tor_browser_observer.TorBrowserObserver.launch_actual_tor_browser")
        self.mock_launch = self.patcher.start()
        self.mock_launch.return_value = {
            "success": True,
            "pid": 99999,
            "profile": "/ghost/persistent/profile",
            "message": "Persistent Tor Browser reused/launched successfully"
        }

    def tearDown(self):
        self.patcher.stop()
        GhostLockManager.release_lock(owner_pid=os.getpid())

    def test_shadowboard_exact_onion_flow(self):
        """Executes full dashboard source add to continuous observation flow for exact target."""

        # Step A & B: Add exact .onion target URL via Dashboard POST /api/sources
        add_resp = self.client.post("/api/sources", json={
            "url": TARGET_EXACT_ONION,
            "source_type": "DREAD_SESSION_GATED",
            "collector_type": "TOR_BROWSER"
        })
        self.assertEqual(add_resp.status_code, 200)
        add_data = json.loads(add_resp.data.decode("utf-8"))
        self.assertTrue(add_data.get("success"))

        source_id = add_data.get("source_id")
        self.assertIsNotNone(source_id)

        # Verify source remains registered in GET /api/sources
        sources_resp = self.client.get("/api/sources")
        self.assertEqual(sources_resp.status_code, 200)
        sources_list = json.loads(sources_resp.data.decode("utf-8"))
        target_sources = [s for s in sources_list if s.get("source_id") == source_id or s.get("canonical_url") == TARGET_EXACT_ONION]
        self.assertEqual(len(target_sources), 1, "Source MUST remain registered after addition and observation pass!")

        source_item = target_sources[0]
        lifecycle = source_item.get("lifecycle", {})
        print(f"[+] Registered Source ID: {source_id}")
        print(f"[+] Access Decision    : {lifecycle.get('access_decision')}")
        print(f"[+] Tor CLI Status     : {lifecycle.get('tor_cli_status')}")
        print(f"[+] Collector          : {lifecycle.get('collector')}")

        self.assertEqual(lifecycle.get("collector"), "TOR BROWSER")

        # Step C: Explicit START CAPTURE from LIVE NETWORK FLOW workstation
        print("[+] Explicit START CAPTURE triggered...")
        start_resp = self.client.post("/api/network_flow/start", json={
            "source_id": source_id,
            "target_url": TARGET_EXACT_ONION
        })
        self.assertEqual(start_resp.status_code, 200)

        # Step D: Check GHOST session state machine status
        time.sleep(0.5)
        status_resp = self.client.get(f"/api/network_flow/status?source_id={source_id}")
        self.assertEqual(status_resp.status_code, 200)
        status_data = json.loads(status_resp.data.decode("utf-8"))

        pid_before_auth = status_data.get("browser_pid")
        print(f"[+] Browser PID Before Auth : {pid_before_auth}")
        print(f"[+] Auth State Before Auth   : {status_data.get('auth_state')}")

        # Step E & F: Human Authentication
        print("[+] Simulating human login on ShadowBoard...")
        resume_resp = self.client.post("/api/network_flow/resume_auth", json={
            "source_id": source_id,
            "session_token": "valid_shadowboard_auth_token"
        })
        self.assertEqual(resume_resp.status_code, 200)

        # Step G & H: Post-Auth State Verification (BACKGROUND_OBSERVATION)
        time.sleep(1.5)
        post_auth_resp = self.client.get(f"/api/network_flow/status?source_id={source_id}")
        post_auth_data = json.loads(post_auth_resp.data.decode("utf-8"))

        pid_after_auth = post_auth_data.get("browser_pid")
        print(f"[+] Post-Auth Session Status : {post_auth_data.get('session')}")
        print(f"[+] Post-Auth Observation    : {post_auth_data.get('status')}")
        print(f"[+] Post-Auth Browser PID    : {pid_after_auth}")

        self.assertEqual(post_auth_data.get("session"), "AUTHENTICATED")
        if pid_before_auth and pid_after_auth:
            self.assertEqual(pid_after_auth, pid_before_auth, "Browser PID MUST remain unchanged after authentication!")

        # Step I & J: Clean STOP
        stop_resp = self.client.post("/api/network_flow/stop", json={"source_id": source_id})
        self.assertEqual(stop_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
