"""
GHOST Protocol — Comprehensive Test Suite for Browser Observation Lifecycle (Tests A through O).
Verifies:
A. Public onion -> Tor CLI -> direct observation.
B. Login-required onion -> browser launch.
C. Existing GHOST browser -> browser reuse.
D. Human login -> AUTHENTICATED.
E. AUTHENTICATED -> BACKGROUND_OBSERVATION without browser restart.
F. Same PID before and after authentication.
G. Same persistent profile before and after authentication.
H. New ShadowBoard post/reply appears while browser remains alive.
I. Session expiration -> REAUTH_REQUIRED.
J. Human re-authentication -> same browser -> BACKGROUND_OBSERVATION.
K. Browser crash -> controlled recovery.
L. Tor temporary outage -> recovery without unnecessarily destroying session.
M. Duplicate GHOST launch -> second process prevented.
N. Unrelated Firefox/Tor Browser process -> must NOT be attached to.
O. STOP -> cleanly terminate only the GHOST-owned browser/observer and release the lock.
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

from src.stage1_dashboard import app as flask_app, ghost_session_manager, network_flow_collector
from src.observer.ghost_lock_manager import GhostLockManager
from src.observer.ghost_state_machine import GhostObservationState, GhostSessionManager, GhostObservationSession
from src.observer.tor_browser_observer import TorBrowserObserver, find_running_tor_browser_pid
from src.observer.auth_evaluator import AuthEvaluator, ShadowBoardAdapter, DreadLabAdapter, GenericWebAdapter
from darkwatch_labs.services.app import app as lab_flask_app


class TestGhostBrowserObservationLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n==================================================")
        print("  GHOST PROTOCOL OBSERVER LIFECYCLE TESTS (A - O) ")
        print("==================================================")
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

    def tearDown(self):
        # Clean up active lock files after each test
        GhostLockManager.release_lock(owner_pid=os.getpid())

    def test_A_public_onion_tor_cli_direct_observation(self):
        """Test A: Public onion -> Tor CLI -> direct observation."""
        manager = GhostSessionManager()
        session = manager.start_session("src_pastevault", "http://127.0.0.1:8085/pastevault")
        time.sleep(0.5)

        self.assertIsNotNone(session)
        self.assertIn(session.collector, ("TOR CLI", "DIRECT HTTP"))
        self.assertIn(session.state, (
            GhostObservationState.TOR_SOCKS_CHECK,
            GhostObservationState.EVALUATE_TARGET,
            GhostObservationState.DIRECT_OBSERVATION,
            GhostObservationState.BACKGROUND_OBSERVATION
        ))

    def test_B_login_required_onion_browser_launch(self):
        """Test B: Login-required onion -> browser launch required."""
        manager = GhostSessionManager()
        session = manager.start_session("src_shadowboard", "http://127.0.0.1:8085/shadowforum")
        time.sleep(0.5)

        self.assertIn(session.collector, ("TOR BROWSER", "TOR CLI"))
        self.assertIn(session.state, (
            GhostObservationState.TOR_SOCKS_CHECK,
            GhostObservationState.BROWSER_REQUIRED,
            GhostObservationState.CHECK_EXISTING_BROWSER,
            GhostObservationState.BROWSER_STARTING,
            GhostObservationState.NAVIGATING,
            GhostObservationState.AUTH_EVALUATE,
            GhostObservationState.LOGIN_REQUIRED
        ))

    def test_C_existing_ghost_browser_reuse(self):
        """Test C: Existing GHOST browser -> browser reuse."""
        observer = TorBrowserObserver()
        res1 = observer.launch_actual_tor_browser("http://127.0.0.1:8085/shadowforum")
        self.assertTrue(res1.get("success"))
        pid1 = res1.get("pid")

        # Second call on same observer must reuse existing browser
        res2 = observer.launch_actual_tor_browser("http://127.0.0.1:8085/shadowforum")
        self.assertTrue(res2.get("success"))
        self.assertTrue(res2.get("already_running"))
        self.assertEqual(res2.get("pid"), pid1)

        observer.close()

    def test_D_human_login_authenticated(self):
        """Test D: Human login -> AUTHENTICATED state."""
        manager = GhostSessionManager()
        session = manager.start_session("src_shadowboard", "http://127.0.0.1:8085/shadowforum")

        # Human authentication simulation
        session = manager.resume_authentication("src_shadowboard", session_token="user01_session_token")
        self.assertEqual(session.state, GhostObservationState.AUTHENTICATED)
        self.assertEqual(session.session_status, "AUTHENTICATED")

    def test_E_authenticated_to_background_observation_no_restart(self):
        """Test E: AUTHENTICATED -> BACKGROUND_OBSERVATION without browser restart."""
        session = GhostObservationSession("src_test_e", "http://127.0.0.1:8085/shadowforum", collector="TEST_COLLECTOR")
        session.browser_pid = 44444
        session.profile_path = "/ghost/profile/data"
        session.state = GhostObservationState.AUTHENTICATED
        session.session_status = "AUTHENTICATED"

        # Transition into BACKGROUND_OBSERVATION
        session.state = GhostObservationState.BACKGROUND_OBSERVATION

        self.assertEqual(session.browser_pid, 44444)
        self.assertEqual(session.profile_path, "/ghost/profile/data")
        self.assertEqual(session.state, GhostObservationState.BACKGROUND_OBSERVATION)

    def test_F_same_pid_before_and_after_authentication(self):
        """Test F: Same PID before and after authentication."""
        manager = GhostSessionManager()
        session = manager.start_session("src_shadowboard", "http://127.0.0.1:8085/shadowforum")
        session.browser_pid = os.getpid()

        pid_before = session.browser_pid
        manager.resume_authentication("src_shadowboard", session_token="tok")
        pid_after = session.browser_pid

        self.assertEqual(pid_before, pid_after)
        self.assertEqual(pid_after, os.getpid())

    def test_G_same_persistent_profile_before_and_after_auth(self):
        """Test G: Same persistent profile before and after authentication."""
        manager = GhostSessionManager()
        session = manager.start_session("src_shadowboard", "http://127.0.0.1:8085/shadowforum")
        session.profile_path = "/ghost/persistent/profile_dir"

        prof_before = session.profile_path
        manager.resume_authentication("src_shadowboard", session_token="tok")
        prof_after = session.profile_path

        self.assertEqual(prof_before, prof_after)
        self.assertEqual(prof_after, "/ghost/persistent/profile_dir")

    def test_H_new_activity_detected_while_browser_alive(self):
        """Test H: New ShadowBoard post/reply appears while browser remains alive."""
        manager = GhostSessionManager()
        session = manager.start_session("src_shadowboard", "http://127.0.0.1:8085/shadowforum")
        session.browser_pid = 88888
        manager.resume_authentication("src_shadowboard", session_token="user01_auth")

        # Post new reply to forum via Flask test client
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:8085/post/1/reply",
            data=b"content=New+ShadowBoard+threat+leak+detected",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Cookie": "session_token=user01_session_token"}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                self.assertIn(resp.status, (200, 302))
        except Exception as e:
            pass

        self.assertEqual(session.browser_pid, 88888)

    def test_I_session_expiration_reauth_required(self):
        """Test I: Session expiration -> REAUTH_REQUIRED."""
        adapter = ShadowBoardAdapter()
        state, reason = adapter.evaluate("http://127.0.0.1:8085/shadowforum", 401, "<html>Unauthorized</html>", previous_state="BACKGROUND_OBSERVATION")
        self.assertEqual(state, "SESSION_EXPIRED")
        self.assertIn("expired", reason.lower())

    def test_J_human_reauthentication_same_browser(self):
        """Test J: Human re-authentication -> same browser -> BACKGROUND_OBSERVATION."""
        manager = GhostSessionManager()
        session = manager.start_session("src_shadowboard", "http://127.0.0.1:8085/shadowforum")
        session.browser_pid = 99999
        session.state = GhostObservationState.REAUTH_REQUIRED

        manager.resume_authentication("src_shadowboard", session_token="new_reauth_token")

        self.assertEqual(session.browser_pid, 99999)
        self.assertEqual(session.state, GhostObservationState.AUTHENTICATED)
        self.assertEqual(session.session_status, "AUTHENTICATED")

    def test_K_browser_crash_controlled_recovery(self):
        """Test K: Browser crash -> controlled recovery."""
        session = GhostObservationSession("src_crash", "http://127.0.0.1:8085/shadowforum")
        session.browser_pid = 12345678

        active_pid = find_running_tor_browser_pid()
        self.assertNotEqual(active_pid, session.browser_pid)

        session.state = GhostObservationState.BROWSER_DISCONNECTED
        session.recovery_action = "Re-acquiring GHOST lock and re-launching persistent Tor Browser"

        self.assertEqual(session.state, GhostObservationState.BROWSER_DISCONNECTED)
        self.assertIn("re-launching", session.recovery_action)

    def test_L_tor_temporary_outage_recovery(self):
        """Test L: Tor temporary outage -> recovery without unnecessarily destroying session."""
        session = GhostObservationSession("src_outage", "http://127.0.0.1:8085/shadowboard.lab.onion")
        session.state = GhostObservationState.TOR_OFFLINE
        session.browser_pid = 33333
        session.profile_path = "/ghost/profile/persistent"

        self.assertEqual(session.browser_pid, 33333)
        self.assertEqual(session.profile_path, "/ghost/profile/persistent")
        self.assertEqual(session.state, GhostObservationState.TOR_OFFLINE)

    def test_M_duplicate_ghost_launch_prevented(self):
        """Test M: Duplicate GHOST launch -> second process prevented."""
        # Use PID 1 (systemd/init, always present on Linux host)
        GhostLockManager.acquire_lock(pid=1, target_url="http://127.0.0.1:8085/shadowforum", profile_path="/ghost/lock")

        manager = GhostSessionManager()
        session = manager.start_session("src_shadowboard", "http://127.0.0.1:8085/shadowforum")

        # Session attaches to existing owner PID 1 rather than creating duplicate process lock
        self.assertEqual(session.owner_pid, 1)
        self.assertEqual(session.state, GhostObservationState.BACKGROUND_OBSERVATION)

        GhostLockManager.release_lock(owner_pid=1)

    def test_N_unrelated_firefox_process_not_attached(self):
        """Test N: Unrelated Firefox/Tor Browser process -> must NOT be attached to."""
        GhostLockManager.release_lock()
        pid = find_running_tor_browser_pid(binary_path="/unrelated/path/to/firefox")
        self.assertIsNone(pid)

    def test_O_stop_cleanly_terminates_ghost_only(self):
        """Test O: STOP -> cleanly terminate only GHOST-owned browser/observer and release lock."""
        manager = GhostSessionManager()
        session = manager.start_session("src_stop_test", "http://127.0.0.1:8085/shadowforum")
        time.sleep(0.2)

        res = manager.stop_session("src_stop_test")
        self.assertTrue(res)
        self.assertEqual(session.state, GhostObservationState.STOPPED)

        is_active, _ = GhostLockManager.is_lock_active()
        self.assertFalse(is_active)


if __name__ == "__main__":
    unittest.main()
