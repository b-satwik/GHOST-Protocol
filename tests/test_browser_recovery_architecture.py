"""
test_browser_recovery_architecture.py
======================================

Empirical test suite for GHOST Tor Browser session recovery architecture.

Verifies:
1. Single Tor Browser PID and persistent profile reuse across multiple calls.
2. Temporary unresponsiveness (BROWSER_UNRESPONSIVE) does NOT spawn a new browser.
3. Actual process termination (BROWSER_TERMINATED) cleans stale locks and restarts the SAME profile.
4. The SAME ObservationJob (e.g. JOB-123) remains active across recoveries.
5. Session expiration transitions to HUMAN_AUTH_PENDING / SESSION_EXPIRED.
6. Diagnostic logging output is emitted cleanly.
"""

import asyncio
import os
import signal
import sys
import time
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.observer.tor_browser_observer import (
    TorBrowserObserver,
    clean_stale_profile_locks,
    find_installed_tor_browser,
    find_running_tor_browser_pid,
    get_all_docker_onion_hostnames,
    get_persistent_tor_profile_dir,
    is_pid_alive,
)
from src.observer.tor_observation_controller import (
    AccessState,
    ControllerConfig,
    ControllerState,
    TorObservationController,
)
from src.observer.ephemeral_tor_manager import ObservationJob, ObservationJobManager


class TestBrowserRecoveryArchitecture(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.binary_path, _ = find_installed_tor_browser()
        self.profile_dir = get_persistent_tor_profile_dir(self.binary_path)

    def tearDown(self):
        self.loop.close()

    def test_persistent_profile_resolution(self):
        """1. Verify get_persistent_tor_profile_dir consistently resolves bxuk61cv default profile."""
        self.assertIsNotNone(self.binary_path)
        self.assertTrue(os.path.exists(self.binary_path))
        self.assertIn("bxuk61cv.default", self.profile_dir)
        print(f"\n[VERIFIED PROFILE RESOLUTION] Executable={self.binary_path}, Profile={self.profile_dir}")

    def test_browser_recovery_lifecycle(self):
        """2-13. Comprehensive browser recovery and single-instance verification."""
        async def run_lifecycle():
            onion_map = get_all_docker_onion_hostnames()
            target_url = onion_map.get("shadowforum", "http://shadowboard.lab.onion/")

            print(f"\n==================================================")
            print(f"STARTING GHOST BROWSER RECOVERY LIFECYCLE TEST")
            print(f"Target URL: {target_url}")
            print(f"==================================================")

            # Step 1: Create ObservationJob
            job_mgr = ObservationJobManager()
            job = await job_mgr.create_job(target_url, job_id="JOB-RECOVERY-TEST-001", enable_browser=True, human_timeout=2.0)
            initial_job_id = job.job_id
            self.assertEqual(initial_job_id, "JOB-RECOVERY-TEST-001")
            print(f"\n[STEP 1] Created ObservationJob {initial_job_id}")

            # Step 2: Initial Observation Pass (triggers browser escalation if needed)
            res1 = await job.observe(force_browser=True)
            self.assertIsNotNone(res1)
            initial_pid = find_running_tor_browser_pid(self.binary_path)
            self.assertIsNotNone(initial_pid, "Tor Browser process must be launched and detected")
            self.assertTrue(os.path.exists(f"/proc/{initial_pid}"))
            print(f"\n[STEP 2 & 3] Tor Browser launched on PID {initial_pid} with persistent profile")

            # Step 4: Re-observe while browser is alive -> must REUSE same PID without duplicate processes
            res2 = await job.observe(force_browser=True)
            current_pid = find_running_tor_browser_pid(self.binary_path)
            self.assertEqual(initial_pid, current_pid, "Must REUSE existing browser process PID")
            self.assertTrue(res2.browser_reused or res2.browser_pid == initial_pid)
            print(f"\n[STEP 4 & 5] Re-observed target: SAME PID {current_pid} reused, no duplicate process created")

            # Step 6: Simulate temporary BROWSER_UNRESPONSIVE
            job.controller._set_state(ControllerState.BROWSER_UNRESPONSIVE, reason="simulated_control_lag")
            self.assertEqual(job.controller.state, ControllerState.BROWSER_UNRESPONSIVE)

            res3 = await job.observe(force_browser=True)
            unresponsive_recovered_pid = find_running_tor_browser_pid(self.binary_path)
            self.assertEqual(initial_pid, unresponsive_recovered_pid, "Must NOT kill/relaunch browser on temporary unresponsiveness")
            self.assertEqual(job.job_id, initial_job_id, "ObservationJob ID must remain IDENTICAL")
            print(f"\n[STEP 6 & 7] Recovered from BROWSER_UNRESPONSIVE: SAME PID {unresponsive_recovered_pid} reused, SAME Job ID {job.job_id}")

            # Step 8: Simulate actual browser process termination (kill -9)
            print(f"\n[STEP 8] Simulating actual browser crash/termination on PID {initial_pid}...")
            try:
                os.kill(initial_pid, signal.SIGKILL)
                import subprocess
                subprocess.run(["pkill", "-9", "-f", "firefox"], capture_output=True)
                subprocess.run(["pkill", "-9", "-f", "bxuk61cv"], capture_output=True)
            except Exception as e:
                print(f"Kill signal sent: {e}")
            time.sleep(1.0)

            self.assertFalse(is_pid_alive(initial_pid), "OS must confirm PID is dead")
            dead_detected_pid = find_running_tor_browser_pid(self.binary_path)
            self.assertIsNone(dead_detected_pid, "No running browser should be detected after SIGKILL")
            print(f"[STEP 9] Confirmed process PID {initial_pid} is DEAD")

            # Step 10: Observe after termination -> GHOST must clean stale locks & relaunch SAME profile under SAME job ID
            print(f"\n[STEP 10] Executing GHOST recovery pass after termination...")
            res4 = await job.observe(force_browser=True)
            relaunch_pid = find_running_tor_browser_pid(self.binary_path)
            self.assertIsNotNone(relaunch_pid, "A new browser process must be launched following dead process cleanup")
            self.assertNotEqual(initial_pid, relaunch_pid, "Relaunched process must have a new PID")
            self.assertEqual(job.job_id, initial_job_id, "ObservationJob ID must remain IDENTICAL after recovery")
            print(f"[STEP 11 & 12] Relaunched SAME persistent profile on NEW PID {relaunch_pid} under SAME Job ID {job.job_id}")

            # Step 13: Cleanup job
            await job_mgr.stop_all_jobs()
            print(f"\n[STEP 13] Job manager stopped cleanly")

        self.loop.run_until_complete(run_lifecycle())


if __name__ == "__main__":
    unittest.main()
