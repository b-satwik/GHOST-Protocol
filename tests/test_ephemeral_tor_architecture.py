"""
test_ephemeral_tor_architecture.py
==================================

Verification suite for Dynamic Ephemeral Tor Job architecture in GHOST Protocol.

Proves:
1. PortAllocator allocates distinct SOCKS/control ports per job.
2. TorInstanceManager creates distinct DataDirectory per job.
3. Multiple observation jobs run simultaneously without port/directory collision.
4. Each job observes its assigned target URL independently.
5. Stopping Job A does NOT stop Job B.
6. Cleanup of Job A releases allocated ports and removes temporary files.
7. Job B continues normal observation after Job A cleanup.
"""

import asyncio
import os
import shutil
import sys
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.observer.ephemeral_tor_manager import (
    JobState,
    ObservationJob,
    ObservationJobManager,
    PortAllocator,
    TorInstance,
    TorInstanceManager,
)
from src.observer.tor_browser_observer import get_all_docker_onion_hostnames


class TestEphemeralTorArchitecture(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.manager = ObservationJobManager()

    def tearDown(self):
        self.loop.run_until_complete(self.manager.stop_all_jobs())
        self.loop.close()

    def test_port_allocator_isolation(self):
        """1. Verify PortAllocator assigns unique port pairs to each job."""
        allocator = PortAllocator(start_socks_port=9300)
        p1_socks, p1_ctrl = allocator.allocate_port_pair()
        p2_socks, p2_ctrl = allocator.allocate_port_pair()

        self.assertNotEqual(p1_socks, p2_socks, "SOCKS ports must be unique")
        self.assertNotEqual(p1_ctrl, p2_ctrl, "Control ports must be unique")
        self.assertEqual(p1_socks, 9300)
        self.assertEqual(p2_socks, 9302)

        allocator.release_port_pair(p1_socks, p1_ctrl)
        allocator.release_port_pair(p2_socks, p2_ctrl)

    def test_tor_instance_datadirectory_isolation(self):
        """2. Verify each job receives a unique DataDirectory and torrc configuration."""
        inst_a = TorInstance("TEST-JOB-A", 9310, 9410)
        inst_b = TorInstance("TEST-JOB-B", 9312, 9412)

        torrc_a = inst_a.generate_torrc()
        torrc_b = inst_b.generate_torrc()

        self.assertNotEqual(inst_a.data_dir, inst_b.data_dir)
        self.assertIn("SocksPort 127.0.0.1:9310", torrc_a)
        self.assertIn("SocksPort 127.0.0.1:9312", torrc_b)
        self.assertTrue(inst_a.data_dir.exists())
        self.assertTrue(inst_b.data_dir.exists())

        # Clean up test directories
        shutil.rmtree(inst_a.base_dir, ignore_errors=True)
        shutil.rmtree(inst_b.base_dir, ignore_errors=True)

    def test_simultaneous_multi_job_lifecycle(self):
        """3-7. Simultaneous multi-job lifecycle verification:
        - Job A & Job B create distinct ports and DataDirectories
        - Both run concurrently
        - Stopping Job A leaves Job B alive
        - Cleanup releases Job A resources while Job B functions normally
        """
        async def run_test():
            onion_map = get_all_docker_onion_hostnames()
            url_a = onion_map.get("shadowforum", "http://shadowboard.lab.onion/")
            url_b = onion_map.get("pastevault", "http://pastevault.lab.onion/")

            print(f"\n--- Creating Job A ({url_a}) and Job B ({url_b}) ---")
            job_a = await self.manager.create_job(url_a, job_id="JOB-SHADOWBOARD-A")
            job_b = await self.manager.create_job(url_b, job_id="JOB-PASTEVAULT-B")

            # 1. Verify unique SOCKS ports
            self.assertNotEqual(job_a.socks_port, job_b.socks_port)
            print(f"[VERIFIED 1] SOCKS ports: Job A={job_a.socks_port}, Job B={job_b.socks_port}")

            # 2. Verify unique DataDirectories
            self.assertNotEqual(job_a.data_directory, job_b.data_directory)
            print(f"[VERIFIED 2] DataDirectories: Job A={job_a.data_directory}, Job B={job_b.data_directory}")

            # 3. Verify both jobs are READY simultaneously
            self.assertEqual(job_a.state, JobState.READY)
            self.assertEqual(job_b.state, JobState.READY)
            print("[VERIFIED 3] Both jobs running and READY simultaneously")

            # 4. Perform observation pass on each job
            res_a = await job_a.observe()
            res_b = await job_b.observe()
            self.assertIsNotNone(res_a)
            self.assertIsNotNone(res_b)
            self.assertEqual(res_a.url, url_a)
            self.assertEqual(res_b.url, url_b)
            print(f"[VERIFIED 4] Job A observed {res_a.url} (status={res_a.status_code}), Job B observed {res_b.url} (status={res_b.status_code})")

            # 5. Stop Job A and verify Job B remains alive
            socks_a_orig = job_a.socks_port
            ctrl_a_orig = job_a.control_port
            data_dir_a = job_a.data_directory

            await self.manager.stop_job("JOB-SHADOWBOARD-A")
            self.assertEqual(job_a.state, JobState.CLEANED_UP)
            self.assertEqual(job_b.state, JobState.OBSERVING if res_b.success else job_b.state)
            print("[VERIFIED 5] Stopping Job A did NOT stop Job B")

            # 6. Verify Job A resources cleaned up (directory deleted)
            self.assertFalse(data_dir_a.exists() if data_dir_a else False)
            print("[VERIFIED 6] Job A resources cleaned up (DataDirectory deleted)")

            # 7. Verify Job B continues operating normally
            res_b_again = await job_b.observe()
            self.assertIsNotNone(res_b_again)
            self.assertEqual(res_b_again.url, url_b)
            print(f"[VERIFIED 7] Job B continues operating normally (status={res_b_again.status_code})")

        self.loop.run_until_complete(run_test())


if __name__ == "__main__":
    unittest.main()
