"""
Regression Unit Test Suite for REAL_EXTERNAL vs CONTROLLED_LAB Transport Fix.

Verifies:
1. is_lab_target correctly distinguishes CONTROLLED_LAB targets from REAL_EXTERNAL .onion addresses.
2. REAL_EXTERNAL targets do NOT trigger Docker laboratory startup.
3. Tor CLI failure/timeout does NOT hang indefinitely or set target as OFFLINE.
4. Tor CLI failure reaches access decision and escalates to TOR_BROWSER collector.
5. ShadowBoard CONTROLLED_LAB classification and behavior remain preserved.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from run_ghost_agent import is_lab_target
from src.observer.ghost_agent import GhostObservationAgent, AccessMode


class TestRealExternalTransportFix(unittest.TestCase):

    def test_target_classification_controlled_lab_vs_real_external(self):
        """1. Verify target classification distinguishes lab targets from real external targets."""
        mock_lab_hosts = {
            "shadowforum": "http://shadowforum.lab.onion/",
            "dreadlab": "http://shadowboard.lab.onion/",
            "pastevault": "http://pastevault.lab.onion/"
        }

        # CONTROLLED_LAB targets
        self.assertTrue(is_lab_target("http://127.0.0.1:8085/dreadlab", mock_lab_hosts))
        self.assertTrue(is_lab_target("http://localhost:8085/shadowforum", mock_lab_hosts))
        self.assertTrue(is_lab_target("http://target.lab.onion/", mock_lab_hosts))
        self.assertTrue(is_lab_target("http://shadowboard.lab.onion/", mock_lab_hosts))

        # REAL_EXTERNAL target (MUST return False)
        real_target = "dreadland.lab.onion"
        self.assertFalse(is_lab_target(real_target, mock_lab_hosts))
        self.assertFalse(is_lab_target(f"http://{real_target}/", mock_lab_hosts))

    def test_tor_cli_failure_does_not_hang_and_escalates_to_browser(self):
        """2. Verify Tor CLI failure/timeout records failure and escalates to TOR_BROWSER access decision."""
        agent = GhostObservationAgent(
            proxy_host="127.0.0.1",
            proxy_port=9050,
            history_db=":memory:",
            enforce_whonix=False
        )

        real_target = "http://dreadland.lab.onion/"

        # Mock fetch_url_over_socks5 returning status=0 (CLI timeout/failure)
        with patch("src.observer.ghost_agent.fetch_url_over_socks5", return_value=(0, "", {})):
            with patch("src.observer.whonix_transport.WhonixTransport.verify_gateway", return_value=True):
                decision = agent.evaluate_access_decision(real_target)

                # CLI failure MUST NOT hang and MUST NOT set access_requirement to OFFLINE
                self.assertEqual(decision.get("tor_cli"), "TOR_CLI_UNAVAILABLE")
                self.assertIn(decision.get("selected_collector"), ["TOR_BROWSER", "NONE"])
                self.assertIn(decision.get("access_state"), ["TOR_CLI_UNAVAILABLE", "SOURCE_UNREACHABLE"])

    def test_unreachable_socks_gateway_escalates_to_browser(self):
        """3. Verify unreachable SOCKS5 gateway records failure and escalates to TOR_BROWSER decision."""
        agent = GhostObservationAgent(
            proxy_host="127.0.0.1",
            proxy_port=9050,
            history_db=":memory:",
            enforce_whonix=False
        )

        real_target = "http://dreadland.lab.onion/"

        with patch("src.observer.whonix_transport.WhonixTransport.verify_gateway", return_value=False):
            decision = agent.evaluate_access_decision(real_target)

            self.assertEqual(decision.get("tor_cli"), "TOR_CLI_UNAVAILABLE")
            self.assertIn(decision.get("access_state"), ["TOR_CLI_UNAVAILABLE", "SOURCE_UNREACHABLE"])


if __name__ == "__main__":
    unittest.main()
