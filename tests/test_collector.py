"""
Unit & Integration Test Suite for DarkWatch Collector (Phase 1).
Tests all 8 core requirements using mock responses without requiring live Tor connectivity:
1. Successful reachable response (CONTENT_ACCESSIBLE)
2. Empty/very short response (REACHABLE)
3. HTTP error response (UNCERTAIN)
4. Connection timeout/failure (OFFLINE)
5. Content SHA-256 hash generation
6. Previous-vs-current hash change detection
7. SQLite evidence storage & history retrieval
8. Content sanitization (stripping JS, style, active HTML tags)
"""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collector.verifier import DarkWatchVerifier
from src.collector.sanitizer import ContentSanitizer
from src.collector.evidence_store import EvidenceStore
from src.collector.state_engine import SourceState


class TestDarkWatchCollector(unittest.TestCase):

    def setUp(self):
        # Use in-memory SQLite database for isolated tests
        self.db_path = ":memory:"
        self.verifier = DarkWatchVerifier(
            socks_proxy=None,
            db_path=self.db_path
        )

    def _create_mock_session(self, status_code=200, content="", content_type="text/html", exception=None):
        """Helper to build a mock requests.Session."""
        session = MagicMock(spec=requests.Session)
        if exception:
            session.get.side_effect = exception
        else:
            mock_resp = MagicMock()
            mock_resp.status_code = status_code
            mock_resp.headers = {"Content-Type": content_type}
            mock_resp.iter_content.return_value = [content.encode('utf-8')]
            session.get.return_value = mock_resp
        return session

    def test_01_successful_reachable_response(self):
        """Requirement 1: Successful reachable response with readable text."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Marketplace</title></head>
        <body>
            <h1>Darknet Cyber Service</h1>
            <p>Providing secure encrypted communication tools and network audit software.</p>
        </body>
        </html>
        """
        mock_session = self._create_mock_session(status_code=200, content=html)
        url = "http://market123456789.onion"

        res = self.verifier.verify_onion_source(url, custom_session=mock_session)

        self.assertEqual(res["onion_address"], url)
        self.assertEqual(res["source_id"], "market123456789.onion")
        self.assertEqual(res["state"], SourceState.CONTENT_ACCESSIBLE.value)
        self.assertEqual(res["http_status"], 200)
        self.assertGreater(res["text_length"], 20)
        self.assertIsNotNone(res["sha256"])
        self.assertIn("Darknet Cyber Service", res["sanitized_text"])
        self.assertIsNone(res["error"])

    def test_02_empty_or_very_short_response(self):
        """Requirement 2: Empty/very short response yields REACHABLE state."""
        html = "<html><body>Ok</body></html>"
        mock_session = self._create_mock_session(status_code=200, content=html)
        url = "http://short123456789.onion"

        res = self.verifier.verify_onion_source(url, custom_session=mock_session)

        self.assertEqual(res["state"], SourceState.REACHABLE.value)
        self.assertEqual(res["http_status"], 200)

    def test_03_http_error_response(self):
        """Requirement 3: HTTP error responses (e.g., 500, 404) yield UNCERTAIN state."""
        mock_session = self._create_mock_session(status_code=500, content="Internal Server Error")
        url = "http://error123456789.onion"

        res = self.verifier.verify_onion_source(url, custom_session=mock_session)

        self.assertEqual(res["state"], SourceState.UNCERTAIN.value)
        self.assertEqual(res["http_status"], 500)

    def test_04_connection_timeout_failure(self):
        """Requirement 4: Connection timeout/failure yields OFFLINE state with error details."""
        mock_session = self._create_mock_session(
            exception=requests.exceptions.Timeout("SOCKS5 proxy connection timed out")
        )
        url = "http://offline123456789.onion"

        res = self.verifier.verify_onion_source(url, custom_session=mock_session)

        self.assertEqual(res["state"], SourceState.OFFLINE.value)
        self.assertIsNone(res["http_status"])
        self.assertIn("timeout", res["error"].lower())

    def test_05_content_hash_generation(self):
        """Requirement 5: Deterministic SHA-256 content hash generation."""
        sanitizer = ContentSanitizer()
        html = "<html><body><p>Deterministic Text Payload</p></body></html>"
        text, length, sha = sanitizer.sanitize_html(html)

        expected_sha = sanitizer.compute_sha256("Deterministic Text Payload")
        self.assertEqual(text, "Deterministic Text Payload")
        self.assertEqual(sha, expected_sha)
        self.assertEqual(length, len("Deterministic Text Payload"))

    def test_06_previous_vs_current_hash_change_detection(self):
        """Requirement 6: Previous-vs-current hash change detection."""
        url = "http://dynamic123456789.onion"

        # Observation 1: Initial content
        html1 = "<html><body><h1>Version 1.0 Announcement Page</h1></body></html>"
        mock_sess1 = self._create_mock_session(status_code=200, content=html1)
        res1 = self.verifier.verify_onion_source(url, custom_session=mock_sess1)

        self.assertIsNone(res1["previous_sha256"])
        self.assertFalse(res1["content_changed"])

        # Observation 2: Same content
        mock_sess2 = self._create_mock_session(status_code=200, content=html1)
        res2 = self.verifier.verify_onion_source(url, custom_session=mock_sess2)

        self.assertEqual(res2["previous_sha256"], res1["sha256"])
        self.assertFalse(res2["content_changed"])

        # Observation 3: Modified content
        html3 = "<html><body><h1>Version 2.0 Updated Announcement Page</h1></body></html>"
        mock_sess3 = self._create_mock_session(status_code=200, content=html3)
        res3 = self.verifier.verify_onion_source(url, custom_session=mock_sess3)

        self.assertEqual(res3["previous_sha256"], res2["sha256"])
        self.assertTrue(res3["content_changed"])
        self.assertNotEqual(res3["sha256"], res2["sha256"])

    def test_07_sqlite_evidence_storage(self):
        """Requirement 7: SQLite evidence storage schema and record history retrieval."""
        url = "http://evidence123456789.onion"
        html = "<html><body><p>Evidence persistence verification test content.</p></body></html>"

        mock_session = self._create_mock_session(status_code=200, content=html)
        self.verifier.verify_onion_source(url, custom_session=mock_session)

        history = self.verifier.evidence_store.get_history(url)
        self.assertEqual(len(history), 1)
        record = history[0]

        self.assertEqual(record["onion_address"], url)
        self.assertEqual(record["state"], SourceState.CONTENT_ACCESSIBLE.value)
        self.assertEqual(record["http_status"], 200)
        self.assertIn("Evidence persistence", record["sanitized_text"])

    def test_08_content_sanitization_active_content(self):
        """Requirement 8: Sanitizes HTML by stripping JavaScript, inline handlers, CSS, and active objects."""
        dirty_html = """
        <html>
        <head>
            <script>alert("Malicious JS execution!");</script>
            <style>body { background: red; }</style>
        </head>
        <body onload="doEvil()">
            <h1>Sanitized Header</h1>
            <iframe src="http://malware.onion/payload.exe"></iframe>
            <p>Clean operational text content for security intelligence processing.</p>
            <script type="text/javascript">var payload = 123;</script>
            <!-- HTML comment to remove -->
        </body>
        </html>
        """
        sanitizer = ContentSanitizer()
        clean_text, length, sha = sanitizer.sanitize_html(dirty_html)

        self.assertNotIn("alert", clean_text)
        self.assertNotIn("doEvil", clean_text)
        self.assertNotIn("background: red", clean_text)
        self.assertNotIn("malware.onion", clean_text)
        self.assertIn("Sanitized Header", clean_text)
        self.assertIn("Clean operational text content", clean_text)

    def test_09_whonix_gateway_proxy_configuration(self):
        """Requirement 9: Whonix Gateway SOCKS5 proxy configuration formatting."""
        # Test explicit Whonix proxy argument
        v_whonix = DarkWatchVerifier(socks_proxy="10.152.152.10:9050", db_path=":memory:")
        proxies = v_whonix._get_proxies()
        self.assertEqual(proxies["http"], "socks5h://10.152.152.10:9050")
        self.assertEqual(proxies["https"], "socks5h://10.152.152.10:9050")

        # Test use_whonix flag
        v_flag = DarkWatchVerifier(use_whonix=True, socks_proxy=None, db_path=":memory:")
        proxies_flag = v_flag._get_proxies()
        self.assertEqual(proxies_flag["http"], "socks5h://10.152.152.10:9050")

    def test_10_whonix_tor_connectivity_check_success(self):
        """Requirement 10: Whonix / Tor connectivity check returns connected_to_tor=True on valid Tor IP response."""
        v = DarkWatchVerifier(socks_proxy="10.152.152.10:9050", db_path=":memory:")
        mock_session = MagicMock(spec=requests.Session)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"IsTor": True, "IP": "185.220.101.5"}
        mock_session.get.return_value = mock_resp

        res = v.check_whonix_tor_connection(custom_session=mock_session)

        self.assertTrue(res["connected_to_tor"])
        self.assertEqual(res["ip"], "185.220.101.5")
        self.assertEqual(res["socks_proxy"], "socks5h://10.152.152.10:9050")
        self.assertIsNone(res["error"])

    def test_11_whonix_tor_connectivity_check_failure(self):
        """Requirement 11: Whonix / Tor connectivity check handles connection errors gracefully."""
        v = DarkWatchVerifier(socks_proxy="10.152.152.10:9050", db_path=":memory:")
        mock_session = MagicMock(spec=requests.Session)
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Could not connect to SOCKS proxy")

        res = v.check_whonix_tor_connection(custom_session=mock_session)

        self.assertFalse(res["connected_to_tor"])
        self.assertIsNone(res["ip"])
        self.assertIn("failed", res["error"].lower())


if __name__ == "__main__":
    unittest.main()

