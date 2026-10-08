"""
Unit Tests for DarkWatch Collector State Engine.
Empirically tests deterministic state evaluation logic across all 6 source states.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collector.state_engine import StateEngine, SourceState


class TestStateEngine(unittest.TestCase):

    def setUp(self):
        self.engine = StateEngine(min_text_length=20)

    def test_01_content_accessible_state(self):
        """Tests HTTP 200 with sufficient text content -> CONTENT_ACCESSIBLE."""
        state = self.engine.determine_state(
            http_status=200,
            content_type="text/html; charset=utf-8",
            text_length=150,
            raw_html="<html><body><h1>Welcome to DarkWeb Forum</h1></body></html>"
        )
        self.assertEqual(state, SourceState.CONTENT_ACCESSIBLE)

    def test_02_reachable_state_short_text(self):
        """Tests HTTP 200 with empty or short text content -> REACHABLE."""
        state = self.engine.determine_state(
            http_status=200,
            content_type="text/html",
            text_length=5,
            raw_html="<html><body>Hi</body></html>"
        )
        self.assertEqual(state, SourceState.REACHABLE)

    def test_03_reachable_state_non_html(self):
        """Tests HTTP 200 with non-HTML content type -> REACHABLE."""
        state = self.engine.determine_state(
            http_status=200,
            content_type="image/png",
            text_length=0
        )
        self.assertEqual(state, SourceState.REACHABLE)

    def test_04_automated_access_blocked_http_403(self):
        """Tests HTTP 403 / 429 response -> AUTOMATED_ACCESS_BLOCKED."""
        state403 = self.engine.determine_state(http_status=403, content_type="text/html", text_length=0)
        state429 = self.engine.determine_state(http_status=429, content_type="text/html", text_length=0)
        self.assertEqual(state403, SourceState.AUTOMATED_ACCESS_BLOCKED)
        self.assertEqual(state429, SourceState.AUTOMATED_ACCESS_BLOCKED)

    def test_05_automated_access_blocked_captcha_keyword(self):
        """Tests HTML containing anti-bot / Cloudflare keywords -> AUTOMATED_ACCESS_BLOCKED."""
        html = "<html><body><h1>Attention Required! Cloudflare Security Check</h1></body></html>"
        state = self.engine.determine_state(
            http_status=200,
            content_type="text/html",
            text_length=50,
            raw_html=html
        )
        self.assertEqual(state, SourceState.AUTOMATED_ACCESS_BLOCKED)

    def test_06_offline_connection_failure(self):
        """Tests TCP/SOCKS timeout or connection failure -> OFFLINE."""
        state_timeout = self.engine.determine_state(
            http_status=None,
            content_type=None,
            text_length=0,
            error="Connection timeout after 10s",
            connection_failed=True
        )
        state_503 = self.engine.determine_state(
            http_status=503,
            content_type="text/html",
            text_length=0
        )
        self.assertEqual(state_timeout, SourceState.OFFLINE)
        self.assertEqual(state_503, SourceState.OFFLINE)

    def test_07_uncertain_state_http_errors(self):
        """Tests HTTP 404 or 500 status codes -> UNCERTAIN."""
        state404 = self.engine.determine_state(http_status=404, content_type="text/html", text_length=0)
        state500 = self.engine.determine_state(http_status=500, content_type="text/html", text_length=0)
        self.assertEqual(state404, SourceState.UNCERTAIN)
        self.assertEqual(state500, SourceState.UNCERTAIN)


if __name__ == "__main__":
    unittest.main()
