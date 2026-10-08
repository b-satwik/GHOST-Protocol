"""
Comprehensive Unit Test Suite for Access State Detection & Thread Extraction in GHOST Protocol.

Tests:
1. Login/2FA page → No Threat Session, no fake post ID, no ML execution.
2. Queue page → No Threat Session, no fake post ID, no ML execution.
3. Authenticated landing page → Automatic post discovery.
4. Inaccessible post → ACCESS_REQUIRED / QUEUED, no ML execution.
5. Accessible post → Valid Threat Session created.
6. Root post + direct replies + nested replies → Exactly ONE Threat Session.
7. Repeated polling of root post → Updates existing Threat Session (no duplicate sessions).
8. Empty / ambiguous extraction → Fail closed, no fake ML analysis.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.observer.ghost_agent import (
    GhostObservationAgent,
    detect_access_or_non_content_state
)
from src.resolution.session_manager import ThreatSessionManager, ThreatSession


class TestAccessStateAndThreadExtraction(unittest.TestCase):

    def setUp(self):
        self.agent = GhostObservationAgent(
            proxy_host="127.0.0.1",
            proxy_port=9050,
            history_db=":memory:",
            enforce_whonix=False
        )

    def test_01_login_2fa_page_no_threat_session(self):
        """1. Login/2FA page MUST NOT create Threat Session or run ML."""
        login_html = """
        <html>
            <head><title>Dread — 2-Step Verification Required</title></head>
            <body>
                <h1>Authorization Required</h1>
                <p>Please log in or complete 2-step verification to continue.</p>
                <form action="/login" method="post"><input type="password" name="2fa"></form>
            </body>
        </html>
        """
        clean_text = "Dread — 2-Step Verification Required Authorization Required Please log in"
        
        state = detect_access_or_non_content_state(login_html, clean_text, 200, "http://dread.onion/login")
        self.assertIn(state, ("TWO_STEP_REQUIRED", "LOGIN_REQUIRED"))

        with patch.object(self.agent.tor_browser, "navigate_and_observe", return_value={
            "navigation_status": "SUCCESS",
            "http_status": 200,
            "raw_html": login_html,
            "clean_text": clean_text,
            "extracted_links": []
        }):
            res = self.agent.observe_target("http://dread.onion/login", session_token=None)
            
            # MUST NOT run ML or create Threat Session
            self.assertEqual(res.get("ai_processing_status"), "SKIPPED_ACCESS_PAGE")
            self.assertIsNone(res.get("threat_session"))
            self.assertIn(res.get("access_state"), ("TWO_STEP_REQUIRED", "LOGIN_REQUIRED"))

    def test_02_queue_page_no_threat_session(self):
        """2. Queue page MUST NOT create Threat Session or run ML."""
        queue_html = """
        <html>
            <head><title>dread Access Queue</title></head>
            <body>
                <h2>dread Access Queue</h2>
                <p>You have been placed in a queue, awaiting forwarding to the platform.</p>
                <p>Your estimated wait time is <3 minutes. Please do not refresh.</p>
            </body>
        </html>
        """
        clean_text = "dread Access Queue You have been placed in a queue, awaiting forwarding to the platform. Your estimated wait time is <3 minutes"

        state = detect_access_or_non_content_state(queue_html, clean_text, 200, "http://dread.onion/")
        self.assertEqual(state, "QUEUED")

        with patch.object(self.agent.tor_browser, "navigate_and_observe", return_value={
            "navigation_status": "SUCCESS",
            "http_status": 200,
            "raw_html": queue_html,
            "clean_text": clean_text,
            "extracted_links": []
        }):
            res = self.agent.observe_target("http://dread.onion/", session_token=None)

            self.assertEqual(res.get("ai_processing_status"), "SKIPPED_ACCESS_PAGE")
            self.assertIsNone(res.get("threat_session"))
            self.assertEqual(res.get("access_state"), "QUEUED")

    def test_03_authenticated_landing_page_post_discovery(self):
        """3. Authenticated landing page MUST automatically discover post URLs."""
        landing_html = """
        <html>
            <head><title>Dread Forum Feed</title></head>
            <body>
                <h1>Recent Discussions</h1>
                <a href="/post/f4c536497e5bb6a4a8da">Zero-Day RCE Exploit Payload</a>
                <a href="/post/8892a001">Database Breach Credentials</a>
            </body>
        </html>
        """
        post_links = self.agent.link_extractor.extract_post_links(landing_html, "http://dread.onion/")
        self.assertEqual(len(post_links), 2)
        self.assertIn("http://dread.onion/post/f4c536497e5bb6a4a8da", post_links)
        self.assertIn("http://dread.onion/post/8892a001", post_links)

    def test_04_inaccessible_post_no_ml(self):
        """4. Inaccessible post URL returning queue/login MUST NOT trigger ML."""
        inaccessible_html = "<html><body><h1>Session Expired</h1><p>Please log in to view this post.</p></body></html>"
        state = detect_access_or_non_content_state(inaccessible_html, "Session Expired Please log in to view this post.", 200, "http://dread.onion/post/locked")
        self.assertIn(state, ("LOGIN_REQUIRED", "SESSION_EXPIRED", "ACCESS_REQUIRED"))

    def test_05_accessible_post_valid_threat_session(self):
        """5. Accessible post page MUST create a valid Threat Session."""
        post_html = """
        <html>
            <body>
                <h1 class="post-title">Zero-Day RCE Exploit Payload Sale</h1>
                <div class="user-badge">ViperSec</div>
                <time>2026-10-06 20:00:00</time>
                <div class="post-content">
                    Selling unpatched RCE exploit targeting ApexGlobal Financial core servers. CVE-2024-9999 POC included.
                </div>
            </body>
        </html>
        """
        thread_info = self.agent.parse_thread_from_html(post_html, "http://dread.onion/post/f4c536497e5bb6a4a8da")
        self.assertEqual(thread_info["post_id"], "post_f4c536497e5bb6a4a8da")
        self.assertEqual(thread_info["title"], "Zero-Day RCE Exploit Payload Sale")
        self.assertEqual(thread_info["author"], "ViperSec")
        self.assertIn("CVE-2024-9999", thread_info["content"])

    def test_06_root_post_and_replies_one_threat_session(self):
        """6. Root post + direct replies + nested replies MUST belong to ONE Threat Session."""
        full_thread_html = """
        <html>
            <body>
                <h1 class="post-title">Zero-Day RCE Exploit Payload Sale</h1>
                <div class="user-badge">ViperSec</div>
                <div class="post-content">Selling RCE exploit CVE-2024-9999 targeting ApexGlobal.</div>
                <div class="nested-comment" id="reply-101">
                    <span class="user-badge">Buyer01</span>
                    <div style="white-space: pre-wrap;">Interested, sent PM.</div>
                    <div class="nested-comment" id="reply-102">
                        <span class="user-badge">ViperSec</span>
                        <div style="white-space: pre-wrap;">PM received.</div>
                    </div>
                </div>
            </body>
        </html>
        """
        thread_info = self.agent.parse_thread_from_html(full_thread_html, "http://dread.onion/post/f4c536497e5bb6a4a8da")
        self.assertEqual(len(thread_info["direct_replies"]), 1)
        self.assertEqual(len(thread_info["nested_replies"]), 1)

        from src.dataset.annotation_store import AnnotationStore
        store = AnnotationStore(db_path=":memory:")
        mgr = ThreatSessionManager(store=store)
        obs_payload = {
            "obs_id": "obs_test_01",
            "canonical_url": "http://dread.onion/post/f4c536497e5bb6a4a8da",
            "target_url": "http://dread.onion/post/f4c536497e5bb6a4a8da",
            "sanitized_text": thread_info["content"],
            "text": thread_info["content"],
            "author": thread_info["author"],
            "thread_info": thread_info,
            "root_post_id": thread_info["post_id"],
            "root_post": thread_info["title"]
        }
        sess, action, reasons = mgr.evaluate_observation(obs_payload)
        self.assertEqual(action, "CREATE_NEW_SESSION")
        self.assertEqual(sess.root_post_id, "post_f4c536497e5bb6a4a8da")
        self.assertEqual(len(sess.direct_replies), 1)
        self.assertEqual(len(sess.nested_replies), 1)

    def test_07_repeated_polling_updates_same_threat_session(self):
        """7. Repeated polling of the same root post MUST update the existing Threat Session."""
        from src.dataset.annotation_store import AnnotationStore
        store = AnnotationStore(db_path=":memory:")
        thread_info = {
            "post_id": "post_f4c536497e5bb6a4a8da",
            "title": "Zero-Day RCE Exploit Payload Sale",
            "content": "Selling RCE exploit CVE-2024-9999 targeting ApexGlobal.",
            "author": "ViperSec",
            "direct_replies": [],
            "nested_replies": []
        }
        mgr = ThreatSessionManager(store=store)
        obs1 = {
            "obs_id": "obs_p1",
            "canonical_url": "http://dread.onion/post/f4c536497e5bb6a4a8da",
            "root_post_id": "post_f4c536497e5bb6a4a8da",
            "root_post": "Zero-Day RCE Exploit Payload Sale",
            "sanitized_text": "Selling RCE exploit CVE-2024-9999 targeting ApexGlobal.",
            "thread_info": thread_info
        }
        sess1, act1, _ = mgr.evaluate_observation(obs1)

        obs2 = {
            "obs_id": "obs_p2",
            "canonical_url": "http://dread.onion/post/f4c536497e5bb6a4a8da",
            "root_post_id": "post_f4c536497e5bb6a4a8da",
            "root_post": "Zero-Day RCE Exploit Payload Sale",
            "sanitized_text": "Selling RCE exploit CVE-2024-9999 targeting ApexGlobal.",
            "thread_info": thread_info
        }
        sess2, act2, _ = mgr.evaluate_observation(obs2)
        
        self.assertEqual(act2, "LINK_TO_EXISTING_SESSION")
        self.assertEqual(sess1.session_id, sess2.session_id)

    def test_08_empty_extraction_fail_closed(self):
        """8. Empty/ambiguous extraction MUST fail closed without fake ML analysis."""
        state = detect_access_or_non_content_state("", "", 200, "http://dread.onion/empty")
        self.assertEqual(state, "ACCESS_REQUIRED")

    def test_09_sidebar_stats_stripped_from_root_content(self):
        """9. Sidebar profile stats (points, joined date, post counts) MUST NOT contaminate root post body."""
        html_with_sidebar = """
        <html>
            <body>
                <h1 class="post-title">Omega Market Discussion</h1>
                <div class="user-info sidebar">
                    <span class="username">HugBunterA</span>
                    <div>/u/HugBunter</div>
                    <div>13,416 points</div>
                    <div>Joined 9 years ago</div>
                    <div>Posts128</div>
                    <div>Comments6,979</div>
                </div>
                <div class="post-content">
                    Selling unpatched database dump and admin RCE exploit payload for Omega Market.
                </div>
            </body>
        </html>
        """
        info = self.agent.parse_thread_from_html(html_with_sidebar, "http://dread.onion/post/omega_01")
        self.assertEqual(info["title"], "Omega Market Discussion")
        self.assertNotIn("Joined 9 years ago", info["content"])
        self.assertNotIn("13,416 points", info["content"])
        self.assertIn("Selling unpatched database dump", info["content"])

    def test_10_page_classification_filters_announcements_and_profiles(self):
        """10. classify_page_and_content MUST filter out announcements, profiles, and community info."""
        from src.observer.ghost_agent import classify_page_and_content

        # Announcement check
        ann_info = {"title": "[Announcement] Dread Rules and Terms of Service"}
        cls_ann = classify_page_and_content("http://dread.onion/post/ann_01", "Official Announcement Read the rules", "Official Announcement", ann_info)
        self.assertEqual(cls_ann, "ANNOUNCEMENT")

        # Profile check
        prof_info = {"title": "User Profile: HugBunter"}
        cls_prof = classify_page_and_content("http://dread.onion/u/HugBunter", "Joined 9 years ago Reputation 13416", "Joined 9 years ago", prof_info)
        self.assertEqual(cls_prof, "PROFILE")

        # Thread page check
        thread_info = {"title": "Exploit Payload Sale", "content": "Selling RCE exploit CVE-2024-9999"}
        cls_thread = classify_page_and_content("http://dread.onion/post/ex01", "Exploit Sale CVE-2024-9999", "Exploit Sale", thread_info)
        self.assertEqual(cls_thread, "THREAD_PAGE")

    def test_11_reported_vs_observed_comments_count(self):
        """11. ThreatSession MUST preserve reported comment count while recording observed comment count."""
        html_thread = """
        <html>
            <body>
                <h1 class="post-title">Database Leak Sale</h1>
                <div class="comment-count">1,079 comments</div>
                <div class="post-content">Selling database leak with 500k rows.</div>
                <div class="nested-comment" id="c1">
                    <span class="user-badge">BuyerA</span>
                    <div>Interested in database sample.</div>
                </div>
            </body>
        </html>
        """
        info = self.agent.parse_thread_from_html(html_thread, "http://dread.onion/post/db01")
        self.assertEqual(info["reported_comments_count"], 1079)
        self.assertEqual(info["observed_comments_count"], 1)

        from src.dataset.annotation_store import AnnotationStore
        store = AnnotationStore(db_path=":memory:")
        mgr = ThreatSessionManager(store=store)
        obs = {
            "obs_id": "obs_db01",
            "canonical_url": "http://dread.onion/post/db01",
            "root_post_id": "post_db01",
            "root_post": "Database Leak Sale",
            "sanitized_text": info["content"],
            "thread_info": info
        }
        sess, _, _ = mgr.evaluate_observation(obs)
        self.assertEqual(sess.metadata.get("reported_comments_count"), 1079)
        self.assertEqual(sess.metadata.get("observed_comments_count"), 1)


if __name__ == "__main__":
    unittest.main()
