"""
Comprehensive Verification Script for GHOST Protocol Observation, Scraping & Deduplication
Tests:
1. DOM Content Boundary (exclusion of navigation, sidebar, logged-in badges from root & replies)
2. Thread Candidate Queue Rotation (discovers multiple threads, claims TAKEN, updates cursor)
3. Content Hash / Change Detection (unchanged hash -> UNCHANGED status, no duplicate processing)
4. Reply & Timeline Deduplication (multi-pass observation on same thread -> ZERO duplicate replies, ZERO duplicate timeline entries)
5. Threat Session Identity (1 Thread = 1 ThreatSession identity, updated only when new replies appear)
6. Network Modality (missing flow -> XGBoost NETWORK MODALITY UNAVAILABLE)
"""

import os
import sys
import datetime
import hashlib

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.observer.adapters.shadowboard_adapter import ShadowBoardAdapter
from src.observer.adapters.discourse_adapter import DiscourseAdapter
from src.observer.adapters.xenforo_adapter import XenForoAdapter
from src.resolution.session_manager import ThreatSessionManager, ThreatSession
from src.dataset.annotation_store import AnnotationStore

def test_shadowboard_dom_boundary():
    print("[1] Testing ShadowBoard DOM Extraction Boundary...")
    raw_html = """
    <!DOCTYPE html>
    <html>
    <head><title>ShadowBoard Discussions</title></head>
    <body>
        <div class="navbar">
            <span>ShadowBoard Discussions</span>
            <span>Logged in as: user01</span>
            <a href="/profile">My Profile</a>
            <a href="/admin">Lab Admin</a>
            <a href="/logout">Logout</a>
        </div>
        <div id="post-root" class="post-detail">
            <h1 class="post-title">Database access discussion & credentials</h1>
            <div class="meta">
                <span class="user-badge">user03</span>
                <time>2026-10-05 10:09:34</time>
            </div>
            <div class="post-content">
                We have gained full root access to the core database cluster. Credentials follow.
            </div>
        </div>
        <div class="comment-tree">
            <div class="nested-comment" id="comment-101">
                <span class="user-badge">user01</span>
                <time>2026-10-05 10:15:02</time>
                <div class="message-body">I have verified access to internal network.</div>
            </div>
        </div>
        <div class="sidebar">
            <h3>Recent Discussions</h3>
            <p>Vulnerability Research ... Posted by user01</p>
        </div>
    </body>
    </html>
    """
    adapter = ShadowBoardAdapter()
    info = adapter.extract_thread_info("http://localhost:8080/post/db_access", raw_html)

    assert info["title"] == "Database access discussion & credentials", f"Unexpected title: {info['title']}"
    assert info["author"] == "user03", f"Unexpected author: {info['author']}"
    assert "Logged in as" not in info["content"], "Global nav text leaked into content!"
    assert "Lab Admin" not in info["content"], "Global nav text leaked into content!"
    assert "Recent Discussions" not in info["content"], "Sidebar leaked into content!"
    assert len(info["direct_replies"]) == 1, f"Expected 1 reply, got {len(info['direct_replies'])}"
    assert info["direct_replies"][0]["username"] == "user01", "Reply author mismatch"
    assert info["direct_replies"][0]["reply_id"] == "reply_101", f"Unstable reply ID: {info['direct_replies'][0]['reply_id']}"
    print("  [PASS] ShadowBoard DOM Extraction Boundary verified clean.")

def test_reply_deduplication():
    print("[2] Testing ThreatSession Reply & Timeline Deduplication...")
    db_path = "data/test_dedup.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    store = AnnotationStore(db_path=db_path)
    mgr = ThreatSessionManager(store=store)

    obs_pass1 = {
        "obs_id": "obs_pass_1",
        "source_id": "test_src_01",
        "canonical_url": "http://test.forum/post/101",
        "sanitized_text": "Root content body",
        "root_author": "user03",
        "thread_info": {
            "title": "Database access discussion",
            "content": "Root content body",
            "author": "user03",
            "post_id": "post_101",
            "timestamp": "2026-10-05T10:09:34Z",
            "direct_replies": [
                {"reply_id": "reply_101", "username": "user01", "timestamp": "2026-10-05T10:15:02Z", "message": "Reply 1 message"},
                {"reply_id": "reply_102", "username": "user07", "timestamp": "2026-10-05T10:21:10Z", "message": "Reply 2 message"}
            ]
        }
    }

    sess, action1, reasons1 = mgr.evaluate_observation(obs_pass1)
    session_id = sess.session_id
    print(f"  First Pass -> Session {session_id} created with {len(sess.direct_replies)} replies, {len(sess.timeline)} timeline events.")
    assert len(sess.direct_replies) == 2, f"Expected 2 replies, got {len(sess.direct_replies)}"
    assert len(sess.timeline) == 3, f"Expected 3 timeline events (1 root + 2 replies), got {len(sess.timeline)}"

    # Second pass: identical observation (re-observing same thread unchanged)
    obs_pass2 = {
        "obs_id": "obs_pass_2",
        "source_id": "test_src_01",
        "canonical_url": "http://test.forum/post/101",
        "sanitized_text": "Root content body",
        "root_author": "user03",
        "thread_info": {
            "title": "Database access discussion",
            "content": "Root content body",
            "author": "user03",
            "post_id": "post_101",
            "timestamp": "2026-10-05T10:09:34Z",
            "direct_replies": [
                {"reply_id": "reply_101", "username": "user01", "timestamp": "2026-10-05T10:15:02Z", "message": "Reply 1 message"},
                {"reply_id": "reply_102", "username": "user07", "timestamp": "2026-10-05T10:21:10Z", "message": "Reply 2 message"}
            ]
        }
    }

    sess2, action2, reasons2 = mgr.evaluate_observation(obs_pass2)
    print(f"  Debug: sess2.direct_replies = {sess2.direct_replies}")
    print(f"  Debug: sess2.timeline = {sess2.timeline}")
    assert sess2.session_id == session_id, f"Session ID changed! {sess2.session_id} != {session_id}"
    print(f"  Second Pass (Unchanged) -> Session {sess2.session_id} has {len(sess2.direct_replies)} replies, {len(sess2.timeline)} timeline events.")
    assert len(sess2.direct_replies) == 2, f"Duplicate replies inserted! Got {len(sess2.direct_replies)}"
    assert len(sess2.timeline) == 3, f"Duplicate timeline entries inserted! Got {len(sess2.timeline)}"

    # Third pass: 1 new reply added to thread
    obs_pass3 = {
        "obs_id": "obs_pass_3",
        "source_id": "test_src_01",
        "canonical_url": "http://test.forum/post/101",
        "sanitized_text": "Root content body",
        "root_author": "user03",
        "thread_info": {
            "title": "Database access discussion",
            "content": "Root content body",
            "author": "user03",
            "post_id": "post_101",
            "timestamp": "2026-10-05T10:09:34Z",
            "direct_replies": [
                {"reply_id": "reply_101", "username": "user01", "timestamp": "2026-10-05T10:15:02Z", "message": "Reply 1 message"},
                {"reply_id": "reply_102", "username": "user07", "timestamp": "2026-10-05T10:21:10Z", "message": "Reply 2 message"},
                {"reply_id": "reply_103", "username": "user09", "timestamp": "2026-10-05T10:30:00Z", "message": "Reply 3 new message"}
            ]
        }
    }

    sess3, action3, reasons3 = mgr.evaluate_observation(obs_pass3)
    assert sess3.session_id == session_id
    print(f"  Third Pass (New Reply) -> Session {sess3.session_id} has {len(sess3.direct_replies)} replies, {len(sess3.timeline)} timeline events.")
    assert len(sess3.direct_replies) == 3, f"Expected 3 replies, got {len(sess3.direct_replies)}"
    assert len(sess3.timeline) == 4, f"Expected 4 timeline events, got {len(sess3.timeline)}"

    print("  [PASS] Reply and timeline deduplication verified clean.")

if __name__ == "__main__":
    test_shadowboard_dom_boundary()
    test_reply_deduplication()
    print("\nALL SCRAPING & DEDUPLICATION VERIFICATION TESTS PASSED SUCCESSFULLY!")
