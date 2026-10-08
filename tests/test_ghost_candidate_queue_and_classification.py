"""
Unit test suite verifying GHOST candidate discovery queue, cursor iteration,
page classification skipping (Announcements, Profiles, Navigation), and root post content cleanup.
"""

import pytest
from src.observer.ghost_agent import GhostObservationAgent, classify_page_and_content


def test_classify_page_and_content_announcement():
    url = "http://dreadland.lab.onion/d/community/post/rev-94a1ba9a44"
    html = "<html><body><h1>Re-vamped Dread - Announcement</h1><p>Welcome to Dread rules and updates</p></body></html>"
    text = "Re-vamped Dread - Announcement Welcome to Dread rules and updates"
    thread_info = {
        "title": "Re-vamped Dread - Announcement",
        "content": "Welcome to Dread rules and updates",
        "author": "HugBunter",
        "post_id": "post_rev94a1ba9a44"
    }

    res = classify_page_and_content(url, html, text, thread_info)
    assert res == "ANNOUNCEMENT"


def test_classify_page_and_content_profile():
    url = "http://dreadland.lab.onion/u/HugBunter"
    html = "<html><body><h1>User Profile</h1><p>Joined 9 years ago</p></body></html>"
    text = "User Profile Joined 9 years ago"
    thread_info = {"title": "User Profile", "content": "", "author": "HugBunter", "post_id": None}

    res = classify_page_and_content(url, html, text, thread_info)
    assert res == "PROFILE"


def test_classify_page_and_content_front_page():
    url = "http://dreadland.lab.onion/"
    html = "<html><body><h1>Frontpage - Dread</h1><a href='/post/123'>Post 1</a></body></html>"
    text = "Frontpage - Dread Post 1"
    thread_info = {"title": "Frontpage - Dread", "content": "Post 1", "author": None, "post_id": None}

    res = classify_page_and_content(url, html, text, thread_info)
    assert res == "FRONT_PAGE"


def test_candidate_queue_cursor_advancement():
    agent = GhostObservationAgent(headless=True)
    agent.discovery_queue = [
        "http://test.onion/post/1",
        "http://test.onion/post/2",
        "http://test.onion/post/3"
    ]

    assert agent.discovery_cursor == 0
    # Simulate selecting candidate 1
    idx1 = agent.discovery_cursor % len(agent.discovery_queue)
    assert agent.discovery_queue[idx1] == "http://test.onion/post/1"
    agent.discovery_cursor += 1

    # Simulate selecting candidate 2
    idx2 = agent.discovery_cursor % len(agent.discovery_queue)
    assert agent.discovery_queue[idx2] == "http://test.onion/post/2"
    agent.discovery_cursor += 1

    # Simulate selecting candidate 3
    idx3 = agent.discovery_cursor % len(agent.discovery_queue)
    assert agent.discovery_queue[idx3] == "http://test.onion/post/3"
    agent.discovery_cursor += 1

    # Wraps around cleanly to candidate 1
    idx4 = agent.discovery_cursor % len(agent.discovery_queue)
    assert agent.discovery_queue[idx4] == "http://test.onion/post/1"


def test_parse_thread_from_html_profile_cleanup():
    agent = GhostObservationAgent(headless=True)
    html = """
    <html>
        <body>
            <div class="user-badge">/u/HugBunterA</div>
            <div class="user-stats">
                13,416 points<br/>
                Joined 9 years ago<br/>
                Posts128<br/>
                Comments6,979
            </div>
            <h1 class="post-title">Zero-Day Vulnerability Advisory</h1>
            <div class="post-content">
                We have uncovered an unpatched RCE vulnerability affecting Apache HTTP Server.
                CVE-2024-9999 allows unauthorized remote code execution.
            </div>
        </body>
    </html>
    """
    url = "http://test.onion/post/cve20249999"
    info = agent.parse_thread_from_html(html, url)

    assert info["author"] == "HugBunter"
    assert info["title"] == "Zero-Day Vulnerability Advisory"
    assert "CVE-2024-9999" in info["content"]
    assert "13,416 points" not in info["content"]
    assert "Joined 9 years ago" not in info["content"]


def test_end_to_end_candidate_queue_and_cursor_flow(monkeypatch):
    agent = GhostObservationAgent(headless=True)
    monkeypatch.setattr(type(agent.tor_browser), "is_running", property(lambda self: True))

    # 22 Candidate URLs simulated
    candid_urls = [f"http://dreadland.lab.onion/post/cand_{i}" for i in range(22)]
    # Make candidate 0 an announcement
    candid_urls[0] = "http://dreadland.lab.onion/d/community/post/rev-94a1ba9a44"

    agent.discovery_queue = list(candid_urls)

    # Mock navigate_and_observe to return appropriate pages for candidates
    def mock_navigate_and_observe(url, session_token=None):
        if "rev-94a1ba9a44" in url:
            return {
                "raw_html": "<html><body><h1>Re-vamped Dread - Announcement</h1><p>Rules and system notices</p></body></html>",
                "clean_text": "Re-vamped Dread - Announcement Rules and system notices",
                "http_status": 200,
                "clean_sha256": "sha_announcement_1"
            }
        elif url == "http://dreadland.lab.onion/":
            return {
                "raw_html": "<html><body><h1>Dread Forum Main Page</h1><a href='/post/cand_1'>Link</a></body></html>",
                "clean_text": "Dread Forum Main Page Link",
                "http_status": 200,
                "clean_sha256": "sha_main_page"
            }
        else:
            return {
                "raw_html": """<html><body>
                    <div class="user-badge">/u/DarkNetUserA</div>
                    <h1 class="post-title">CVE-2024-1234 Threat Post</h1>
                    <div class="post-content">Exploit payload RCE zero-day vulnerability details</div>
                </body></html>""",
                "clean_text": "DarkNetUser CVE-2024-1234 Threat Post Exploit payload RCE zero-day vulnerability details",
                "http_status": 200,
                "clean_sha256": f"sha_threat_{url}"
            }

    monkeypatch.setattr(agent.tor_browser, "navigate_and_observe", mock_navigate_and_observe)
    agent.active_sessions["http://dreadland.lab.onion/"] = {
        "status": "AUTHENTICATED",
        "session_token": "valid_token"
    }

    # Pass 1: Candidate 1 (Announcement) -> Skipped -> Cursor becomes 1
    res1 = agent.observe_target("http://dreadland.lab.onion/", session_token="valid_token")
    assert res1["navigation_status"] == "SKIPPED_ANNOUNCEMENT"
    assert res1["page_type"] == "ANNOUNCEMENT"
    assert agent.discovery_cursor == 1
    assert agent.candidates_skipped_count == 1

    # Pass 2: Candidate 2 (Threat Post) -> Processed -> ThreatSession created -> Cursor becomes 2
    res2 = agent.observe_target("http://dreadland.lab.onion/", session_token="valid_token")
    assert res2["navigation_status"] == "SUCCESS"
    assert res2["page_type"] == "THREAD_PAGE"
    assert res2["threat_session"] is not None
    assert agent.discovery_cursor == 2
    assert agent.candidates_processed_count == 2

    # Pass 3: Candidate 3 (Threat Post) -> Processed -> Cursor becomes 3
    res3 = agent.observe_target("http://dreadland.lab.onion/", session_token="valid_token")
    assert res3["navigation_status"] == "SUCCESS"
    assert res3["page_type"] == "THREAD_PAGE"
    assert agent.discovery_cursor == 3
    assert agent.candidates_processed_count == 3

