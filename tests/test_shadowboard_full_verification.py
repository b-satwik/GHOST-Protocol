import os
import time
import json
import urllib.request
import urllib.parse
import http.cookiejar
import socket
import unittest

# Try installing/importing PySocks if available for SOCKS5 proxy test
try:
    import socks
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

BASE_URL = "http://127.0.0.1:8080"
SOCKS_PROXY_HOST = "127.0.0.1"
SOCKS_PROXY_PORT = 9050

class TestShadowBoardFullVerification(unittest.TestCase):
    def setUp(self):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))

    def test_01_unauthenticated_redirect_login_required(self):
        """Verify unauthenticated requests return 401 with login prompt."""
        url = f"{BASE_URL}/"
        try:
            req = urllib.request.Request(url)
            resp = self.opener.open(req)
            status = resp.getcode()
            body = resp.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read().decode('utf-8')

        self.assertEqual(status, 401, "Unauthenticated request MUST return HTTP 401")
        self.assertIn("Login Required", body)
        self.assertIn("user01", body)

    def test_02_authentication_workflow(self):
        """Verify authentication with valid credentials sets session token."""
        login_url = f"{BASE_URL}/login"
        form_data = urllib.parse.urlencode({
            "username": "user01",
            "password": "ShadowPass123!"
        }).encode('utf-8')

        req = urllib.request.Request(login_url, data=form_data, method='POST')
        resp = self.opener.open(req)

        self.assertEqual(resp.getcode(), 200)
        body = resp.read().decode('utf-8')
        self.assertIn("ShadowBoard Discussions", body)

        cookies = {cookie.name: cookie.value for cookie in self.cookie_jar}
        self.assertIn("session_token", cookies)
        self.assertTrue(cookies["session_token"].startswith("sb_sess_"))

    def test_03_create_post_and_view(self):
        """Verify creating a new post and viewing thread details."""
        # 1. Login as user03
        login_data = urllib.parse.urlencode({"username": "user03", "password": "ShadowPass123!"}).encode('utf-8')
        self.opener.open(urllib.request.Request(f"{BASE_URL}/login", data=login_data, method='POST'))

        # 2. Create post
        create_url = f"{BASE_URL}/post/create"
        title = "ApexGlobal Cloud Gateway Security Audit Test"
        content = "Synthetic test content reviewing ApexGlobal Cloud Gateway rules."
        category = "Security Audit"

        post_data = urllib.parse.urlencode({
            "title": title,
            "content": content,
            "category": category
        }).encode('utf-8')

        resp = self.opener.open(urllib.request.Request(create_url, data=post_data, method='POST'))
        self.assertEqual(resp.getcode(), 200)
        body = resp.read().decode('utf-8')

        self.assertIn(title, body)
        self.assertIn(content, body)
        self.assertIn("user03", body)

    def test_04_reply_and_nested_reply_workflow(self):
        """Verify replying to a post and submitting nested replies."""
        # 1. Create post as user03
        login_u3 = urllib.parse.urlencode({"username": "user03", "password": "ShadowPass123!"}).encode('utf-8')
        self.opener.open(urllib.request.Request(f"{BASE_URL}/login", data=login_u3, method='POST'))

        post_data = urllib.parse.urlencode({
            "title": "Northstar Systems Backup Validation",
            "content": "Checking telemetry backup sync on Northstar cluster.",
            "category": "Telemetry Analysis"
        }).encode('utf-8')

        resp_post = self.opener.open(urllib.request.Request(f"{BASE_URL}/post/create", data=post_data, method='POST'))
        post_url = resp_post.geturl()
        post_id = post_url.split("/post/")[1]

        # 2. Login as user07 and reply to post
        opener_u7 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        login_u7 = urllib.parse.urlencode({"username": "user07", "password": "ShadowPass123!"}).encode('utf-8')
        opener_u7.open(urllib.request.Request(f"{BASE_URL}/login", data=login_u7, method='POST'))

        reply_data1 = urllib.parse.urlencode({
            "content": "User07 replying: Backup logs verified cleanly.",
            "parent_reply_id": ""
        }).encode('utf-8')

        resp_r1 = opener_u7.open(urllib.request.Request(f"{BASE_URL}/post/{post_id}/reply", data=reply_data1, method='POST'))
        body_r1 = resp_r1.read().decode('utf-8')

        self.assertIn("User07 replying: Backup logs verified cleanly.", body_r1)
        self.assertIn("user07", body_r1)

        # Extract reply ID from page HTML (reply-X)
        import re
        reply_ids = re.findall(r'id="reply-(\d+)"', body_r1)
        self.assertTrue(len(reply_ids) > 0, "Reply ID must be present in HTML DOM")
        parent_r_id = reply_ids[-1]

        # 3. Submit nested reply as user05 under parent_r_id
        opener_u5 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        login_u5 = urllib.parse.urlencode({"username": "user05", "password": "ShadowPass123!"}).encode('utf-8')
        opener_u5.open(urllib.request.Request(f"{BASE_URL}/login", data=login_u5, method='POST'))

        nested_data = urllib.parse.urlencode({
            "content": "User05 nested reply: Confirmed patch applied on node-03.",
            "parent_reply_id": parent_r_id
        }).encode('utf-8')

        resp_nested = opener_u5.open(urllib.request.Request(f"{BASE_URL}/post/{post_id}/reply", data=nested_data, method='POST'))
        body_nested = resp_nested.read().decode('utf-8')

        self.assertIn("User05 nested reply: Confirmed patch applied on node-03.", body_nested)
        self.assertIn("comment-tree", body_nested)

    def test_05_user_profile_and_activity_logging(self):
        """Verify user profile page displays activity logs and stats."""
        login_data = urllib.parse.urlencode({"username": "user01", "password": "ShadowPass123!"}).encode('utf-8')
        self.opener.open(urllib.request.Request(f"{BASE_URL}/login", data=login_data, method='POST'))

        resp = self.opener.open(urllib.request.Request(f"{BASE_URL}/user/user01"))
        self.assertEqual(resp.getcode(), 200)
        body = resp.read().decode('utf-8')

        self.assertIn("User Profile: user01", body)
        self.assertIn("Activity History Log", body)
        self.assertIn("login", body)

    def test_06_realtime_polling_api(self):
        """Verify real-time reply count and post feed API endpoints."""
        login_data = urllib.parse.urlencode({"username": "user01", "password": "ShadowPass123!"}).encode('utf-8')
        self.opener.open(urllib.request.Request(f"{BASE_URL}/login", data=login_data, method='POST'))

        # Fetch replies count API
        resp1 = self.opener.open(urllib.request.Request(f"{BASE_URL}/api/post/1/replies"))
        data1 = json.loads(resp1.read().decode('utf-8'))
        self.assertTrue(data1["success"])
        self.assertIn("reply_count", data1)

        # Fetch posts array API
        resp2 = self.opener.open(urllib.request.Request(f"{BASE_URL}/api/posts"))
        data2 = json.loads(resp2.read().decode('utf-8'))
        self.assertTrue(data2["success"])
        self.assertGreater(len(data2["posts"]), 0)

    def test_07_lab_admin_reset_workflow(self):
        """Verify lab reset endpoint resets user data while preserving accounts."""
        login_data = urllib.parse.urlencode({"username": "user10", "password": "ShadowPass123!"}).encode('utf-8')
        self.opener.open(urllib.request.Request(f"{BASE_URL}/login", data=login_data, method='POST'))

        # Perform admin reset
        resp = self.opener.open(urllib.request.Request(f"{BASE_URL}/admin/reset", data=b"", method='POST'))
        self.assertEqual(resp.getcode(), 200)

        # Verify initial harmless discussions re-seeded
        resp_feed = self.opener.open(urllib.request.Request(f"{BASE_URL}/forum"))
        body = resp_feed.read().decode('utf-8')
        self.assertIn("ApexGlobal Infrastructure Audit", body)

if __name__ == "__main__":
    unittest.main()
