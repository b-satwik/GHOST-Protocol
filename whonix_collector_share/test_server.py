#!/usr/bin/env python3
"""
Lightweight Controlled Test HTTP Server for DarkWatch State Machine & Harness Testing.
Simulates dark web source conditions (accessible, captcha blocked, uninformative,
content changed, near-duplicate mirror, 500 error) on 127.0.0.1:8080.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import threading
import time

ACCESSIBLE_HTML = """<!DOCTYPE html>
<html>
<head><title>LockBit 3.0 Ransomware Leak Site</title></head>
<body>
    <h1>LockBit 3.0 Ransomware Proof</h1>
    <p>Target CVE-2023-4966 vulnerability remote code execution exploit released.</p>
    <p>Contact via Telegram @darknet_dealer or Jabber. Command and Control Server IP: 192.168.1.50.</p>
    <p>Bitcoin Payment Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
    <p>Official Tor Mirror: leaklocker.lab.onion</p>
</body>
</html>"""

BLOCKED_HTML = """<!DOCTYPE html>
<html>
<head><title>DDoS Protection / CAPTCHA Challenge</title></head>
<body>
    <h1>Attention Required! Cloudflare CAPTCHA Verification</h1>
    <p>Please verify you are human to access this hidden service. Access Denied. Ray ID: 89ab12345cd678ef.</p>
</body>
</html>"""

UNINFORMATIVE_HTML = """<!DOCTYPE html><html><body><p>Ok</p></body></html>"""

CHANGED_HTML = """<!DOCTYPE html>
<html>
<head><title>LockBit 3.0 Ransomware Leak Site UPDATE</title></head>
<body>
    <h1>LockBit 3.0 Ransomware Proof UPDATE</h1>
    <p>Target CVE-2023-4966 and CVE-2024-38077 remote code execution exploit released.</p>
    <p>Includes 500x stolen RDP access credentials dump. Contact via Telegram @darknet_dealer.</p>
    <p>Bitcoin Payment Address: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy. Command and Control IP: 192.168.1.50.</p>
</body>
</html>"""

MIRROR_HTML = """<!DOCTYPE html>
<html>
<head><title>LockBit 3.0 Ransomware Leak Site</title></head>
<body>
    <h1>LockBit 3.0 Ransomware Proof</h1>
    <p>Target CVE-2023-4966 vulnerability remote code execution exploit released.</p>
    <p>Contact via Telegram @darknet_dealer or Jabber. Command and Control Server IP: 192.168.1.50.</p>
    <p>Bitcoin Payment Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
    <p>Official Tor Mirror: leaklocker.lab.onion. Mirror link active now.</p>
</body>
</html>"""


class DarkWatchTestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler simulating DarkWatch source state routes."""

    def log_message(self, format, *args):
        # Suppress standard logging output for clean harness execution
        pass

    def do_GET(self):
        path = self.path.split('?')[0]

        if path == "/accessible":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(ACCESSIBLE_HTML.encode("utf-8"))

        elif path == "/blocked":
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(BLOCKED_HTML.encode("utf-8"))

        elif path == "/uninformative":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(UNINFORMATIVE_HTML.encode("utf-8"))

        elif path == "/changed":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(CHANGED_HTML.encode("utf-8"))

        elif path == "/mirror":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(MIRROR_HTML.encode("utf-8"))

        elif path == "/500_error":
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>500 Internal Server Error</body></html>")

        elif path == "/shutdown":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Server shutting down...")
            threading.Thread(target=self.server.shutdown).start()

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")


def run_server(host="127.0.0.1", port=8080):
    server = HTTPServer((host, port), DarkWatchTestHandler)
    print(f"DarkWatch Controlled Test Server running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port=port)
