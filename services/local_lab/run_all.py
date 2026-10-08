"""
DarkWatch Local Test Lab Multi-Service Master Runner (Revised Architecture)
Runs ports 8001 (Direct), 8002 (Tor), 8003 (VPN), 8004 (2FA), and 8005 (No2FA) concurrently in Python threads.
"""

import os
import sys
import threading
import time

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from services.local_lab.seed_data import seed_test_data
from services.local_lab.chat_app import create_chat_app

def run_chat_service(port):
    print(f"[+] Controlled Chat Service (Port {port}) listening on http://127.0.0.1:{port}")
    app = create_chat_app(service_id=str(port))
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

def start_all():
    print("[+] Seeding database and processing initial synthetic records...")
    seed_test_data()

    threads = []
    for p in [8001, 8002, 8003, 8004, 8005]:
        t = threading.Thread(target=run_chat_service, args=(p,), daemon=True)
        threads.append(t)
        t.start()

    print("=========================================================================")
    echo_msg = """
DarkWatch Local 5-Service Lab RUNNING!
- Service A (Port 8001 - Direct): http://127.0.0.1:8001
- Service B (Port 8002 - Tor):    http://127.0.0.1:8002  (Direct access blocked)
- Service C (Port 8003 - VPN):    http://127.0.0.1:8003  (Direct access blocked)
- Service D (Port 8004 - 2FA):    http://127.0.0.1:8004  (2-Step Verification)
- Service E (Port 8005 - No2FA):  http://127.0.0.1:8005  (Baseline Password)
    """
    print(echo_msg)
    print("=========================================================================")

    while True:
        time.sleep(1)

if __name__ == "__main__":
    start_all()
