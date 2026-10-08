"""
DarkWatch Local Test Lab Server Orchestrator (Revised Architecture)
CLI entrypoint to launch individual controlled services.
"""

import os
import sys
import argparse

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from services.local_lab.seed_data import seed_test_data
from services.local_lab.chat_app import create_chat_app

def main():
    parser = argparse.ArgumentParser(description="DarkWatch Local Lab Service Runner")
    parser.add_argument("--port", type=int, required=True, choices=[8001, 8002, 8003, 8004, 8005], help="Port to run (8001=Direct, 8002=Tor, 8003=VPN, 8004=2FA, 8005=No2FA)")
    args = parser.parse_args()

    seed_test_data()
    service_id = str(args.port)
    print(f"[+] Starting Controlled Chat Service (Port {args.port}) on http://127.0.0.1:{args.port}...")
    app = create_chat_app(service_id=service_id)
    app.run(host="127.0.0.1", port=args.port, debug=False)

if __name__ == "__main__":
    main()
