"""
DarkWatch Local Test Lab Seed Data Script (Revised Architecture)
Populates local SQLite database with test users and baseline chat conversations for 5 controlled services.
"""

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from services.local_lab.db import init_db, create_user, create_thread, get_threads
from src.collector.local_lab_adapter import LocalLabAdapter

def seed_test_data():
    print("[+] Initializing local database schema...")
    init_db()

    print("[+] Creating synthetic test accounts...")
    create_user("user1", "password123", role="user")
    create_user("analyst", "analyst123", role="analyst")

    existing = get_threads()
    if len(existing) > 0:
        print(f"[!] Database already seeded with {len(existing)} threads. Processing background observations...")
        LocalLabAdapter.process_all_unprocessed()
        return

    print("[+] Seeding initial chat conversations across 5 controlled services...")

    seeds = [
        {
            "service_id": "DIRECT_CHAT",
            "network_path": "DIRECT",
            "title": "General Security Discussion",
            "author_handle": "user1",
            "text": "Hello everyone, welcome to the community chat channel."
        },
        {
            "service_id": "TOR_CHAT",
            "network_path": "TOR",
            "title": "Vulnerability Analysis: TEST-CVE-0000",
            "author_handle": "synthetic_actor_01",
            "text": "Discussing remote code execution bug TEST-CVE-0000 targeting internal host 192.0.2.45 on domain example[.]local."
        },
        {
            "service_id": "VPN_CHAT",
            "network_path": "VPN",
            "title": "Internal Infrastructure & Reverse Shell Beacons",
            "author_handle": "synthetic_actor_02",
            "text": "TEST-MALWARE payload establishes reverse shell beacon to command control server 192.0.2.110 every 60 seconds."
        },
        {
            "service_id": "TWOFA_CHAT",
            "network_path": "DIRECT",
            "title": "Protected 2FA Discussion Channel",
            "author_handle": "analyst",
            "text": "Authenticated channel after 2-Step Verification code check. Discussing threat intelligence attribution techniques."
        },
        {
            "service_id": "NO2FA_CHAT",
            "network_path": "DIRECT",
            "title": "Standard Password Baseline Channel",
            "author_handle": "user1",
            "text": "Non-2FA baseline conversation channel for comparing observation metadata against 2FA services."
        }
    ]

    for item in seeds:
        res = create_thread(
            service_id=item["service_id"],
            network_path=item["network_path"],
            title=item["title"],
            author_handle=item["author_handle"],
            initial_text=item["text"]
        )
        post_id = res["post_id"]
        LocalLabAdapter.process_message(
            post_id=post_id,
            session_id=f"seed_sess_{item['service_id']}",
            network_path=item["network_path"],
            tor_verified=(item["network_path"] == "TOR"),
            vpn_verified=(item["network_path"] == "VPN"),
            observed_exit_ip="192.0.2.105" if item["network_path"] == "TOR" else "127.0.0.1"
        )

    print("[+] Seed complete! Initial conversations created and background observations stored silently.")

if __name__ == "__main__":
    seed_test_data()
