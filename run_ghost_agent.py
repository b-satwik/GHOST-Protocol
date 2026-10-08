#!/usr/bin/env python3
"""
🛡️ DARKWATCH GHOST PROTOCOL — AUTONOMOUS OBSERVATION AGENT
Single Executable Entry Point for Actual Tor Browser Launch & Docker Hidden Service (.onion) Test.
Runs against real persistent 56-character Tor v3 onion service addresses in the controlled Docker lab.
"""

import sys
import os
import time
import datetime
import json
import subprocess
import atexit

# Ensure repository root is in python path
repo_root = os.path.dirname(os.path.abspath(__file__))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.observer.tor_browser_observer import (
    find_installed_tor_browser,
    get_all_docker_onion_hostnames,
    get_docker_onion_hostname,
    wait_for_onion_service,
    get_persistent_tor_profile_dir,
    TorBrowserObserver
)
from src.observer.ghost_agent import GhostObservationAgent, AccessMode
from src.observer.ghost_lock_manager import GhostLockManager
from src.config import print_gemini_config_status


def print_banner(text: str):
    print("\n" + "=" * 75)
    print(f" {text}")
    print("=" * 75)


def check_and_ensure_docker_lab():
    """
    Checks if existing Docker laboratory containers are running.
    Starts docker compose if needed.
    """
    print("[+] Checking existing Docker laboratory containers...")
    res = subprocess.run(["docker", "ps"], capture_output=True, text=True)
    if "darkwatch-tor-router" not in res.stdout or "darkwatch-services" not in res.stdout:
        print("[+] Starting existing Docker laboratory environment...")
        subprocess.run(["docker", "compose", "-f", "darkwatch_labs/docker-compose.yml", "up", "-d"], check=False)
        time.sleep(3)


def is_lab_target(target_url: str, lab_onion_hosts: dict) -> bool:
    """
    Returns True if the target URL matches a known CONTROLLED_LAB target.
    Includes localhost/127.0.0.1 endpoints, .lab.onion domains, known lab services,
    and Docker container generated .onion hostnames.
    Real external .onion target addresses return False.
    """
    if not target_url:
        return False
    url_lower = target_url.lower()
    if "127.0.0.1" in url_lower or "localhost" in url_lower or ".lab.onion" in url_lower:
        return True
    for svc in ("shadowforum", "dreadlab", "pastevault", "leaklocker"):
        if svc in url_lower:
            return True
    if lab_onion_hosts:
        for svc_url in lab_onion_hosts.values():
            lab_host = svc_url.replace("http://", "").replace("https://", "").rstrip("/")
            if lab_host and lab_host in url_lower:
                return True
    return False





def run_ghost():
    import argparse
    parser = argparse.ArgumentParser(description="GHOST Protocol — Autonomous Observation Agent")
    parser.add_argument("url", nargs="?", default=None, help="Target .onion or HTTP URL to observe")
    parser.add_argument("--url", dest="url_opt", default=None, help="Target URL to observe")
    parser.add_argument("--multi-source", action="store_true", help="Run multi-source observation test across 4 public sources")
    parser.add_argument("--demo", action="store_true", help="Execute observation passes then pause")
    parser.add_argument("--synthetic-session", action="store_true", help="Use synthetic lab session token")
    parser.add_argument("--poll-interval", type=int, default=10, help="Polling interval in seconds")
    parser.add_argument("--duration", type=int, default=180, help="Observation wait duration in seconds (default: 180s / 3 minutes)")
    args, _ = parser.parse_known_args()

    print_banner("GHOST PROTOCOL — AUTONOMOUS OBSERVATION DECISION AGENT")
    print_gemini_config_status()

    # 0. Multi-source mode execution
    if args.multi_source:
        print_banner("GHOST PROTOCOL — PUBLIC MULTI-SOURCE SCRAPING TEST")
        sources = [
            ("Source 1 (0x00sec)", "https://0x00sec.org/"),
            ("Source 2 (BlackHatWorld)", "https://www.blackhatworld.com/forums/?x=-"),
            ("Source 3 (Darknet77 Onion)", "http://shadowboard.lab.onion/forums/hacking-cracking-tools-apps.21/"),
            ("Source 4 (Telegram Channel)", "https://t.me/s/SliceForLifeee")
        ]

        agent = GhostObservationAgent(
            proxy_host="127.0.0.1",
            proxy_port=9050,
            history_db="data/observation_history.db",
            headless=True,
            access_mode=AccessMode.AUTO
        )

        results = []
        for name, src_url in sources:
            print_banner(f"OBSERVING: {name}\nURL: {src_url}")
            dec = agent.evaluate_access_decision(src_url)
            obs = agent.observe_target(src_url, force_decision=dec)
            results.append({
                "name": name,
                "url": src_url,
                "collector": obs.get("collector", dec.get("selected_collector")),
                "access_req": dec.get("access_requirement"),
                "nav_status": obs.get("navigation_status"),
                "threat_session": obs.get("threat_session")
            })

        print("\n============================================================")
        print("MULTI-SOURCE SCRAPING SUMMARY")
        print("============================================================")
        for r in results:
            print(f"{r['name']}: {r['url']}")
            print(f"  Collector: {r['collector']} | Access: {r['access_req']} | Nav: {r['nav_status']} | TS: {r['threat_session']}")
        print("============================================================\n")
        return

    # Single-instance lock check
    is_active, lock_data = GhostLockManager.is_lock_active()
    if is_active and lock_data and lock_data.get("pid") != os.getpid():
        print("\n" + "=" * 60)
        print("GHOST SESSION ALREADY ACTIVE")
        print("=" * 60)
        print(f"\nPID: {lock_data.get('pid')}")
        print(f"TARGET: {lock_data.get('target_url')}")
        print(f"PROFILE: {lock_data.get('profile_path')}\n")
        print("=" * 60 + "\n")
        sys.exit(0)

    print("[+] Inspecting system for actual installed Tor Browser executable...")
    binary_path, checked_paths = find_installed_tor_browser()

    if not binary_path:
        print("\nERROR: Actual Tor Browser executable was not found on system paths.")
        sys.exit(1)

    print(f"[+] DETECTED TOR BROWSER PATH: {binary_path}")

    target_url = args.url_opt or args.url
    onion_hosts = get_all_docker_onion_hostnames()
    shadow_url = onion_hosts.get("shadowforum")
    dread_url = target_url or onion_hosts.get("dreadlab") or "http://shadowboard.lab.onion/"

    lab_mode = is_lab_target(dread_url, onion_hosts)

    if lab_mode:
        check_and_ensure_docker_lab()

    target_type_str = "CONTROLLED_LAB" if lab_mode else "REAL_EXTERNAL"
    docker_lab_str = "ENABLED" if lab_mode else "DISABLED"

    print("\n============================================================")
    print("GHOST PROTOCOL — OBSERVER TARGET CONFIGURATION")
    print("============================================================")
    print(f"TARGET TYPE:  {target_type_str}")
    print(f"TOR TRANSPORT: 127.0.0.1:9050")
    print(f"DOCKER LAB:    {docker_lab_str}")
    print(f"TOR CLI CHECK: RUNNING")
    print(f"Target URL:    {dread_url}")
    print(f"OBSERVATION TIME: {args.duration}s (3 MINUTES)")
    print("============================================================\n")

    profile_dir = get_persistent_tor_profile_dir(binary_path)
    GhostLockManager.acquire_lock(os.getpid(), dread_url, profile_dir)
    atexit.register(lambda: GhostLockManager.release_lock(os.getpid()))

    if lab_mode:
        print(f"[+] Waiting for Tor v3 hidden service connectivity over SOCKS5 (127.0.0.1:9050)...")
        service_ready = wait_for_onion_service(dread_url, proxy_host="127.0.0.1", proxy_port=9050, timeout=35)
        if not service_ready:
            print("[-] Tor hidden service unreachable over SOCKS5 proxy. Aborting observation.")
            sys.exit(1)

    agent = GhostObservationAgent(
        proxy_host="127.0.0.1",
        proxy_port=9050,
        history_db="data/observation_history.db",
        headless=False,
        access_mode=AccessMode.AUTO
    )

    print_banner(f"GHOST PROTOCOL — LIVE OBSERVATION FOR {dread_url}")
    dec = agent.evaluate_access_decision(dread_url)
    
    session_tok = "valid_lab_session" if args.synthetic_session else None
    if dec.get("selected_collector") == "TOR_BROWSER":
        print(f"[+] Target requires Tor Browser ({dec.get('access_requirement')}).")
        sec_ok, sec_msg = agent.tor_browser.verify_security_policy()
        if not sec_ok:
            print(f"[-] SECURITY POLICY FAILURE: {sec_msg}")
            sys.exit(1)

        launch_diag = agent.tor_browser.launch_actual_tor_browser(dread_url)
        if not launch_diag.get("success"):
            print(f"\n[-] FAILED TO LAUNCH TOR BROWSER: {launch_diag.get('error')}")
            sys.exit(1)

        if args.demo:
            print(f"\n[+] PERSISTENT BROWSER ACTIVE — OBSERVING TARGET FOR AT LEAST {args.duration} SECONDS (3 MINUTES)...")
            start_time = time.time()
            iteration = 1
            while time.time() - start_time < args.duration:
                elapsed = int(time.time() - start_time)
                rem = max(0, args.duration - elapsed)
                print(f"\n--- [PASS {iteration} | Elapsed: {elapsed}s / {args.duration}s | Remaining: {rem}s] Observing {dread_url} ---")
                agent.observe_target(dread_url, force_decision=dec, session_token=session_tok)
                iteration += 1
                if time.time() - start_time < args.duration:
                    time.sleep(min(15, int(args.duration - (time.time() - start_time))))
        else:
            agent.run_live_observation_loop(dread_url, poll_interval=args.poll_interval, session_token=session_tok)
    else:
        if args.demo:
            print(f"\n[+] OBSERVING TARGET FOR AT LEAST {args.duration} SECONDS (3 MINUTES)...")
            start_time = time.time()
            iteration = 1
            while time.time() - start_time < args.duration:
                elapsed = int(time.time() - start_time)
                rem = max(0, args.duration - elapsed)
                print(f"\n--- [PASS {iteration} | Elapsed: {elapsed}s / {args.duration}s | Remaining: {rem}s] Observing {dread_url} ---")
                agent.observe_target(dread_url, force_decision=dec, session_token=session_tok)
                iteration += 1
                if time.time() - start_time < args.duration:
                    time.sleep(min(15, int(args.duration - (time.time() - start_time))))
        else:
            agent.run_live_observation_loop(dread_url, poll_interval=args.poll_interval, session_token=session_tok)


if __name__ == "__main__":
    run_ghost()

