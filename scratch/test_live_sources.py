import sys
import os
import urllib.request
import socks
import socket

repo_root = os.path.dirname(os.path.dirname(os.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.observer.tor_browser_observer import fetch_url_over_socks5
from src.observer.adapters.adapter_registry import get_adapter_for_url
from src.collector.sanitizer import ContentSanitizer
from src.filter.threat_filter import ThreatFilter
from src.pipeline.lab_bridge import DarkWatchLabBridge
from src.discovery.observation_record import ObservationRecord
import datetime
import time

def fetch_live_url(url: str, proxy_host: str = "127.0.0.1", proxy_port: int = 9050):
    """
    Attempts fetch over Tor SOCKS5 proxy first. If clearnet and SOCKS5 proxy is offline,
    falls back to direct HTTPS fetch for public clearnet URLs.
    """
    status, body, headers = fetch_url_over_socks5(url, proxy_host=proxy_host, proxy_port=proxy_port, timeout=15)
    if status == 200 and body:
        return status, body, "SOCKS5_TOR"

    if not url.endswith(".onion"):
        # Fallback to direct HTTPS request for public clearnet URLs if Tor CLI proxy not active
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/115.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="ignore")
                return status, body, "HTTP_DIRECT"
        except Exception as e:
            return 0, f"Error: {e}", "FAILED"

    return status, body, "SOCKS5_TOR"

def test_source(name: str, url: str):
    print(f"\nTesting {name}: {url}")
    status, body, access_method = fetch_live_url(url)
    print(f"Status: {status} via {access_method}, Body len: {len(body)}")
    adapter = get_adapter_for_url(url, body)
    print(f"Adapter: {adapter.__class__.__name__} (source_type: {adapter.source_type})")
    
    sanitizer = ContentSanitizer()
    clean_text, text_len, clean_sha = sanitizer.sanitize_html(body)
    page_type = adapter.classify_page_type(url, body, clean_text, {})
    print(f"Page Type: {page_type}")

    candidates = adapter.extract_candidate_links(url, body)
    print(f"Candidates found: {len(candidates)}")
    if candidates:
        print(f"Sample candidate: {candidates[0]}")
        cand_status, cand_body, _ = fetch_live_url(candidates[0])
        print(f"Candidate fetch status: {cand_status}, body len: {len(cand_body)}")
        cand_adapter = get_adapter_for_url(candidates[0], cand_body)
        cand_thread = cand_adapter.extract_thread_info(candidates[0], cand_body)
        print(f"Candidate Thread Info: Title='{cand_thread.get('title')}', Author='{cand_thread.get('author')}', Content len={len(cand_thread.get('content') or '')}")

if __name__ == "__main__":
    sources = [
        ("0x00sec", "https://0x00sec.org/"),
        ("BlackHatWorld", "https://www.blackhatworld.com/forums/?x=-"),
        ("Darknet77", "http://shadowboard.lab.onion/forums/hacking-cracking-tools-apps.21/"),
        ("Telegram", "https://t.me/s/SliceForLifeee")
    ]
    for name, url in sources:
        test_source(name, url)
