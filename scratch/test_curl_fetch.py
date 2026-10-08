import sys
import os

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.observer.tor_browser_observer import fetch_url_over_socks5
from src.observer.adapters.adapter_registry import get_adapter_for_url
from src.collector.sanitizer import ContentSanitizer

sources = [
    ("0x00sec", "https://0x00sec.org/"),
    ("BlackHatWorld", "https://www.blackhatworld.com/forums/?x=-"),
    ("Darknet77", "http://shadowboard.lab.onion/forums/hacking-cracking-tools-apps.21/"),
    ("Telegram", "https://t.me/s/SliceForLifeee")
]

for name, url in sources:
    print(f"\n==================================================")
    print(f"FETCHING: {name} ({url})")
    status, body, headers = fetch_url_over_socks5(url)
    print(f"STATUS: {status} | BODY LEN: {len(body)}")
    if body:
        print(f"BODY SNIPPET: {body[:150]}...")
        adapter = get_adapter_for_url(url, body)
        print(f"ADAPTER MATCHED: {adapter.__class__.__name__} ({adapter.source_type})")
        sanitizer = ContentSanitizer()
        clean_text, _, _ = sanitizer.sanitize_html(body)
        page_type = adapter.classify_page_type(url, body, clean_text, {})
        print(f"PAGE TYPE: {page_type}")
        candidates = adapter.extract_candidate_links(url, body)
        print(f"CANDIDATES FOUND ({len(candidates)}): {candidates[:3]}")
