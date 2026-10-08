import sys
import os
import re

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.observer.tor_browser_observer import fetch_url_over_socks5
from bs4 import BeautifulSoup

status, body, _ = fetch_url_over_socks5("https://0x00sec.org/")
print("Status:", status)
soup = BeautifulSoup(body, "html.parser")

links = []
for a in soup.find_all("a", href=True):
    href = a["href"]
    if "/t/" in href or "/c/" in href or "topic" in href.lower():
        links.append((href, a.get_text().strip()))

print(f"Total hrefs with /t/ or /c/: {len(links)}")
for href, text in links[:15]:
    print(f"  {href} -> {text[:40]}")
