import sys
import os
import subprocess
import json

urls = [
    "https://0x00sec.org/latest.json",
    "https://0x00sec.org/c/malware/14.json",
    "https://0x00sec.org/t/cve-2024-38077-windows-remote-desktop-licensing-service-rce/39564"
]

for url in urls:
    print(f"\nFETCHING WITH -L: {url}")
    cmd = ["curl", "-s", "-L", "-i", "-A", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", url]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    header_part, _, body_part = res.stdout.partition("\r\n\r\n")
    if not body_part and "\n\n" in res.stdout:
        header_part, _, body_part = res.stdout.partition("\n\n")
    print(f"BODY LEN: {len(body_part)}")
    if body_part and body_part.startswith("{"):
        try:
            data = json.loads(body_part)
            if "topic_list" in data:
                topics = data["topic_list"].get("topics", [])
                print(f"Found {len(topics)} topics in JSON!")
                for t in topics[:5]:
                    slug = t.get("slug")
                    tid = t.get("id")
                    title = t.get("title")
                    print(f"  → https://0x00sec.org/t/{slug}/{tid} | Title: {title}")
        except Exception as e:
            print("Error parsing JSON:", e)
    elif "0x00sec" in body_part:
        print("HTML received! Snippet:", body_part[:300])
