#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "=== DarkWatch Docker Container Status ==="
docker ps --filter "name=darkwatch"

PYTHON_EXEC=""
if [ -f "${REPO_ROOT}/.venv/bin/python3" ]; then
    PYTHON_EXEC="${REPO_ROOT}/.venv/bin/python3"
else
    PYTHON_EXEC="python3"
fi

echo ""
echo "=== DarkWatch Lab Endpoint Reachability Check ==="
"${PYTHON_EXEC}" -c '
import urllib.request, urllib.error

base_url = "http://127.0.0.1:8080"
endpoints = [
    ("/forum", 200, "Forum Discussion"),
    ("/market", 200, "Cryptomarket Baseline"),
    ("/paste", 200, "Code/Paste PoC"),
    ("/leak", 200, "Ransomware Disclosures"),
    ("/barrier", 503, "DDoS CAPTCHA Barrier (Expected Blocked)"),
    ("/session_gated", 401, "Session Token Required (Expected Unauthorized)"),
    ("/dynamic_forum", 200, "Dynamic Feed"),
    ("/forum_mirror", 200, "Near-Duplicate Mirror")
]

for ep, expected_code, name in endpoints:
    url = base_url + ep
    actual_code = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DarkWatch-LabCheck/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            actual_code = resp.status
    except urllib.error.HTTPError as e:
        actual_code = e.code
    except Exception:
        actual_code = 0

    status_str = "REACHABLE (OK)" if actual_code == expected_code else f"HTTP {actual_code}"
    print(f"  {ep:<18} | {status_str:<15} | {name}")
'
