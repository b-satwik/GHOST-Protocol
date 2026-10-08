#!/usr/bin/env bash
# ==============================================================================
# Whonix DarkWatch Controlled Onion Endpoint Check Script
# ==============================================================================
# Checks authorized DarkWatch .onion lab endpoints via SOCKS5 proxy.
# Does NOT attempt to bypass barriers (503) or authentication (401).
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ONION_HOST="shadowboard.lab.onion"
if [ -f "${SHARE_DIR}/darkwatch_lab_onion_url.txt" ]; then
    URL_LINE=$(head -n 1 "${SHARE_DIR}/darkwatch_lab_onion_url.txt" | tr -d '\r\n')
    if [ -n "${URL_LINE}" ]; then
        ONION_HOST=$(echo "${URL_LINE}" | sed -E 's|https?://||' | cut -d'/' -f1)
    fi
fi

echo "========================================================================="
echo "       DARKWATCH CONTROLLED ONION ENDPOINT REACHABILITY CHECK"
echo "========================================================================="
echo "Target .onion Domain: ${ONION_HOST}"
echo "========================================================================="

PYTHON_BIN="python3"
if [ -f "${SHARE_DIR}/.venv/bin/python3" ]; then
    PYTHON_BIN="${SHARE_DIR}/.venv/bin/python3"
fi

export ONION_HOST

"${PYTHON_BIN}" -c '
import os, sys, requests

onion_host = os.environ.get("ONION_HOST", "shadowboard.lab.onion")
base_url = f"http://{onion_host}"

gw_ip = os.environ.get("WHONIX_GATEWAY_IP", "10.152.152.10")
gw_port = os.environ.get("WHONIX_SOCKS_PORT", "9050")

proxies_whonix = {
    "http": f"socks5h://{gw_ip}:{gw_port}",
    "https": f"socks5h://{gw_ip}:{gw_port}"
}
proxies_local = {
    "http": f"socks5h://127.0.0.1:{gw_port}",
    "https": f"socks5h://127.0.0.1:{gw_port}"
}

# Determine working proxy
active_proxies = None
for px in [proxies_whonix, proxies_local, None]:
    try:
        r = requests.get(f"{base_url}/forum", proxies=px, timeout=5)
        if r.status_code == 200:
            active_proxies = px
            break
    except Exception:
        continue

endpoints = [
    ("/forum", 200, "Accessible Forum Discussions"),
    ("/market", 200, "Accessible Cryptomarket Baseline"),
    ("/paste", 200, "Accessible Code/Paste Leak PoC"),
    ("/leak", 200, "Accessible Ransomware Disclosures"),
    ("/barrier", 503, "DDoS CAPTCHA Barrier (Expected Blocked Status)"),
    ("/session_gated", 401, "Session Token Required (Expected Unauthorized)"),
    ("/dynamic_forum", 200, "Accessible Dynamic Feed"),
    ("/forum_mirror", 200, "Accessible Near-Duplicate Mirror")
]

h_ep, h_st, h_res, h_notes = "ENDPOINT", "STATUS", "RESULT", "NOTES"
print(f"  {h_ep:<18} | {h_st:<12} | {h_res:<12} | {h_notes}")
print("  " + "-" * 72)

for ep, expected_code, note in endpoints:
    url = base_url + ep
    actual_code = 0
    try:
        r = requests.get(url, proxies=active_proxies, timeout=5)
        actual_code = r.status_code
    except requests.exceptions.HTTPError as e:
        actual_code = e.response.status_code if e.response else 0
    except Exception:
        actual_code = 0

    if actual_code == expected_code:
        res_str = "OK (PASS)"
    else:
        res_str = f"CODE {actual_code}"

    print(f"  {ep:<18} | HTTP {actual_code:<6} | {res_str:<12} | {note}")
'

echo "========================================================================="
echo "[+] Endpoint Check Completed."
echo "========================================================================="
