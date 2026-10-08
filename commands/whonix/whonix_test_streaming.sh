#!/usr/bin/env bash
# ==============================================================================
# DarkWatch Collector Streaming vs Unstreamed Request Diagnostic
# ==============================================================================
# Tests whether requests.get(..., stream=True) times out or fails compared
# to an unstreamed requests.get(...) request over Whonix SOCKS5 proxy.
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

PYTHON_BIN="python3"
if [ -f "${SHARE_DIR}/.venv/bin/python3" ]; then
    PYTHON_BIN="${SHARE_DIR}/.venv/bin/python3"
fi

export ONION_HOST

"${PYTHON_BIN}" -c '
import os, time, socket, requests

onion_host = os.environ.get("ONION_HOST", "shadowboard.lab.onion")
target_url = f"http://{onion_host}/forum"

gw_ip = os.environ.get("WHONIX_GATEWAY_IP", "10.152.152.10")
gw_port = os.environ.get("WHONIX_SOCKS_PORT", "9050")

# Default Whonix Gateway SOCKS5 proxy
socks_proxy = f"socks5h://{gw_ip}:{gw_port}"

# Fallback to local 127.0.0.1:9050 if 10.152.152.10 socket unavailable
try:
    s = socket.socket()
    s.settimeout(2)
    s.connect((gw_ip, int(gw_port)))
    s.close()
except Exception:
    socks_proxy = f"socks5h://127.0.0.1:{gw_port}"

proxies = {"http": socks_proxy, "https": socks_proxy}
headers = {
    "User-Agent": "DarkWatch-Collector/1.0 (Research/Isolated)",
    "Accept": "text/html,application/xhtml+xml"
}

print("=== DarkWatch Collector Request Diagnostic ===")
print(f"Target URL: {target_url}")
print(f"Proxy:      {socks_proxy}\n")

# [1] Normal / Unstreamed Request
print("[1] Normal request")
t0 = time.time()
try:
    r1 = requests.get(target_url, headers=headers, proxies=proxies, timeout=10)
    dt1 = int((time.time() - t0) * 1000)
    print(f"- HTTP status:    {r1.status_code}")
    print(f"- response bytes: {len(r1.content)} bytes")
    print(f"- response time:  {dt1} ms")
except Exception as e:
    dt1 = int((time.time() - t0) * 1000)
    print(f"- HTTP status:    FAILED")
    print(f"- error type:     {type(e).__name__}")
    print(f"- error message:  {e}")
    print(f"- response time:  {dt1} ms")

print()

# [2] Streamed Request (as used in DarkWatchVerifier)
print("[2] Streamed request")
t0 = time.time()
try:
    r2 = requests.get(target_url, headers=headers, proxies=proxies, timeout=10, stream=True, allow_redirects=True)
    dt2 = int((time.time() - t0) * 1000)
    print(f"- HTTP status:    {r2.status_code}")
    print(f"- headers:        {dict(r2.headers)}")
    print(f"- response time:  {dt2} ms")
except Exception as e:
    dt2 = int((time.time() - t0) * 1000)
    print(f"- HTTP status:    FAILED")
    print(f"- error type:     {type(e).__name__}")
    print(f"- error message:  {e}")
    print(f"- response time:  {dt2} ms")

print("\n=== Diagnostic Complete ===")
'
