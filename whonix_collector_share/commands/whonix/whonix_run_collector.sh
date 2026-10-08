#!/usr/bin/env bash
# ==============================================================================
# Whonix DarkWatch Collector Runner Script
# ==============================================================================
# Executes Phase 1 telemetry collection & verification over the Whonix SOCKS5 route.
# Uses existing DarkWatchVerifier with use_whonix=True.
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
echo "          WHONIX DARKWATCH COLLECTOR OBSERVATION RUNNER"
echo "========================================================================="
echo "Target .onion Domain: ${ONION_HOST}"
echo "========================================================================="

PYTHON_BIN="python3"
if [ -f "${SHARE_DIR}/.venv/bin/python3" ]; then
    PYTHON_BIN="${SHARE_DIR}/.venv/bin/python3"
fi

export ONION_HOST

"${PYTHON_BIN}" -c '
import os, sys, socket, requests
sys.path.insert(0, "'"${SHARE_DIR}"'")

from src.collector.verifier import DarkWatchVerifier

onion_host = os.environ.get("ONION_HOST", "shadowboard.lab.onion")
target_url = f"http://{onion_host}/forum"

gw_ip = os.environ.get("WHONIX_GATEWAY_IP", "10.152.152.10")
gw_port = os.environ.get("WHONIX_SOCKS_PORT", "9050")

# Check which proxy reaches the Tor service
socks_proxy = f"socks5h://{gw_ip}:{gw_port}"
try:
    s = socket.socket()
    s.settimeout(2)
    s.connect((gw_ip, int(gw_port)))
    s.close()
except Exception:
    socks_proxy = f"socks5h://127.0.0.1:{gw_port}"

print(f"[+] Launching DarkWatchVerifier (proxy={socks_proxy}) against {target_url}...")
verifier = DarkWatchVerifier(socks_proxy=socks_proxy)
res = verifier.verify_onion_source(target_url)

onion_addr = res.get("onion_address")
http_st = res.get("http_status")
st_val = res.get("state")
resp_time = res.get("response_time_ms")
txt_len = res.get("text_length")
hash_val = res.get("sha256")
att_id = res.get("attempt_id")

print("\n=== Collector Evidence Summary ===")
print(f"  • Source URL:        {onion_addr}")
print(f"  • HTTP Status:       {http_st}")
print(f"  • Evaluated State:   {st_val}")
print(f"  • Response Time:     {resp_time} ms")
print(f"  • Text Bytes:        {txt_len} bytes")
print(f"  • SHA-256 Hash:      {hash_val}")
print(f"  • Evidence DB ID:    {att_id}")
print("=========================================================================")
'

echo "[+] Collector Observation Completed Successfully."
