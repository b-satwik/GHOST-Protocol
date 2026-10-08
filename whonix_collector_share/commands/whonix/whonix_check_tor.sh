#!/usr/bin/env bash
# ==============================================================================
# Whonix SOCKS5 Proxy Connectivity Check Script
# ==============================================================================
# Verifies that Whonix Workstation can reach the Whonix Gateway SOCKS5 proxy
# at socks5h://10.152.152.10:9050.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GW_IP="${WHONIX_GATEWAY_IP:-10.152.152.10}"
GW_PORT="${WHONIX_SOCKS_PORT:-9050}"
PROXY_URL="socks5h://${GW_IP}:${GW_PORT}"

echo "========================================================================="
echo "        WHONIX GATEWAY SOCKS5 CONNECTIVITY CHECK"
echo "========================================================================="
echo "Target SOCKS5 Proxy: ${PROXY_URL}"
echo "========================================================================="

PYTHON_BIN="python3"
if [ -f "${SHARE_DIR}/.venv/bin/python3" ]; then
    PYTHON_BIN="${SHARE_DIR}/.venv/bin/python3"
fi

"${PYTHON_BIN}" -c '
import socket, sys, os

gw_ip = os.environ.get("WHONIX_GATEWAY_IP", "10.152.152.10")
gw_port = int(os.environ.get("WHONIX_SOCKS_PORT", "9050"))

# Check local/host proxy port 9050 as fallback if gateway IP unreachable
try_ips = [gw_ip, "127.0.0.1"]
success = False

for ip in try_ips:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, gw_port))
        s.close()
        print(f"[+] Whonix SOCKS5 Proxy reachability confirmed at {ip}:{gw_port}")
        success = True
        break
    except Exception as e:
        continue

if not success:
    print(f"[!] Warning: Could not open direct TCP socket to {gw_ip}:{gw_port} or 127.0.0.1:{gw_port}")
    print("    Ensure Whonix Gateway is running and SOCKS5 proxy port 9050 is open.")
    sys.exit(1)
'

echo "========================================================================="
echo "[+] Tor SOCKS5 Check Complete."
echo "Next Recommended Command:"
echo "  ./commands/whonix/whonix_check_darkwatch.sh"
echo "========================================================================="
