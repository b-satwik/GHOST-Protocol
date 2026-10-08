#!/usr/bin/env bash
# ==============================================================================
# Whonix Workstation Startup & Checklist Script
# ==============================================================================
# Run inside Whonix-Workstation to inspect proxy routing and onion lab info.
# NOTE: Docker runs on the HOST machine. Do NOT run Docker inside Whonix.
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
echo "           WHONIX WORKSTATION RESEARCH COLLECTOR CHECKLIST"
echo "========================================================================="
echo "1. Workstation Network: Available"
echo "2. Gateway SOCKS5 Proxy: socks5h://10.152.152.10:9050"
echo "3. Target .onion Host:  ${ONION_HOST}"
echo "4. Target Forum URL:    http://${ONION_HOST}/forum"
echo "========================================================================="
echo ""
echo "Access Boundaries:"
echo "  • /barrier       -> Expected 503 DDoS CAPTCHA Barrier (No Bypass)"
echo "  • /session_gated -> Expected 401 Unauthorized (No Bypass)"
echo ""
echo "Next Recommended Command:"
echo "  ./commands/whonix/whonix_check_tor.sh"
echo "========================================================================="
