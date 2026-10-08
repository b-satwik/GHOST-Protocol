#!/usr/bin/env bash
# DarkWatch Local Test Lab Status Checker Script (Revised Architecture)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "========================================================================="
echo "DarkWatch Local Test Lab Status"
echo "========================================================================="
printf "%-25s %-8s %-15s %-22s %-15s\n" "SERVICE NAME" "PORT" "NETWORK PATH" "AUTH METHOD" "STATUS"
echo "-------------------------------------------------------------------------"

services=(
    "8001:Service A (Direct Chat):DIRECT:PASSWORD_ONLY"
    "8002:Service B (Tor Chat):TOR:PASSWORD_ONLY"
    "8003:Service C (VPN Chat):VPN:PASSWORD_ONLY"
    "8004:Service D (2FA Chat):DIRECT:PASSWORD_PLUS_2FA"
    "8005:Service E (No-2FA Chat):DIRECT:PASSWORD_ONLY"
)

for item in "${services[@]}"; do
    IFS=":" read -r port name net auth <<< "${item}"
    status="OFFLINE"

    if curl -s -m 1 "http://127.0.0.1:${port}/health" >/dev/null 2>&1 || curl -s -m 1 "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
        status="ONLINE (HTTP 200/403 Gatekeeper)"
    fi

    printf "%-25s %-8s %-15s %-22s %-15s\n" "${name}" "${port}" "${net}" "${auth}" "${status}"
done

echo "========================================================================="
