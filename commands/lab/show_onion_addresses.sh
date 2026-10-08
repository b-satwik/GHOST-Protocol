#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

get_hostname() {
    local service="$1"
    local addr=""

    if docker ps --filter "name=darkwatch-tor-router" --format "{{.Names}}" | grep -q "darkwatch-tor-router"; then
        addr=$(docker exec darkwatch-tor-router cat "/var/lib/tor/${service}/hostname" 2>/dev/null | tr -d '\r\n' || true)
        if [ -z "${addr}" ]; then
            addr=$(docker exec darkwatch-tor-router cat "/var/lib/tor/services/hs_${service}/hostname" 2>/dev/null | tr -d '\r\n' || true)
        fi
    fi

    if [ -z "${addr}" ] && [ -f "${REPO_ROOT}/darkwatch_labs/hs_data/${service}/hostname" ]; then
        addr=$(cat "${REPO_ROOT}/darkwatch_labs/hs_data/${service}/hostname" 2>/dev/null | tr -d '\r\n' || true)
    fi

    if [ -z "${addr}" ] && [ -f "${REPO_ROOT}/darkwatch_labs/hs_data/hs_${service}/hostname" ]; then
        addr=$(cat "${REPO_ROOT}/darkwatch_labs/hs_data/hs_${service}/hostname" 2>/dev/null | tr -d '\r\n' || true)
    fi

    echo "${addr}"
}

SHADOWBOARD_ONION=$(get_hostname "shadowboard")
SHADOWFORUM_ONION=$(get_hostname "shadowforum")
DREADLAB_ONION=$(get_hostname "dreadlab")
PASTEVAULT_ONION=$(get_hostname "pastevault")
LEAKLOCKER_ONION=$(get_hostname "leaklocker")

echo "========================================"
echo "SHADOWBOARD LAB READY"
echo "========================================"
echo ""
echo "Local:"
echo "http://127.0.0.1:8080"
echo ""
echo "Tor:"
echo "http://${SHADOWBOARD_ONION:-${SHADOWFORUM_ONION}}/"
echo ""
echo "Test accounts:"
echo "user01 / ShadowPass123!"
echo "user02 / ShadowPass123!"
echo "user03 / ShadowPass123!"
echo "user04 / ShadowPass123!"
echo "user05 / ShadowPass123!"
echo "user06 / ShadowPass123!"
echo "user07 / ShadowPass123!"
echo "user08 / ShadowPass123!"
echo "user09 / ShadowPass123!"
echo "user10 / ShadowPass123!"
echo ""
echo "========================================"
