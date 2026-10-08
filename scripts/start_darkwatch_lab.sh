#!/usr/bin/env bash
# ==============================================================================
# DarkWatch Controlled Docker Laboratory Startup Script
# ==============================================================================
# Starts the self-contained ShadowBoard web app container and Tor hidden-service router,
# waits for Tor v3 hidden service hostname generation, and prints lab details.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "========================================================================="
echo "       DarkWatch Controlled Docker Laboratory Startup"
echo "========================================================================="
echo "Project Root:         ${REPO_ROOT}"
echo "Docker Compose File:  ${REPO_ROOT}/darkwatch_labs/docker-compose.yml"
echo "Shared Folder Path:   ${REPO_ROOT}/whonix_collector_share"
echo "========================================================================="

# 1. Check Docker Installation & Daemon Status
if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] Docker CLI is not installed or not in PATH."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "[ERROR] Docker daemon is not running or current user lacks docker permissions."
    echo "        Try running: sudo systemctl start docker"
    exit 1
fi

# 2. Determine Docker Compose Command Syntax
COMPOSE_CMD=""
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "[ERROR] Neither 'docker compose' nor 'docker-compose' is available."
    exit 1
fi

echo "[+] Starting DarkWatch Controlled Docker Lab containers..."
(cd "${REPO_ROOT}/darkwatch_labs" && ${COMPOSE_CMD} up -d)

# 3. Wait for Containers to reach Running State
echo "[+] Waiting for containers to initialize..."
MAX_ATTEMPTS=20
ATTEMPT=0
SERVICES_RUNNING=false

while [ ${ATTEMPT} -lt ${MAX_ATTEMPTS} ]; do
    ATTEMPT=$((ATTEMPT + 1))
    STATUS_SVCS=$(docker inspect -f '{{.State.Running}}' darkwatch-services 2>/dev/null || echo "false")
    STATUS_TOR=$(docker inspect -f '{{.State.Running}}' darkwatch-tor-router 2>/dev/null || echo "false")

    if [ "${STATUS_SVCS}" = "true" ] && [ "${STATUS_TOR}" = "true" ]; then
        SERVICES_RUNNING=true
        break
    fi
    sleep 1
done

if [ "${SERVICES_RUNNING}" != "true" ]; then
    echo "[ERROR] Lab containers failed to start cleanly within timeout."
    docker ps -a --filter "name=darkwatch"
    exit 1
fi

# 4. Wait for Tor hidden service hostname generation
echo "[+] Waiting for Tor v3 hidden service hostname generation..."
TOR_ATTEMPTS=0
ONION_ADDR=""

while [ ${TOR_ATTEMPTS} -lt 30 ]; do
    TOR_ATTEMPTS=$((TOR_ATTEMPTS + 1))
    if docker exec darkwatch-tor-router test -f /var/lib/tor/shadowboard/hostname 2>/dev/null; then
        ONION_ADDR=$(docker exec darkwatch-tor-router cat /var/lib/tor/shadowboard/hostname 2>/dev/null | tr -d '\r\n')
    elif docker exec darkwatch-tor-router test -f /var/lib/tor/services/hs_shadowboard/hostname 2>/dev/null; then
        ONION_ADDR=$(docker exec darkwatch-tor-router cat /var/lib/tor/services/hs_shadowboard/hostname 2>/dev/null | tr -d '\r\n')
    fi

    if [ -n "${ONION_ADDR}" ]; then
        break
    fi
    sleep 1
done

if [ -z "${ONION_ADDR}" ] && [ -f "${REPO_ROOT}/darkwatch_labs/hs_data/shadowboard/hostname" ]; then
    ONION_ADDR=$(cat "${REPO_ROOT}/darkwatch_labs/hs_data/shadowboard/hostname" 2>/dev/null | tr -d '\r\n' || true)
fi

# 5. Display Environment & Architecture Summary
echo ""
echo "========================================"
echo "SHADOWBOARD LAB READY"
echo "========================================"
echo ""
echo "Local:"
echo "http://127.0.0.1:8080"
echo ""
echo "Tor:"
if [ -n "${ONION_ADDR}" ]; then
    echo "http://${ONION_ADDR}/"
else
    echo "http://[Tor initializing / hostname pending generation]/"
fi
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
echo ""
