#!/usr/bin/env bash
# ==============================================================================
# DarkWatch Controlled Docker Laboratory Stop Script
# ==============================================================================
# Safely stops and removes lab containers using Docker Compose down.
# Preserves persistent Tor hidden-service data in darkwatch_labs/hs_data/.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "========================================================================="
echo "       DarkWatch Controlled Docker Laboratory Shutdown"
echo "========================================================================="

# Determine Docker Compose Command Syntax
COMPOSE_CMD=""
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "[ERROR] Neither 'docker compose' nor 'docker-compose' is available."
    exit 1
fi

echo "[+] Stopping DarkWatch Controlled Docker Lab containers..."
(cd "${REPO_ROOT}/darkwatch_labs" && ${COMPOSE_CMD} down)

echo "[+] Containers stopped successfully."
echo "[+] Persistent Tor hidden-service data preserved in ${REPO_ROOT}/darkwatch_labs/hs_data/."
echo "========================================================================="
