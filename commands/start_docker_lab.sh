#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}/darkwatch_labs"

if docker compose version >/dev/null 2>&1; then
    docker compose up -d
else
    docker-compose up -d
fi

echo "[+] DarkWatch Controlled Docker Lab Started."
docker ps --filter "name=darkwatch"
echo ""

"${REPO_ROOT}/commands/lab/show_onion_addresses.sh"
