#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}/darkwatch_labs"

if docker compose version >/dev/null 2>&1; then
    docker compose down
else
    docker-compose down
fi

echo "[+] DarkWatch Controlled Docker Lab Stopped."
