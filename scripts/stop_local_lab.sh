#!/usr/bin/env bash
# DarkWatch Local Test Lab Shutdown Script (Revised Architecture)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${REPO_ROOT}/logs/local_lab"

echo "========================================================================="
echo "Stopping DarkWatch Local Test Lab Services..."
echo "========================================================================="

PID_FILE="${LOG_DIR}/local_lab_master.pid"
if [ -f "${PID_FILE}" ]; then
    PID=$(cat "${PID_FILE}")
    if kill -0 "${PID}" 2>/dev/null; then
        echo "[+] Killing Master Process PID ${PID}..."
        kill -9 "${PID}" 2>/dev/null || true
    fi
    rm -f "${PID_FILE}"
fi

# Clean up any processes bound to ports 8001..8005
for port in 8001 8002 8003 8004 8005; do
    fuser -k -9 "${port}/tcp" 2>/dev/null || true
done

echo "[+] All Local Lab services stopped."
