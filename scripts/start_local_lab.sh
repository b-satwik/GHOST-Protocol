#!/usr/bin/env bash
# DarkWatch Local Test Lab Startup Script (Revised Architecture)
# Launches 5 controlled services on ports 8001-8005 in a detached daemon process.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LOG_DIR="${REPO_ROOT}/logs/local_lab"
mkdir -p "${LOG_DIR}"

PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
if [ ! -f "${PYTHON_BIN}" ]; then
    PYTHON_BIN="python3"
fi

PID_FILE="${LOG_DIR}/local_lab_master.pid"
LOG_FILE="${LOG_DIR}/local_lab_master.log"

echo "========================================================================="
echo "DarkWatch Local 5-Service Lab Startup"
echo "========================================================================="
echo "Repo Root: ${REPO_ROOT}"
echo "Python Executable: ${PYTHON_BIN}"
echo "Logs Directory: ${LOG_DIR}"
echo ""

if [ -f "${PID_FILE}" ] && kill -0 $(cat "${PID_FILE}") 2>/dev/null; then
    echo "[!] DarkWatch Local Lab is already running (Master PID: $(cat "${PID_FILE}"))."
else
    echo "[+] Launching DarkWatch Local Lab Master Daemon (Ports 8001-8005)..."
    "${PYTHON_BIN}" -c "
import subprocess, sys, os

log_fd = open('${LOG_FILE}', 'a')
p = subprocess.Popen([sys.executable, '${REPO_ROOT}/services/local_lab/run_all.py'], stdout=log_fd, stderr=log_fd, start_new_session=True)
with open('${PID_FILE}', 'w') as f:
    f.write(str(p.pid))
print('    Master Daemon PID:', p.pid)
"
fi

sleep 4

echo ""
echo "========================================================================="
echo "Local Lab Startup Completed Successfully!"
echo "========================================================================="
echo "Service A (Port 8001 - Direct): http://127.0.0.1:8001"
echo "Service B (Port 8002 - Tor):    http://127.0.0.1:8002"
echo "Service C (Port 8003 - VPN):    http://127.0.0.1:8003"
echo "Service D (Port 8004 - 2FA):    http://127.0.0.1:8004"
echo "Service E (Port 8005 - No2FA):  http://127.0.0.1:8005"
echo "========================================================================="
