#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

PYTHON_EXEC="${REPO_ROOT}/.venv/bin/python3"
if [ ! -f "${PYTHON_EXEC}" ]; then
    PYTHON_EXEC="python3"
fi

echo "[+] Executing DarkWatch ML Inference Pipeline over Docker Lab Endpoints..."
"${PYTHON_EXEC}" src/pipeline/lab_bridge.py --all
