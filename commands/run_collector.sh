#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

PYTHON_EXEC="${REPO_ROOT}/.venv/bin/python3"
if [ ! -f "${PYTHON_EXEC}" ]; then
    PYTHON_EXEC="python3"
fi

echo "[+] Executing DarkWatch Collector against Local Lab..."
"${PYTHON_EXEC}" -c '
from src.collector.local_lab_adapter import LocalLabAdapter
res = LocalLabAdapter.process_message(post_id=1)
print(res)
'
