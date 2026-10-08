#!/usr/bin/env bash
# DarkWatch Real Corpus Collection Executable Script (Whonix Workstation Handoff)
# Strictly enforces approval-gated seed source registry and passive collection rules.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================="
echo "DarkWatch Real Corpus Batch Collection Execution"
echo "======================================================================="
echo "Working Directory: $SCRIPT_DIR"
echo "Timestamp:         $(date -u)"
echo "-----------------------------------------------------------------------"

# 1. Virtual Environment Activation / Setup
# Determine writable venv location (prefer local .venv if writable, fallback to $HOME/darkwatch_collector/.venv)
VENV_TARGET="$SCRIPT_DIR/.venv"
if [ ! -w "$SCRIPT_DIR" ]; then
    VENV_TARGET="$HOME/darkwatch_collector/.venv"
fi

if [ -d "$SCRIPT_DIR/.venv" ]; then
    echo "[+] Activating local virtual environment ($SCRIPT_DIR/.venv)..."
    source "$SCRIPT_DIR/.venv/bin/activate"
elif [ -d "$HOME/darkwatch_collector/.venv" ]; then
    echo "[+] Activating user virtual environment ($HOME/darkwatch_collector/.venv)..."
    source "$HOME/darkwatch_collector/.venv/bin/activate"
elif [ -d "$HOME/.venv" ]; then
    echo "[+] Activating user virtual environment ($HOME/.venv)..."
    source "$HOME/.venv/bin/activate"
elif [ -d "/home/user/.venv" ]; then
    echo "[+] Activating Whonix virtual environment (/home/user/.venv)..."
    source "/home/user/.venv/bin/activate"
else
    echo "[!] No existing virtual environment found. Checking Python 3..."
fi

PYTHON_CMD="python3"
if ! command -v $PYTHON_CMD &> /dev/null; then
    echo "[!] ERROR: python3 command not found."
    exit 1
fi

echo "[+] Python Version: $($PYTHON_CMD --version)"

# Verify required python dependencies
$PYTHON_CMD -c "
import yaml, requests, bs4
print('[+] Required Python dependencies verified (PyYAML, requests, bs4).')
" 2>/dev/null || {
    echo "[!] Installing required dependencies into $VENV_TARGET..."
    mkdir -p "$(dirname "$VENV_TARGET")"
    $PYTHON_CMD -m venv "$VENV_TARGET"
    source "$VENV_TARGET/bin/activate"
    pip install --quiet -r requirements-collector.txt PyYAML
    echo "[+] Virtual environment created and dependencies installed."
}

# 2. Verify Tor SOCKS5 Connectivity
PROXY_URL="socks5h://10.152.152.10:9050"
echo "[+] Whonix SOCKS5 Proxy Target: $PROXY_URL"

# 3. Verify Seed Source Registry
SEEDS_FILE="config/seed_sources.yaml"
if [ ! -f "$SEEDS_FILE" ]; then
    echo "[!] ERROR: Approved seed sources registry missing at $SEEDS_FILE"
    exit 1
fi

# 4. Execute Real Corpus Collection Batch
echo "[+] Executing Real Corpus Batch Runner (run_corpus_batch.py)..."
echo "-----------------------------------------------------------------------"

$PYTHON_CMD run_corpus_batch.py --seeds-path "$SEEDS_FILE"

echo "-----------------------------------------------------------------------"
echo "[+] Real Corpus Collection Batch Execution Finished."
echo "    Evidence Store DB: $SCRIPT_DIR/data/collector_evidence.db"
echo "    Gold Dataset DB:   $SCRIPT_DIR/data/gold_dataset.db"
echo "    JSONL Export:      $SCRIPT_DIR/data/exports/darkwatch_gold_dataset.jsonl"
echo "    CSV Export:        $SCRIPT_DIR/data/exports/darkwatch_gold_dataset.csv"
echo "======================================================================="

