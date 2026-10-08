#!/usr/bin/env bash
# DarkWatch Real Corpus Collection Shell Script (Whonix Workstation Subdirectory Runner)
# Delegates execution to top-level run_real_corpus_batch.sh.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$SHARE_ROOT"
bash run_real_corpus_batch.sh
