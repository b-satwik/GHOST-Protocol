"""
CLI Launcher for Stage 1 Continuous Observer Live Daemon.
Starts the real-time background observation loop across all active registered sources.
"""

import sys
import os

repo_root = os.path.dirname(os.path.abspath(__file__))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.stage1_continuous_observer import Stage1ContinuousObserver

if __name__ == "__main__":
    print("=" * 75)
    print("🛡️ DarkWatch GHOST PROTOCOL — Stage 1 Continuous Live Observer Daemon")
    print("Executing periodic scheduled observations across registered CTI sources...")
    print("Press Ctrl+C to stop the daemon worker.")
    print("=" * 75)

    observer = Stage1ContinuousObserver()
    observer.start_live_daemon(poll_interval_seconds=10)
