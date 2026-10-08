"""
CLI Launcher for Stage 1 Analyst Test Dashboard.
Starts local Flask server on http://127.0.0.1:5000.
"""

import sys
import os

# Add repository root to python path
repo_root = os.path.dirname(os.path.abspath(__file__))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.stage1_dashboard import app

if __name__ == "__main__":
    print("=" * 70)
    print("🛡️ DarkWatch GHOST PROTOCOL — Stage 1 Analyst Dashboard Server")
    print("Local URL: http://127.0.0.1:5000")
    print("Synthetic Test Feed: http://127.0.0.1:5000/synthetic_test_feed")
    print("Press Ctrl+C to stop the server.")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=False)
