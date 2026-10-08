import sys
import os

sys.path.insert(0, os.path.abspath("."))

try:
    from src.stage1_dashboard import app
    print("SUCCESS: src.stage1_dashboard imported without any IndentationError or SyntaxError!")
except Exception as e:
    print(f"ERROR importing stage1_dashboard: {e}")
