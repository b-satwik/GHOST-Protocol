import sys
import os

# Import from root pilot_runner without circular import
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import pilot_runner as root_pilot

run_gold_dataset_pilot = root_pilot.run_gold_dataset_pilot

__all__ = ["run_gold_dataset_pilot"]

