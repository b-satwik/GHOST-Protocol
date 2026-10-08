"""
Threat Filter Gate for DarkWatch GHOST PROTOCOL.
Acts as a first-stage decision gate before ML classification:
1. Filters out ordinary, non-threat community/general discussion (classified as ROUTINE_CONTENT / NORMAL).
2. Routes threat-relevant cybersecurity content to the frozen DistilBERT model for exploit classification.
Enforces contextual pattern matching (does NOT flag isolated 'database' or 'server' without breach context).
"""

import sys
import os
from typing import Dict, Any

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.filter.threat_filter import ThreatFilter as ContextualThreatFilter


class ThreatFilter:
    """
    Context-aware first-stage decision gate.
    """

    def __init__(self):
        self.context_filter = ContextualThreatFilter()

    def evaluate(self, text: str) -> Dict[str, Any]:
        """
        Evaluates input text and returns threat filter decision dictionary.
        """
        res = self.context_filter.filter_and_categorize(text)
        return {
            "is_threat": res["is_threat"],
            "decision": res["decision"],
            "category": res["category"],
            "severity": res["severity"],
            "pattern": res["pattern"],
            "reason": res["rationale"],
            "matched_keywords": [res["matched_text"]] if res["matched_text"] else []
        }
