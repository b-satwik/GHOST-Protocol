#!/usr/bin/env python3
"""
🛡️ GHOST PROTOCOL — DISTILBERT VALIDATION MATRIX TEST SUITE
Runs controlled synthetic lab observation records through the real frozen DistilBERT model.
Outputs validation matrix evaluating:
scenario_id | expected_category | actual_distilbert_prediction | confidence | top_3_predictions | pass/fail
"""

import os
import sys
import json
import unittest

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.pipeline.inference_engine import InferenceEngine


class TestDistilBertValidationMatrix(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = InferenceEngine()

    def test_distilbert_validation_matrix(self):
        lab_dataset = [
            {
                "scenario_id": "LAB_SCENARIO_01_NORMAL",
                "expected_category": "NORMAL",
                "text": "Welcome to our general site discussion board. Please check our site updates and community rules. Have a great day everyone!",
                "source": "http://127.0.0.1:8080/general"
            },
            {
                "scenario_id": "LAB_SCENARIO_02_RCE",
                "expected_category": "rce",
                "text": "Unauthenticated remote code execution zero-day exploit payload targeting unpatched web application server allowing system command execution.",
                "source": "http://127.0.0.1:8080/security"
            },
            {
                "scenario_id": "LAB_SCENARIO_03_XSS",
                "expected_category": "xss",
                "text": "Reflected cross-site scripting flaw in query parameter allows arbitrary JavaScript execution in user browser context.",
                "source": "http://127.0.0.1:8080/forum"
            },
            {
                "scenario_id": "LAB_SCENARIO_04_INJECTION",
                "expected_category": "injection",
                "text": "SQL injection vulnerability in search parameter allows dumping database contents using UNION SELECT queries.",
                "source": "http://127.0.0.1:8080/paste"
            },
            {
                "scenario_id": "LAB_SCENARIO_05_AUTH_ACCESS",
                "expected_category": "auth_access",
                "text": "Default credentials and broken access control on administrative management interface allow unauthorized session takeover.",
                "source": "http://127.0.0.1:8080/market"
            },
            {
                "scenario_id": "LAB_SCENARIO_06_FILE_INCLUSION",
                "expected_category": "file_inclusion",
                "text": "Local file inclusion vulnerability via directory traversal parameter allows reading arbitrary system configuration files.",
                "source": "http://127.0.0.1:8080/forum"
            },
            {
                "scenario_id": "LAB_SCENARIO_07_INFO_DISCLOSURE",
                "expected_category": "info_disclosure",
                "text": "Exposed backup directory containing unencrypted database dump files and administrative credential files.",
                "source": "http://127.0.0.1:8080/leak"
            },
            {
                "scenario_id": "LAB_SCENARIO_08_DOS",
                "expected_category": "dos",
                "text": "Recursive parsing loop and high memory usage cause server hang and denial of service crash.",
                "source": "http://127.0.0.1:8080/forum"
            },
            {
                "scenario_id": "LAB_SCENARIO_09_MEMORY_CORRUPTION",
                "expected_category": "memory_corruption",
                "text": "Heap memory buffer overflow vulnerability in binary parser allows register overwrite and memory corruption.",
                "source": "http://127.0.0.1:8080/forum"
            }
        ]

        print("\n" + "=" * 110)
        print(" 🛡️ GHOST PROTOCOL — DISTILBERT VALIDATION MATRIX (REAL FROZEN MODEL INFERENCE)")
        print("=" * 110)
        header = f"{'Scenario ID':<25} | {'Expected':<16} | {'Actual Prediction':<18} | {'Confidence':<10} | {'Status':<6} | {'Top-3 Predictions'}"
        print(header)
        print("-" * 110)

        passed_count = 0
        total_count = len(lab_dataset)

        for item in lab_dataset:
            scenario_id = item["scenario_id"]
            expected = item["expected_category"]
            text = item["text"]

            pred_res = self.engine._predict_text(text)
            actual_pred = pred_res.get("predicted_class")
            conf = pred_res.get("confidence", 0.0)
            class_probs = pred_res.get("class_probabilities", {})

            # Format top 3
            top_3 = sorted(class_probs.items(), key=lambda x: x[1], reverse=True)[:3]

            is_match = (actual_pred == expected)
            status_str = "PASS" if is_match else "MISMATCH"
            if is_match:
                passed_count += 1

            top_3_str = ", ".join([f"{k}:{v:.3f}" for k, v in top_3])
            print(f"{scenario_id:<25} | {expected:<16} | {actual_pred:<18} | {conf:<10.4f} | {status_str:<6} | {top_3_str}")

            # Verify structure completeness
            self.assertIn("predicted_class", pred_res)
            self.assertIn("confidence", pred_res)

        print("-" * 110)
        print(f"VALIDATION MATRIX SUMMARY: {passed_count}/{total_count} Passed")
        print("=" * 110 + "\n")


if __name__ == "__main__":
    unittest.main()
