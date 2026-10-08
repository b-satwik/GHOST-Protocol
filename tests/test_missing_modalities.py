#!/usr/bin/env python3
"""
🛡️ GHOST PROTOCOL — MULTI-MODAL MISSING MODALITY HANDLING TEST SUITE
Verifies HM-TIF dynamic weight renormalization across 4 modality configurations:
1. TEXT ONLY
2. TEXT + NETWORK
3. TEXT + TEMPORAL
4. TEXT + NETWORK + TEMPORAL
"""

import os
import sys
import unittest
import numpy as np

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.pipeline.inference_engine import InferenceEngine


class TestMissingModalities(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = InferenceEngine()

    def test_text_only(self):
        input_data = "Remote code execution zero-day exploit payload targeting unpatched web application server."
        res = self.engine.predict(input_data)
        
        avail = res["fusion"]["available_modalities"]
        self.assertTrue(avail["text"])
        self.assertFalse(avail["network"])
        self.assertFalse(avail["temporal"])
        self.assertFalse(avail["behavioral"])

        weights = res["fusion"]["active_weights"]
        self.assertEqual(weights["text"], 1.0)
        self.assertEqual(weights["network"], 0.0)
        self.assertEqual(weights["temporal"], 0.0)
        self.assertEqual(weights["behavioral"], 0.0)

    def test_text_plus_network(self):
        input_data = {
            "text": "SQL injection vulnerability in search parameter allows dumping database contents.",
            "onion_address": "http://test-target.onion"
        }
        # Populate genuine network features from XGBoost schema
        for feat in self.engine.xgb_features:
            input_data[feat] = 0.5

        res = self.engine.predict(input_data)
        avail = res["fusion"]["available_modalities"]
        self.assertTrue(avail["text"])
        self.assertTrue(avail["network"])
        self.assertFalse(avail["temporal"])

        weights = res["fusion"]["active_weights"]
        self.assertGreater(weights["text"], 0.0)
        self.assertGreater(weights["network"], 0.0)
        self.assertEqual(sum(weights.values()), 1.0)

    def test_text_plus_temporal(self):
        input_data = {
            "text": "Exposed backup directory containing unencrypted database dump files.",
            "onion_address": "http://test-target.onion"
        }
        # Populate genuine temporal features from Temporal AE schema
        for feat in self.engine.temp_features:
            input_data[feat] = 1.0

        res = self.engine.predict(input_data)
        avail = res["fusion"]["available_modalities"]
        self.assertTrue(avail["text"])
        self.assertFalse(avail["network"])
        self.assertTrue(avail["temporal"])

        weights = res["fusion"]["active_weights"]
        self.assertGreater(weights["text"], 0.0)
        self.assertGreater(weights["temporal"], 0.0)
        self.assertEqual(sum(weights.values()), 1.0)

    def test_text_plus_network_plus_temporal(self):
        input_data = {
            "text": "Default credentials and broken access control allow unauthorized session takeover.",
            "onion_address": "http://test-target.onion"
        }
        for feat in self.engine.xgb_features:
            input_data[feat] = 0.5
        for feat in self.engine.temp_features:
            input_data[feat] = 1.0

        res = self.engine.predict(input_data)
        avail = res["fusion"]["available_modalities"]
        self.assertTrue(avail["text"])
        self.assertTrue(avail["network"])
        self.assertTrue(avail["temporal"])

        weights = res["fusion"]["active_weights"]
        self.assertGreater(weights["text"], 0.0)
        self.assertGreater(weights["network"], 0.0)
        self.assertGreater(weights["temporal"], 0.0)
        self.assertEqual(sum(weights.values()), 1.0)


if __name__ == "__main__":
    unittest.main()
