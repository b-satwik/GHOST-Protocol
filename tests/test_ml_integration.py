import unittest
import os
import sys
import torch
import numpy as np

# Ensure darkwatch repository root is in sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.pipeline.inference_engine import InferenceEngine


class TestMLPipelineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Initialize the unified InferenceEngine orchestrator."""
        cls.engine = InferenceEngine()

    def test_model_loading(self):
        """Verify all trained models load successfully."""
        self.assertIsNotNone(self.engine.text_model, "DistilBERT text model failed to load")
        self.assertIsNotNone(self.engine.tokenizer, "Tokenizer failed to load")
        self.assertIsNotNone(self.engine.tab_model, "Tabular Autoencoder failed to load")
        self.assertIsNotNone(self.engine.temp_model, "Temporal Autoencoder v2 failed to load")
        self.assertIsNotNone(self.engine.xgb_model, "XGBoost Multiclass Model failed to load")

    def test_model_output_shapes(self):
        """Verify exact tensor and array output shapes for each model."""
        # 1. Text Model Output Shape
        inputs = self.engine.tokenizer("Test threat listing", return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = self.engine.text_model(**inputs)
        self.assertEqual(outputs.logits.shape, (1, 8), f"Expected Text logits shape (1, 8), got {outputs.logits.shape}")

        # 2. Tabular Model Tensor Shape (39 features)
        dummy_tab = torch.zeros((1, 39), dtype=torch.float32)
        with torch.no_grad():
            tab_recon = self.engine.tab_model(dummy_tab)
        self.assertEqual(tab_recon.shape, (1, 39), f"Expected Tabular recon shape (1, 39), got {tab_recon.shape}")

        # 3. Temporal v2 Model Tensor Shape (14 features)
        dummy_temp = torch.zeros((1, 14), dtype=torch.float32)
        with torch.no_grad():
            temp_recon = self.engine.temp_model(dummy_temp)
            temp_latent = self.engine.temp_model.encoder(dummy_temp)
        self.assertEqual(temp_recon.shape, (1, 14), f"Expected Temporal recon shape (1, 14), got {temp_recon.shape}")
        self.assertEqual(temp_latent.shape, (1, 8), f"Expected Temporal latent shape (1, 8), got {temp_latent.shape}")

        # 4. XGBoost Network Model Prediction Shape (79 features)
        if self.engine.xgb_features:
            import pandas as pd
            dummy_net_df = pd.DataFrame(np.zeros((1, 79)), columns=self.engine.xgb_features)
            probs = self.engine.xgb_model.predict_proba(dummy_net_df)
            self.assertEqual(probs.shape, (1, 4), f"Expected XGBoost probs shape (1, 4), got {probs.shape}")

    def test_full_multimodal_prediction(self):
        """Test full multi-modal record prediction (Text + Tabular + Temporal + Network)."""
        record = {
            "text": "Selling 100x Credit Card CVVs with PIN and RDP admin credentials",
            "snapshot_year": 2024,
            "snapshot_month": 10,
            "snapshot_quarter": 4,
            "snapshot_day_of_month": 15,
            "snapshot_day_of_week": 2,
            "snapshot_is_weekend": 0,
            "days_since_first_snapshot": 120,
            "vendor_activity_days": 45,
            "vendor_listing_count": 12,
            "marketplace_listing_count": 150,
            "vendor_observation_number": 3,
            "vendor_previous_observation_gap": 7,
            "category_frequency": 500,
            "marketplace_vendor_count": 25
        }
        # Add 39 tabular features
        for f in self.engine.tab_features:
            record[f] = 1.0
            
        # Add 79 XGBoost network features
        for f in self.engine.xgb_features:
            record[f] = 0.5

        result = self.engine.predict(record)
        
        self.assertIn("fusion", result)
        self.assertIn("fusion_score", result["fusion"])
        self.assertTrue(0.0 <= result["fusion"]["fusion_score"] <= 1.0)
        self.assertTrue(result["fusion"]["available_modalities"]["text"])
        self.assertTrue(result["fusion"]["available_modalities"]["behavioral"])
        self.assertTrue(result["fusion"]["available_modalities"]["temporal"])
        self.assertTrue(result["fusion"]["available_modalities"]["network"])

    def test_missing_text_modality_prediction(self):
        """Test prediction when text modality is missing/empty."""
        record = {
            "text": "",
            "snapshot_year": 2024,
            "vendor_activity_days": 30
        }
        for f in self.engine.tab_features:
            record[f] = 0.5
            
        result = self.engine.predict(record)
        
        self.assertIn("fusion", result)
        self.assertFalse(result["fusion"]["available_modalities"]["text"])
        self.assertTrue(result["fusion"]["available_modalities"]["behavioral"])
        self.assertTrue(0.0 <= result["fusion"]["fusion_score"] <= 1.0)
        self.assertEqual(result["text_model"]["predicted_class"], "MISSING_TEXT_MODALITY")

    def test_text_only_prediction(self):
        """Test prediction on text-only input."""
        result = self.engine.predict("CVE-2024-1234 zero-day exploit for Windows RCE")
        
        self.assertIn("fusion", result)
        self.assertTrue(result["fusion"]["available_modalities"]["text"])
        self.assertFalse(result["fusion"]["available_modalities"]["behavioral"])
        self.assertFalse(result["fusion"]["available_modalities"]["temporal"])
        self.assertTrue(0.0 <= result["fusion"]["fusion_score"] <= 1.0)
        self.assertIn("rce", result["text_model"]["class_probabilities"])


if __name__ == "__main__":
    unittest.main()
