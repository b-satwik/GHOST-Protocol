import unittest
import os
import sys

# Ensure repository root is in sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.pipeline.lab_bridge import DarkWatchLabBridge


class TestDarkWatchLabBridgeIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Initialize lab bridge targeting the running Docker laboratory environment."""
        cls.bridge = DarkWatchLabBridge(base_url="http://127.0.0.1:8080")

    def test_model_verification(self):
        """Verify that HackerSignal DistilBERT final_model is loaded instead of old text models."""
        text_model_dir = getattr(self.bridge.engine, "text_model_dir", "")
        self.assertTrue(
            "distilbert_hackersignal" in text_model_dir and "final_model" in text_model_dir,
            f"Expected HackerSignal final_model, got: {text_model_dir}"
        )
        self.assertNotIn("dwdata_text_model", text_model_dir)

    def test_1_controlled_forum_observation(self):
        """
        TEST 1:
        Controlled forum observation (/forum)
        -> sanitize
        -> feature preparation
        -> ML inference
        -> HM-TIF result
        """
        result = self.bridge.observe_endpoint("/forum")

        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["sanitized_text_status"], "CONTENT_ACCESSIBLE")
        self.assertTrue(result["text_length"] > 0)
        self.assertTrue(len(result["sanitized_text"]) > 0)

        # Modality availability
        modalities = result["modality_availability"]
        self.assertTrue(modalities["text"], "Text modality should be available for /forum")

        # ML Inference predictions
        text_pred = result["text_prediction"]
        self.assertIn("predicted_class", text_pred)
        self.assertNotEqual(text_pred["predicted_class"], "MISSING_TEXT_MODALITY")
        self.assertTrue(0.0 <= text_pred["confidence"] <= 1.0)

        # HM-TIF Fusion Score
        fusion_score = result["fusion_score"]
        self.assertTrue(0.0 <= fusion_score <= 1.0, f"Invalid fusion score: {fusion_score}")

    def test_2_barrier_and_session_gated_endpoints(self):
        """
        TEST 2:
        Barrier/session-gated endpoint
        -> verify that blocked/unavailable text is handled through the existing missing-modality logic
        -> do NOT bypass the barrier
        """
        # 2a. Barrier endpoint (HTTP 503 CAPTCHA challenge)
        barrier_res = self.bridge.observe_endpoint("/barrier")
        self.assertEqual(barrier_res["http_status"], 503)
        self.assertEqual(barrier_res["sanitized_text_status"], "AUTOMATED_ACCESS_BLOCKED")
        self.assertEqual(barrier_res["sanitized_text"], "")
        self.assertFalse(barrier_res["modality_availability"]["text"])
        self.assertEqual(barrier_res["text_prediction"]["predicted_class"], "MISSING_TEXT_MODALITY")
        self.assertTrue(0.0 <= barrier_res["fusion_score"] <= 1.0)

        # 2b. Session-gated endpoint without credentials (HTTP 401 Unauthorized)
        unauth_res = self.bridge.observe_endpoint("/session_gated")
        self.assertEqual(unauth_res["http_status"], 401)
        self.assertEqual(unauth_res["sanitized_text_status"], "SESSION_GATED_ACCESS")
        self.assertEqual(unauth_res["sanitized_text"], "")
        self.assertFalse(unauth_res["modality_availability"]["text"])
        self.assertEqual(unauth_res["text_prediction"]["predicted_class"], "MISSING_TEXT_MODALITY")

        # 2c. Session-gated endpoint WITH valid lab credentials (HTTP 200 Authorized)
        auth_res = self.bridge.observe_endpoint("/session_gated", session_token="valid_lab_session")
        self.assertEqual(auth_res["http_status"], 200)
        self.assertEqual(auth_res["sanitized_text_status"], "CONTENT_ACCESSIBLE")
        self.assertTrue(auth_res["modality_availability"]["text"])
        self.assertNotEqual(auth_res["text_prediction"]["predicted_class"], "MISSING_TEXT_MODALITY")

    def test_3_dynamic_endpoint(self):
        """
        TEST 3:
        Dynamic endpoint (/dynamic_forum)
        -> observation reaches the pipeline with temporal/session information when available
        """
        temporal_features = {
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

        result = self.bridge.observe_endpoint(
            "/dynamic_forum",
            temporal_telemetry=temporal_features
        )

        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["sanitized_text_status"], "CONTENT_ACCESSIBLE")
        self.assertTrue(result["modality_availability"]["temporal"], "Temporal modality should be active")
        self.assertTrue(result["temporal_result"]["temporal_available"])
        self.assertTrue(0.0 <= result["temporal_result"]["anomaly_score"] <= 1.0)
        self.assertTrue(0.0 <= result["fusion_score"] <= 1.0)

    def test_4_near_duplicate_endpoint(self):
        """
        TEST 4:
        Near-duplicate endpoint (/forum_mirror)
        -> existing MinHash/deduplication logic is invoked correctly
        """
        # First observe canonical /forum to build index
        self.bridge.observe_endpoint("/forum")

        # Then observe /forum_mirror which has near-identical content
        mirror_res = self.bridge.observe_endpoint("/forum_mirror")

        self.assertEqual(mirror_res["http_status"], 200)
        self.assertTrue(mirror_res["deduplication"]["is_duplicate"], "Near-duplicate mirror should be detected")
        self.assertIn(mirror_res["sanitized_text_status"], ("NEAR_DUPLICATE_MIRROR", "EXACT_DUPLICATE"))
        self.assertIsNotNone(mirror_res["deduplication"]["duplicate_of"])

    def test_5_cti_lookup_and_mitre_mapping(self):
        """
        TEST 5:
        CTI Lookup + MITRE ATT&CK Mapping
        -> verify that /forum endpoint observation extracts CTI indicators,
           performs local exact CTI store lookup, maps to MITRE ATT&CK techniques,
           and attaches enrichment metadata.
        """
        res = self.bridge.observe_endpoint("/forum")

        # 1. CTI indicators & lookup
        self.assertIn("cti", res)
        self.assertIn("cti_lookup", res["cti"])
        self.assertGreater(res["cti"]["extracted_indicators_count"], 0)

        # 2. MITRE ATT&CK Mapping & Enrichment
        self.assertIn("mitre_mapping", res)
        mitre_info = res["mitre_mapping"]
        self.assertGreater(mitre_info["mapped_techniques_count"], 0)
        self.assertIn("techniques", mitre_info)
        
        tech = mitre_info["techniques"][0]
        self.assertIn("technique_id", tech)
        self.assertIn("technique_name", tech)
        self.assertIn("darkwatch_mapping", tech)
        self.assertIn("confidence", tech["darkwatch_mapping"])
        self.assertIn("matched_evidence", tech["darkwatch_mapping"])

        # 3. STIX 2.1 Bundle Object Types
        self.assertIn("stix", res)
        stix_types = res["stix"]["stix_object_types"]
        self.assertIn("attack-pattern", stix_types)
        self.assertIn("vulnerability", stix_types)

    def test_6_two_tier_xai_integration(self):
        """
        TEST 6:
        Two-Tier XAI Integration
        -> verify that observation payload contains two-tier XAI output:
           Tier 1 (text token highlights & narrative) and Tier 2 (feature attributions).
        """
        res = self.bridge.observe_endpoint("/forum")

        self.assertIn("xai", res)
        xai = res["xai"]

        self.assertTrue(xai["xai_available"])
        self.assertIn(xai["explanation_mode"], ("DEEP_EXPLANATION", "LIGHTWEIGHT"))
        self.assertIn("summary_narrative", xai)
        self.assertIn("text_token_highlights", xai)
        self.assertGreater(len(xai["text_token_highlights"]), 0)
        self.assertIn("behavioral_feature_attributions", xai)
        self.assertIn("temporal_feature_attributions", xai)
        self.assertIn("modalities_explained", xai)


if __name__ == "__main__":
    unittest.main()


