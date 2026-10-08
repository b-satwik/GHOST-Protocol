"""
Automated Unit & Integration Test Suite for DarkWatch XAI Pipeline.
Empirically tests:
1. Benign cybersecurity text
2. Malware text
3. Credential/access text
4. CVE/exploit text
5. Unrelated text
6. Actual historical dataset record
7. Text-only mode (behavior_available=False, temporal_available=False)
8. CTI Extraction
9. MITRE mapping (EXPLICIT_EVIDENCE vs WEAK_KEYWORD_ASSOCIATION)
10. Risk score calculation
11. XAI availability
12. End-to-end JSON output schema validation
"""

import sys
import os
import unittest
import json

# Add repository root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.extraction.threat_extractor import ThreatExtractor
from src.cti.mitre_mapper import MITREMapper
from src.risk.risk_engine import RiskEngine
from src.xai.conditional_xai import ConditionalXAIEngine
from src.alerts.alert_generator import AlertGenerator
from src.pipeline.inference_engine import InferenceEngine

class TestDarkWatchPipeline(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.engine = InferenceEngine()
        cls.extractor = ThreatExtractor()
        cls.mapper = MITREMapper()
        cls.risk_engine = RiskEngine()
        cls.xai_engine = ConditionalXAIEngine()

    def test_01_benign_cybersecurity_text(self):
        text = "Detailed cybersecurity tutorial on configuring Linux firewall iptables and SSH keys."
        res = self.engine.predict(text)
        
        self.assertIn("text_model", res)
        self.assertTrue(res["text_model"]["model_artifact"].endswith("model.safetensors"))
        self.assertIn("risk", res)
        self.assertIn(res["risk"]["severity"], ["LOW", "MODERATE", "ELEVATED"])

    def test_02_malware_text(self):
        text = "Selling Loki 2.0 Botnet keylogger source code with stealth persistence module."
        res = self.engine.predict(text)
        
        self.assertTrue(res["text_model"]["model_artifact"].endswith("model.safetensors"))
        self.assertIn("botnet", str(res["cti_entities"]).lower())
        self.assertTrue(len(res["mitre"]) > 0)
        self.assertIn(res["risk"]["severity"], ["ELEVATED", "HIGH"])

    def test_03_credential_access_text(self):
        text = "Fresh batch of 500x corporate RDP access logins and admin password combo lists."
        res = self.engine.predict(text)
        
        self.assertIn("credentials_access", res["cti_entities"])
        self.assertTrue(any(m["mapping_method"] == "EXPLICIT_EVIDENCE" for m in res["mitre"]))

    def test_04_cve_exploit_text(self):
        text = "Zero-day RCE exploit for CVE-2024-30078 affecting Windows Kernel remote code execution."
        res = self.engine.predict(text)
        
        self.assertIn("CVE-2024-30078", res["cti_entities"].get("cves", []))
        cve_mitre = [m for m in res["mitre"] if m["mapping_method"] == "EXPLICIT_EVIDENCE"]
        self.assertTrue(len(cve_mitre) > 0)

    def test_05_unrelated_text(self):
        text = "Organic green tea leaves imported directly from Japan Kyoto gardens."
        res = self.engine.predict(text)
        
        self.assertIn(res["risk"]["severity"], ["LOW", "MODERATE"])
        self.assertEqual(len(res["mitre"]), 0)

    def test_06_historical_dataset_record(self):
        # Record with actual 39 tabular & 14 temporal features
        record = {
            "text": "Selling cracked software license keys",
            "price_value": 49.99,
            "rating": 4.8,
            "vendor_rating": 4.9,
            "reputation": 150.0,
            "sold": 45,
            "in_stock": 10,
            "has_price": 1.0,
            "has_network_indicator": 0.0,
            "text_char_count": 35.0,
            "text_unique_word_count": 5.0,
            "text_avg_word_length": 6.0,
            "text_digit_count": 0.0,
            "text_digit_ratio": 0.0,
            "text_uppercase_count": 0.0,
            "text_uppercase_ratio": 0.0,
            "text_special_char_count": 0.0,
            "text_has_url": 0.0,
            "text_has_ip": 0.0,
            "text_has_crypto_term": 0.0,
            "text_has_malware_term": 0.0,
            "text_has_credential_term": 0.0,
            "text_has_exploit_term": 0.0,
            "category_frequency": 100.0,
            "vendor_listing_count": 12.0,
            "vendor_category_count": 2.0,
            "vendor_marketplace_count": 1.0,
            "vendor_activity_days": 180.0,
            "marketplace_listing_count": 5000.0,
            "marketplace_vendor_count": 300.0,
            "price_log1p": 3.9,
            "price_text_length": 35.0,
            "currency_known": 1.0,
            "is_crypto_currency": 0.0,
            "price_is_zero": 0.0,
            "domain_count": 0.0,
            "ip_count": 0.0,
            "email_count": 0.0,
            "total_indicator_count": 0.0,
            "network_indicator_density": 0.0,
            # Temporal features
            "vendor_observation_number": 5.0,
            "vendor_previous_observation_gap": 3.0
        }
        
        res = self.engine.predict(record)
        
        self.assertTrue(res["behavior_model"]["behavior_available"])
        self.assertTrue(res["temporal_model"]["temporal_available"])
        self.assertIsNotNone(res["behavior_model"]["anomaly_score"])
        self.assertIsNotNone(res["temporal_model"]["anomaly_score"])
        self.assertTrue(res["behavior_model"]["model_artifact"].endswith("model.pt"))
        self.assertTrue(res["temporal_model"]["model_artifact"].endswith(".pt"))
        self.assertEqual(res["fusion"]["available_modalities"]["behavioral"], True)

    def test_07_text_only_mode(self):
        res = self.engine.predict("Simple text prompt without historical tabular features")
        
        self.assertFalse(res["behavior_model"]["behavior_available"])
        self.assertFalse(res["temporal_model"]["temporal_available"])
        self.assertIsNone(res["behavior_model"]["anomaly_score"])
        self.assertIsNone(res["temporal_model"]["anomaly_score"])
        self.assertEqual(res["fusion"]["active_weights"]["text"], 1.0)
        self.assertEqual(res["fusion"]["active_weights"]["behavioral"], 0.0)

    def test_08_cti_extraction(self):
        text = "Contact vendor@onion.tor or 192.168.1.50 with SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = self.engine.predict(text)
        
        self.assertIn("iocs", res["cti_entities"])
        cti = res["cti_entities"]
        self.assertTrue(len(cti.get("iocs", {}).get("hashes", [])) > 0 or len(cti.get("iocs", {}).get("emails", [])) > 0 or len(cti.get("iocs", {}).get("ip_addresses", [])) > 0)

    def test_09_mitre_mapping_confidence(self):
        text = "Selling Loki 2.0 Botnet keylogger source code"
        res = self.engine.predict(text)
        
        for m in res["mitre"]:
            self.assertIn("technique_id", m)
            self.assertIn("technique_name", m)
            self.assertIn("evidence", m)
            self.assertIn("mapping_method", m)
            self.assertIn("confidence", m)
            self.assertIn(m["mapping_method"], ["EXPLICIT_EVIDENCE", "WEAK_KEYWORD_ASSOCIATION"])

    def test_10_risk_engine_transparency(self):
        res = self.engine.predict("CVE-2024-1234 zero-day exploit for Windows RCE")
        
        risk = res["risk"]
        self.assertIn("risk_score", risk)
        self.assertIn("severity", risk)
        self.assertIn("contributing_factors", risk)
        self.assertTrue(0.0 <= risk["risk_score"] <= 1.0)

    def test_11_xai_availability(self):
        res = self.engine.predict("Selling Loki 2.0 Botnet", deep_explain=True)
        
        xai = res["xai"]
        self.assertTrue(xai["xai_available"])
        self.assertEqual(xai["explanation_mode"], "DEEP_EXPLANATION")

    def test_12_end_to_end_alert_structure(self):
        res = self.engine.predict("Selling Loki 2.0 Botnet keylogger with RDP access")
        
        alert = res["alert"]
        self.assertTrue(alert["alert_id"].startswith("DW-ALERT-"))
        self.assertIn("timestamp", alert)
        self.assertIn("risk_score", alert)
        self.assertIn("severity", alert)
        self.assertIn("mitre_matches", alert)

if __name__ == "__main__":
    unittest.main()
