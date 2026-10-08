"""
End-to-End Prototype Integration Tests for DarkWatch.
Verifies full pipeline execution across:
1. Collector Evidence SQLite Store
2. CTI Indicator Extraction & STIX 2.1 Serialization
3. Official Local MITRE ATT&CK STIX 2.1 Enrichment
4. DistilBERT Text Model + PyTorch Autoencoders + XGBoost Classifier
5. Dynamic Tri-Modal Risk Fusion Engine
6. Performance-Aware XAI & Security Alert Object Generation
"""

import unittest
import os
import shutil
import tempfile
import sqlite3

from src.collector.evidence_store import EvidenceStore
from src.pipeline.inference_engine import InferenceEngine


class TestEndToEndPrototype(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test_collector_evidence.db")
        cls.store = EvidenceStore(db_path=cls.db_path)
        cls.engine = InferenceEngine(models_dir="models")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_collector_record_ingestion_and_pipeline(self):
        """Test processing a collector verification attempt through the end-to-end prototype."""
        sample_text = (
            "Selling Loki 2.0 Botnet keylogger source code. "
            "Includes Windows RCE exploit CVE-2024-38077 and 100x stolen RDP access. "
            "Contact C2 server at 192.168.1.50 or visit darkmarket12345.onion."
        )
        
        saved = self.store.save_attempt({
            "source_id": "SRC_TEST_001",
            "onion_address": "http://darkmarket12345.onion",
            "timestamp": "2026-09-26T21:15:00Z",
            "http_status": 200,
            "response_time_ms": 350,
            "state": "CONTENT_ACCESSIBLE",
            "text_length": len(sample_text),
            "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "sanitized_text": sample_text
        })
        
        record_id = saved["id"]
        result = self.engine.predict_collector_record(record_id, db_path=self.db_path, deep_explain=True)
        
        # Check overall result schema
        self.assertIn("input", result)
        self.assertIn("text_model", result)
        self.assertIn("behavior_model", result)
        self.assertIn("temporal_model", result)
        self.assertIn("network_model", result)
        self.assertIn("fusion", result)
        self.assertIn("cti_entities", result)
        self.assertIn("mitre", result)
        self.assertIn("risk", result)
        self.assertIn("xai", result)
        self.assertIn("alert", result)
        self.assertIn("cti_bridge", result)

    def test_02_stix_bundle_and_mitre_enrichment(self):
        """Test STIX 2.1 bundle association and MITRE STIX 2.1 enrichment in alert output."""
        sample_text = "Zero-day exploit for CVE-2024-1234 with credential dumping keylogger tool."
        
        saved = self.store.save_attempt({
            "source_id": "SRC_TEST_002",
            "onion_address": "http://exploitvault99.onion",
            "timestamp": "2026-09-26T21:20:00Z",
            "http_status": 200,
            "response_time_ms": 280,
            "state": "CONTENT_ACCESSIBLE",
            "text_length": len(sample_text),
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "sanitized_text": sample_text
        })
        
        result = self.engine.predict_collector_record(saved["id"], db_path=self.db_path)
        alert = result["alert"]
        
        # Verify STIX 2.1 bundle ID is attached to Alert object
        self.assertIn("stix_bundle_id", alert)
        self.assertTrue(alert["stix_bundle_id"].startswith("bundle--"))
        
        # Verify MITRE STIX 2.1 enrichment
        cti_bridge = result["cti_bridge"]
        self.assertGreater(cti_bridge["extracted_indicators_count"], 0)
        self.assertIn("enriched_mitre_techniques", cti_bridge)

    def test_03_modality_availability_handling(self):
        """Verify dynamic fusion handles missing behavioral/temporal/network modalities cleanly."""
        text_only_input = "Selling stolen credentials combo list for banking apps"
        result = self.engine.predict(text_only_input)
        
        fusion = result["fusion"]
        modalities = fusion["available_modalities"]
        
        self.assertTrue(modalities["text"])
        self.assertFalse(modalities["behavioral"])
        self.assertFalse(modalities["temporal"])
        self.assertFalse(modalities["network"])
        
        # Renormalized weight must be 1.0 for text
        self.assertEqual(fusion["active_weights"]["text"], 1.0)
        self.assertEqual(fusion["active_weights"]["behavioral"], 0.0)


if __name__ == "__main__":
    unittest.main()
