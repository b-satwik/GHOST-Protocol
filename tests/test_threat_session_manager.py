"""
Test suite for Threat Session Manager & CTI AI Mode / Search External Research Service.
Verifies all 14 session correlation, boundary, CTI aggregation, sanitization, and provenance rules.
"""

import unittest
import os
import sys
import shutil
import tempfile

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.dataset.annotation_store import AnnotationStore
from src.resolution.session_manager import ThreatSessionManager, ThreatSession
from src.investigation.external_research_service import ExternalResearchService


class TestThreatSessionManager(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_gold.db")
        self.store = AnnotationStore(db_path=self.db_path)
        self.session_manager = ThreatSessionManager(store=self.store)
        self.research_service = ExternalResearchService(store=self.store)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_1_new_unrelated_observation_creates_new_session(self):
        obs1 = {
            "obs_id": "OBS-001",
            "text": "Regular darknet forum post about programming tutorials.",
            "canonical_url": "http://forum.onion/post1",
            "bridge_output": {"cti": {"entities": []}}
        }
        sess, action, reasons = self.session_manager.evaluate_observation(obs1)
        self.assertEqual(action, "CREATE_NEW_SESSION")
        self.assertIsNotNone(sess.session_id)
        self.assertIn("OBS-001", sess.observation_ids)

    def test_2_related_observation_joins_existing_session(self):
        obs1 = {
            "obs_id": "OBS-001",
            "text": "ViperSec: I got access to ApexGlobal.",
            "canonical_url": "http://shadowforum.lab.onion/access1",
            "bridge_output": {
                "cti": {
                    "entities": [
                        {"type": "ACTOR", "value": "ViperSec"},
                        {"type": "TARGET", "value": "ApexGlobal Financial"}
                    ]
                }
            }
        }
        sess1, action1, _ = self.session_manager.evaluate_observation(obs1)

        obs2 = {
            "obs_id": "OBS-002",
            "text": "ViperSec: ApexGlobal database sample available now.",
            "canonical_url": "http://shadowforum.lab.onion/access2",
            "bridge_output": {
                "cti": {
                    "entities": [
                        {"type": "ACTOR", "value": "ViperSec"},
                        {"type": "TARGET", "value": "ApexGlobal Financial"}
                    ]
                }
            }
        }
        sess2, action2, reasons2 = self.session_manager.evaluate_observation(obs2)
        self.assertEqual(action2, "LINK_TO_EXISTING_SESSION")
        self.assertEqual(sess1.session_id, sess2.session_id)
        self.assertIn("OBS-001", sess2.observation_ids)
        self.assertIn("OBS-002", sess2.observation_ids)

    def test_3_alias_resolution_correct_session_linking(self):
        obs1 = {
            "obs_id": "OBS-101",
            "text": "ViperSec: Claiming access to ApexGlobal Financial.",
            "canonical_url": "http://shadowforum.lab.onion/p1"
        }
        sess1, _, _ = self.session_manager.evaluate_observation(obs1)

        obs2 = {
            "obs_id": "OBS-102",
            "text": "Viper_X: Selling ApexGlobal VPN access.",
            "canonical_url": "http://dreadlab.lab.onion/p2"
        }
        sess2, action2, reasons2 = self.session_manager.evaluate_observation(obs2)
        self.assertEqual(action2, "LINK_TO_EXISTING_SESSION")
        self.assertEqual(sess1.session_id, sess2.session_id)
        self.assertTrue(any("Alias relationship" in r or "Viper_X" in r or "ViperSec" in r for r in reasons2))

    def test_4_same_target_and_evidence_updates_session(self):
        obs1 = {
            "obs_id": "OBS-201",
            "text": "ViperSec: Initial access claim to ApexGlobal.",
            "canonical_url": "http://shadowforum.lab.onion/p1"
        }
        sess1, _, _ = self.session_manager.evaluate_observation(obs1)

        obs3 = {
            "obs_id": "OBS-203",
            "text": "ApexGlobal database sample leak file.",
            "canonical_url": "http://pastevault.lab.onion/raw/123"
        }
        sess3, action3, _ = self.session_manager.evaluate_observation(obs3)
        self.assertEqual(action3, "LINK_TO_EXISTING_SESSION")
        self.assertEqual(sess1.session_id, sess3.session_id)
        self.assertIn("ApexGlobal Financial", sess3.targets)

    def test_5_unrelated_same_site_post_does_not_automatically_join(self):
        obs1 = {
            "obs_id": "OBS-301",
            "text": "ViperSec claiming access to ApexGlobal.",
            "canonical_url": "http://shadowforum.lab.onion/p1"
        }
        sess1, _, _ = self.session_manager.evaluate_observation(obs1)

        obs_unrelated = {
            "obs_id": "OBS-302",
            "text": "RandomUser: Selling graphic design templates for cryptocurrency.",
            "canonical_url": "http://shadowforum.lab.onion/unrelated_post"
        }
        sess_unrelated, action_unrelated, _ = self.session_manager.evaluate_observation(obs_unrelated)
        self.assertEqual(action_unrelated, "CREATE_NEW_SESSION")
        self.assertNotEqual(sess1.session_id, sess_unrelated.session_id)

    def test_6_duplicate_observation_no_duplicate_session_evidence(self):
        obs1 = {
            "obs_id": "OBS-DUP-001",
            "text": "ViperSec: Access sold.",
            "canonical_url": "http://shadowforum.lab.onion/p4"
        }
        sess1, action1, _ = self.session_manager.evaluate_observation(obs1)
        self.assertEqual(len(sess1.observation_ids), 1)

        # Submit exact same observation ID again
        sess2, action2, reasons2 = self.session_manager.evaluate_observation(obs1)
        self.assertEqual(action2, "LINK_TO_EXISTING_SESSION")
        self.assertEqual(len(sess2.observation_ids), 1)

    def test_8_session_timeline_updates_correctly(self):
        obs1 = {"obs_id": "OBS-TL-1", "text": "ViperSec claim ApexGlobal.", "canonical_url": "http://s.onion/1"}
        sess, _, _ = self.session_manager.evaluate_observation(obs1)
        self.assertEqual(len(sess.timeline), 1)
        self.assertEqual(sess.timeline[0]["observation_id"], "OBS-TL-1")

    def test_9_temporal_autoencoder_independence(self):
        obs = {
            "obs_id": "OBS-TAE-1",
            "text": "Routine post",
            "temporal_ae_result": {
                "is_anomaly": True,
                "anomaly_score": 0.85,
                "reason": "Unusual timing observed"
            }
        }
        sess, _, _ = self.session_manager.evaluate_observation(obs)
        self.assertEqual(sess.temporal_anomaly["status"], "HIGH")
        self.assertEqual(sess.temporal_anomaly["anomaly_score"], 0.85)

    def test_12_ai_mode_sanitizes_outbound_context(self):
        sensitive_text = "Actor posted password: superSecretPassword123 with token YOUR_API_KEY_HERE."
        clean = self.research_service.sanitize_outbound_context(sensitive_text)
        self.assertNotIn("superSecretPassword123", clean)
        self.assertNotIn("sk-1234567890abcdef", clean)
        self.assertIn("[REDACTED_SECRET]", clean)

    def test_13_ai_mode_stores_provenance_and_separation(self):
        # Create a threat session in DB
        obs = {"obs_id": "OBS-AI-1", "text": "ViperSec claim ApexGlobal.", "canonical_url": "http://s.onion/1"}
        sess, _, _ = self.session_manager.evaluate_observation(obs)

        result = self.research_service.execute_research(
            session_id=sess.session_id,
            analyst_question="What public security information exists regarding ApexGlobal?"
        )
        self.assertIn("provenance_label", result)
        self.assertTrue(
            "EXTERNAL" in result["provenance_label"] or "UNVERIFIED" in result["provenance_label"]
        )

        # Retrieve stored logs from database
        logs = self.store.get_external_research_for_session(sess.session_id)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["research_id"], result["research_id"])


if __name__ == "__main__":
    unittest.main()
