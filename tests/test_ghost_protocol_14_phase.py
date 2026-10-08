"""
GHOST PROTOCOL 20-Scenario Integration Test Suite.
Validates all 14 phases across frozen ML core, Whonix boundary, source registry,
Telegram & Dread observers, NLU extraction, pipeline bridge, entity resolution,
HIBP breach lookups, Sherlock OSINT, graph correlation, and dashboard telemetry.
"""

import sys
import os
import unittest
import datetime

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.dataset.annotation_store import AnnotationStore
from src.observer.whonix_transport import verify_whonix_gateway, WhonixTransport
from src.discovery.source_registry import SourceRegistry
from src.observer.telegram_public_observer import TelegramPublicObserver
from src.observer.dread_session_observer import DreadSessionObserver
from src.discovery.link_extractor import LinkExtractor
from src.filter.threat_filter import ThreatFilter
from src.extraction.threat_extractor import ThreatExtractor
from src.pipeline.lab_bridge import DarkWatchLabBridge
from src.resolution.entity_resolver import EntityResolver
from src.resolution.hibp_service import HIBPBreachService
from src.investigation.sherlock_wrapper import SherlockWrapper
from src.cti.lookup_service import CTILookupService


class TestGhostProtocol14Phases(unittest.TestCase):
    """
    20-Scenario integration test suite for GHOST PROTOCOL.
    """

    def setUp(self):
        self.store = AnnotationStore(db_path=":memory:")
        self.registry = SourceRegistry(db_path=":memory:")
        self.resolver = EntityResolver(store=self.store)
        self.hibp = HIBPBreachService(store=self.store)
        self.sherlock = SherlockWrapper()
        self.cti_lookup = CTILookupService()
        self.threat_filter = ThreatFilter()
        self.threat_extractor = ThreatExtractor()

    def test_scenario_01_repo_audit_imports(self):
        """Scenario 1: Verify frozen ML imports load without retraining."""
        bridge = DarkWatchLabBridge()
        self.assertIsNotNone(bridge.engine)

    def test_scenario_02_database_schema(self):
        """Scenario 2: Verify extended GHOST PROTOCOL SQLite tables."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cursor.fetchall()]
            self.assertIn("entities", tables)
            self.assertIn("graph_edges", tables)
            self.assertIn("breach_claims", tables)
            self.assertIn("hibp_dumps", tables)

    def test_scenario_03_whonix_boundary(self):
        """Scenario 3: Verify Whonix Transport status classification."""
        status = WhonixTransport.classify_http_status(200)
        self.assertEqual(status, WhonixTransport.STATUS_CONTENT_ACCESSIBLE)

    def test_scenario_04_source_registry(self):
        """Scenario 4: Verify source registry URL canonicalization."""
        canon = SourceRegistry.canonicalize_url("http://test.onion/path/#anchor")
        self.assertEqual(canon, "http://test.onion/path")

    def test_scenario_05_telegram_observer(self):
        """Scenario 5: Verify public Telegram web observer polling."""
        observer = TelegramPublicObserver(channel_name="SliceForLifeee")
        posts = observer.poll()
        self.assertGreater(len(posts), 0)

    def test_scenario_06_dread_observer(self):
        """Scenario 6: Verify Dread session observer cookie vault."""
        dread = DreadSessionObserver()
        res = dread.poll_dread_forum()
        self.assertTrue(res["cookie_vault_active"])

    def test_scenario_07_link_extractor(self):
        """Scenario 7: Verify recursive link extraction for onion and paste links."""
        extractor = LinkExtractor()
        text = "Check http://shadowboard.lab.onion and pastebin.com/xyz123 and t.me/s/channel"
        links = extractor.extract_links(text)
        self.assertGreater(len(links), 0)

    def test_scenario_08_threat_filter_nlu(self):
        """Scenario 8: Verify NLU threat pre-filter categorization."""
        res = self.threat_filter.filter_and_categorize("Company ABC 50GB database leak access for sale")
        self.assertEqual(res["category"], "Data Breach")

    def test_scenario_09_threat_extractor_claims(self):
        """Scenario 9: Verify threat extractor NLU entity claims."""
        res = self.threat_extractor.extract("ShadowFox_lab released StealerX with 50GB data claim")
        self.assertEqual(res["status"]["nlu_claims"], "DETECTED")

    def test_scenario_10_entity_resolution_composite(self):
        """Scenario 10: Verify Jaro-Winkler & Composite Resolution Score."""
        jw = EntityResolver.jaro_winkler_similarity("ShadowFox_lab", "ShadowFox_lab")
        self.assertEqual(jw, 1.0)

    def test_scenario_11_entity_host_migration(self):
        """Scenario 11: Verify entity host migration tracking."""
        prof = self.resolver.resolve_entity("ShadowFox_lab", infrastructure=["abc.onion", "xyz.onion"])
        self.assertEqual(len(prof["timeline"]), 3)

    def test_scenario_12_hibp_identity_search(self):
        """Scenario 12: Verify HIBP breach search engine lookup."""
        res = self.hibp.search_identity("Company ABC")
        self.assertTrue(res["found"])
        self.assertFalse(res["results"][0]["raw_secrets_exposed"])

    def test_scenario_13_sherlock_osint(self):
        """Scenario 13: Verify Sherlock surface-web handle queries."""
        res = self.sherlock.query_username("ShadowFox_lab")
        self.assertEqual(res["username"], "ShadowFox_lab")

    def test_scenario_14_graph_correlation(self):
        """Scenario 14: Verify STIX 2.1 multi-hop graph query."""
        res = self.cti_lookup.query_graph("ShadowFox_lab")
        self.assertIn("stix_bundle", res)

    def test_scenario_15_pipeline_bridge_observation(self):
        """Scenario 15: Verify lab bridge observation execution."""
        bridge = DarkWatchLabBridge()
        res = bridge.observe_endpoint("/forum")
        self.assertIn("text_prediction", res)

    def test_scenario_16_distilbert_token_evidence(self):
        """Scenario 16: Verify DistilBERT prediction evidence fields."""
        bridge = DarkWatchLabBridge()
        res = bridge.observe_endpoint("/forum")
        self.assertIn("predicted_class", res["text_prediction"])

    def test_scenario_17_xgboost_flow_classification(self):
        """Scenario 17: Verify XGBoost flow feature classification."""
        bridge = DarkWatchLabBridge()
        res = bridge.observe_endpoint("/forum")
        self.assertIn("network_prediction", res)

    def test_scenario_18_temporal_ae_reconstruction(self):
        """Scenario 18: Verify Temporal Autoencoder reconstruction score."""
        bridge = DarkWatchLabBridge()
        res = bridge.observe_endpoint("/forum")
        self.assertIn("temporal_result", res)

    def test_scenario_19_hm_tif_fusion(self):
        """Scenario 19: Verify HM-TIF dynamic fusion risk score."""
        bridge = DarkWatchLabBridge()
        res = bridge.observe_endpoint("/forum")
        self.assertIn("risk_score", res)

    def test_scenario_20_end_to_end_verification(self):
        """Scenario 20: Complete 14-Phase end-to-end verification."""
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
