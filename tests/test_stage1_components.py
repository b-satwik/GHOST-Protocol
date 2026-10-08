"""
Unit and Integration Tests for GHOST PROTOCOL Stage 1 Infrastructure.
Covers:
- SourceRegistry CRUD & URL canonicalization
- DiscoveryQueue state management
- LinkExtractor regex parsing & canonicalization
- ChangeDetector SHA-256 exact matching & MinHash near-duplicate detection
- WhonixTransport fail-closed pre-flight socket verification & status mapping
- Stage1Runner orchestration with local mock observations and lab_bridge integration
"""

import unittest
import os
import sys
import tempfile

# Ensure root in sys.path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.discovery.source_registry import SourceRegistry
from src.discovery.discovery_queue import DiscoveryQueue
from src.discovery.observation_record import ObservationRecord
from src.discovery.link_extractor import LinkExtractor
from src.observer.whonix_transport import WhonixTransport, WhonixIsolationError
from src.observer.change_detector import ChangeDetector
from src.pipeline.lab_bridge import DarkWatchLabBridge
from src.stage1_runner import Stage1Runner


class TestStage1SourceRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = SourceRegistry(db_path=":memory:")

    def test_canonicalize_url(self):
        self.assertEqual(
            SourceRegistry.canonicalize_url("HTTP://EXAMPLE.COM/path/"),
            "HTTP://EXAMPLE.COM/path"
        )
        self.assertEqual(
            SourceRegistry.canonicalize_url("https://test.lab.onion/#fragment"),
            "https://test.lab.onion"
        )

    def test_crud_operations(self):
        # Add source
        added = self.registry.add_source("src1", "http://test.onion/path", "ONION", "DEEPDARKCTI")
        self.assertTrue(added)

        # Prevent Duplicate canonical URL
        dup = self.registry.add_source("src2", "http://test.onion/path/", "ONION", "SEARCH")
        self.assertFalse(dup)

        # Get Source
        src = self.registry.get_source_by_url("http://test.onion/path")
        self.assertIsNotNone(src)
        self.assertEqual(src["source_id"], "src1")
        self.assertEqual(src["validation_status"], "ACTIVE")

        # Deactivate / Reactivate
        self.assertTrue(self.registry.deactivate_source("src1"))
        self.assertEqual(len(self.registry.get_active_sources()), 0)

        self.assertTrue(self.registry.reactivate_source("src1"))
        self.assertEqual(len(self.registry.get_active_sources()), 1)

        # Remove
        self.assertTrue(self.registry.remove_source("src1"))
        self.assertIsNone(self.registry.get_source_by_url("http://test.onion/path"))


class TestStage1DiscoveryQueue(unittest.TestCase):

    def setUp(self):
        self.queue = DiscoveryQueue(db_path=":memory:")

    def test_enqueue_dequeue(self):
        inserted = self.queue.enqueue("http://candidate.onion", "LINK_HOPPING", "http://parent.onion")
        self.assertTrue(inserted)

        # Prevent Duplicate candidate URL
        dup = self.queue.enqueue("http://candidate.onion/", "LINK_HOPPING")
        self.assertFalse(dup)

        item = self.queue.dequeue()
        self.assertIsNotNone(item)
        self.assertEqual(item["candidate_url"], "http://candidate.onion")
        self.assertEqual(item["processing_state"], "IN_PROGRESS")

        self.assertTrue(self.queue.mark_processed(item["queue_id"], "PROMOTED"))

        # Queue should now be empty
        self.assertIsNone(self.queue.dequeue())


class TestStage1LinkExtractor(unittest.TestCase):

    def setUp(self):
        self.extractor = LinkExtractor()

    def test_extract_links(self):
        sample_text = """
        Check out ransomware site http://testleak.lab.onion/leak
        Also join our Telegram: https://t.me/s/SliceForLifeee and chat https://t.me/joinchat/12345.
        Surface CTI: https://example.com/report.pdf.
        """
        links = self.extractor.extract_links(sample_text)
        self.assertTrue(any("testleak.lab.onion" in l for l in links))
        self.assertTrue(any("t.me/s/SliceForLifeee" in l for l in links))
        self.assertTrue(any("example.com/report.pdf" in l for l in links))


class TestStage1ChangeDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ChangeDetector(jaccard_threshold=0.80)

    def test_sha256_exact_change(self):
        raw = "<html><body>Test payload</body></html>"
        clean = "Test payload"

        # First evaluation -> CHANGED_UNIQUE
        state, r_hash, c_hash, meta = self.detector.evaluate_change("src_1", raw, clean)
        self.assertEqual(state, ChangeDetector.STATE_CHANGED_UNIQUE)

        # Second evaluation with same content -> UNCHANGED
        state2, r_hash2, c_hash2, meta2 = self.detector.evaluate_change("src_1", raw, clean)
        self.assertEqual(state2, ChangeDetector.STATE_UNCHANGED)

    def test_minhash_near_duplicate(self):
        text_a = "Critical ransomware threat actor releasing database leaks containing user records and credentials."
        text_b = "Critical ransomware threat actor releasing database leaks containing user records and password credentials."

        state1, r1, c1, m1 = self.detector.evaluate_change("src_a", text_a, text_a)
        self.assertEqual(state1, ChangeDetector.STATE_CHANGED_UNIQUE)

        state2, r2, c2, m2 = self.detector.evaluate_change("src_b", text_b, text_b)
        self.assertEqual(state2, ChangeDetector.STATE_CHANGED_NEAR_DUPLICATE)


class TestStage1WhonixTransport(unittest.TestCase):

    def test_status_classification(self):
        self.assertEqual(WhonixTransport.classify_http_status(200), WhonixTransport.STATUS_CONTENT_ACCESSIBLE)
        self.assertEqual(WhonixTransport.classify_http_status(401), WhonixTransport.STATUS_VERIFICATION_REQUIRED)
        self.assertEqual(WhonixTransport.classify_http_status(403), WhonixTransport.STATUS_VERIFICATION_REQUIRED)
        self.assertEqual(WhonixTransport.classify_http_status(503), WhonixTransport.STATUS_AUTOMATED_ACCESS_BLOCKED)
        self.assertEqual(WhonixTransport.classify_http_status(500), WhonixTransport.STATUS_OFFLINE)

    def test_whonix_fail_closed_mock(self):
        # Target an unused loopback port to trigger connection refusal
        transport = WhonixTransport(proxy_host="127.0.0.1", proxy_port=59999, enforce_fail_closed=True)
        with self.assertRaises(WhonixIsolationError):
            transport.verify_gateway(timeout=0.1)


class TestStage1RunnerIntegration(unittest.TestCase):

    def setUp(self):
        self.runner = Stage1Runner(
            registry_db=":memory:",
            queue_db=":memory:",
            enforce_whonix=False
        )

    def test_stage1_runner_flow(self):
        mock_html = "<html><body>Ransomware alert! Target IP 192.168.1.100 leaked on http://leak777.onion</body></html>"
        mock_text = "Ransomware alert! Target IP 192.168.1.100 leaked on http://leak777.onion"

        res = self.runner.process_mock_observation(
            source_id="src_mock_1",
            url="http://mockfeed.onion/posts",
            raw_html=mock_html,
            clean_text=mock_text
        )

        self.assertEqual(res["change_state"], ChangeDetector.STATE_CHANGED_UNIQUE)
        self.assertTrue(res["dispatched_to_bridge"])
        self.assertGreaterEqual(res["extracted_links_count"], 1)
        self.assertEqual(res["newly_enqueued_links"], 1)

        b_out = res["bridge_output"]
        self.assertIsNotNone(b_out)
        self.assertEqual(b_out["data_provenance"], "GHOST_PROTOCOL_STAGE1_OBSERVATION")
        self.assertIn("indicators", b_out["cti"])


if __name__ == "__main__":
    unittest.main()
