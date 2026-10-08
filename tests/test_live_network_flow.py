"""
Unit & Integration Test Suite for Live Network Flow Workspace & XGBoost Feature Capture Pipeline.
"""

import sys
import os
import time
import json
import unittest
import threading

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.stage1_dashboard import app as flask_app, network_flow_collector, inference_engine
from src.observer.network_flow_collector import NetworkFlowCollector
from darkwatch_labs.services.app import app as lab_app


class TestLiveNetworkFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n==================================================")
        print("  LIVE NETWORK FLOW & XGBOOST TEST SUITE          ")
        print("==================================================")
        cls.client = flask_app.test_client()
        cls.collector = network_flow_collector

    def setUp(self):
        self.collector.captured_flows.clear()
        self.collector.capture_active = False

    def test_01_network_unavailable_state(self):
        """Verify network-unavailable state displays correctly when no flows are recorded."""
        res = self.client.get("/api/network_flow/status?source_id=src_none")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data.decode("utf-8"))
        self.assertFalse(data.get("modality_available"))
        self.assertIsNone(data.get("latest_xgboost"))
        self.assertIsNone(data.get("network_score"))

        analysis_res = self.client.get("/api/network_flow/xgboost_analysis")
        analysis_data = json.loads(analysis_res.data.decode("utf-8"))
        self.assertFalse(analysis_data.get("modality_available"))
        self.assertIn("NETWORK MODALITY UNAVAILABLE", analysis_data.get("interpretation"))

    def test_02_79_cicflowmeter_feature_extraction(self):
        """Verify feature extraction generates exact 79 features matching frozen XGBoost model."""
        flow = self.collector.record_observed_traffic(
            source_id="src_shadowforum",
            target_url="http://127.0.0.1:8085/shadowforum",
            collector="TOR CLI",
            http_status=200,
            bytes_sent=450,
            bytes_received=1540,
            round_trip_time_ms=120.0
        )
        self.assertIsNotNone(flow)
        raw_feats = flow.get("features_raw", {})
        self.assertEqual(len(raw_feats), 79)
        self.assertIn("Src Port", raw_feats)
        self.assertIn("Dst Port", raw_feats)
        self.assertIn("Flow Duration", raw_feats)
        self.assertIn("Total Fwd Packet", raw_feats)

    def test_03_flow_provenance_retention(self):
        """Verify each flow retains full provenance (flow_id, source_id, observation_id, target_url, collector, timestamp)."""
        flow = self.collector.record_observed_traffic(
            source_id="src_dreadlab",
            target_url="http://127.0.0.1:8085/dreadlab",
            collector="TOR BROWSER",
            http_status=401,
            bytes_sent=320,
            bytes_received=1820,
            round_trip_time_ms=210.0,
            observation_id="obs_test_123"
        )
        self.assertTrue(flow["flow_id"].startswith("flow_"))
        self.assertEqual(flow["source_id"], "src_dreadlab")
        self.assertEqual(flow["observation_id"], "obs_test_123")
        self.assertEqual(flow["target_url"], "http://127.0.0.1:8085/dreadlab")
        self.assertEqual(flow["collector"], "TOR BROWSER")
        self.assertIn("UTC", flow["timestamp"])

    def test_04_xgboost_inference_and_score(self):
        """Verify frozen XGBoost model runs on captured network features and produces actual score."""
        flow = self.collector.record_observed_traffic(
            source_id="src_shadowforum",
            target_url="http://127.0.0.1:8085/shadowforum",
            collector="TOR CLI",
            http_status=200,
            bytes_sent=500,
            bytes_received=2500,
            round_trip_time_ms=95.0
        )
        xgb = flow.get("xgboost")
        self.assertIsNotNone(xgb)
        self.assertTrue(xgb.get("network_available"))
        self.assertIn("predicted_class", xgb)
        self.assertIn("confidence", xgb)
        self.assertIsNotNone(flow.get("network_score"))

    def test_05_network_flow_api_endpoints(self):
        """Test REST API endpoints for starting, stopping, investigating, and analyzing network flows."""
        start_res = self.client.post("/api/network_flow/start", json={"source_id": "src_shadowforum", "target_url": "http://127.0.0.1:8085/shadowforum"})
        self.assertEqual(start_res.status_code, 200)
        start_data = json.loads(start_res.data.decode("utf-8"))
        self.assertTrue(start_data.get("success"))

        self.collector.record_observed_traffic("src_shadowforum", "http://127.0.0.1:8085/shadowforum", 4, 4, 1024, 3219, 15.2)

        status_res = self.client.get("/api/network_flow/status?source_id=src_shadowforum")
        self.assertEqual(status_res.status_code, 200)
        status_data = json.loads(status_res.data.decode("utf-8"))
        self.assertTrue(status_data.get("active"))
        self.assertTrue(len(status_data.get("flows")) > 0)

        flow_id = status_data["flows"][0]["flow_id"]
        inv_res = self.client.get(f"/api/network_flow/investigate/{flow_id}")
        self.assertEqual(inv_res.status_code, 200)
        inv_data = json.loads(inv_res.data.decode("utf-8"))
        self.assertEqual(inv_data.get("flow_id"), flow_id)
        self.assertIn("Packet Overview", inv_data.get("features_normalized", {}))

        stop_res = self.client.post("/api/network_flow/stop", json={"source_id": "src_shadowforum"})
        self.assertEqual(stop_res.status_code, 200)

    def test_06_browser_required_flow(self):
        """Verify browser-required flow sets correct collector, access requirement, and Tor Browser status."""
        res = self.client.post("/api/network_flow/start", json={"source_id": "src_dreadlab", "target_url": "http://127.0.0.1:8085/dreadlab"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data.decode("utf-8"))
        self.assertEqual(data.get("access_requirement"), "BROWSER REQUIRED")
        self.assertEqual(data.get("collector"), "TOR BROWSER")
        self.assertEqual(data.get("status"), "WAITING FOR BROWSER")
        self.assertIn("Tor Browser", data.get("message"))


if __name__ == "__main__":
    unittest.main()
