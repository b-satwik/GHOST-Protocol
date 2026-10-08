"""
Automated Test Suite for Stage 1 Live Continuous Observation & Operation.
Tests:
- Extended SourceRegistry scheduling & failure tracking
- ObservationHistoryStore persistence & entity queries
- HistoricalCorrelator recurrence timelines (FIRST_SEEN, LAST_SEEN, TIMELINE)
- Stage1AlertEngine rule triggers & alert object schema
- Stage1ContinuousObserver live observation loop & heartbeat logic
- Dashboard REST APIs (/api/live_status, /api/alerts, /api/history/correlate, /api/timeline_data, /api/discovery_graph)
"""

import unittest
import os
import sys
import json
import tempfile
import datetime

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.discovery.source_registry import SourceRegistry
from src.discovery.observation_history import ObservationHistoryStore
from src.discovery.historical_correlator import HistoricalCorrelator
from src.discovery.stage1_alert_engine import Stage1AlertEngine
from src.stage1_continuous_observer import Stage1ContinuousObserver
from src.stage1_dashboard import app


class TestStage1LiveOperation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.registry_db = os.path.join(self.temp_dir.name, "sources.db")
        self.queue_db = os.path.join(self.temp_dir.name, "queue.db")
        self.history_db = os.path.join(self.temp_dir.name, "history.db")
        self.alerts_db = os.path.join(self.temp_dir.name, "alerts.db")

        self.registry = SourceRegistry(db_path=self.registry_db)
        self.history_store = ObservationHistoryStore(db_path=self.history_db)
        self.correlator = HistoricalCorrelator(history_store=self.history_store)
        self.alert_engine = Stage1AlertEngine(db_path=self.alerts_db)

        self.app = app.test_client()
        self.app.testing = True

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_extended_source_registry_scheduling(self):
        added = self.registry.add_source(
            source_id="src_sched_1",
            url="http://schedtest.onion/main",
            source_type="ONION_WEBSITE",
            collector_type="TOR_BROWSER",
            polling_interval_mins=15,
            discovered_via="UNIT_TEST"
        )
        self.assertTrue(added)

        due = self.registry.get_due_sources()
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0]["collector_type"], "TOR_BROWSER")

        # Update observation schedule
        self.registry.update_source_observation(
            source_id="src_sched_1",
            status="CONTENT_ACCESSIBLE",
            raw_html_sha256="raw_sha_123",
            clean_text_sha256="clean_sha_123",
            content_changed=True,
            polling_interval_mins=60
        )

        src = self.registry.get_source_by_url("http://schedtest.onion/main")
        self.assertEqual(src["polling_interval_mins"], 60)  # updated polling interval persisted

    def test_observation_history_and_correlation(self):
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        obs1 = {
            "observation_id": "obs_001",
            "source_id": "src_alpha",
            "canonical_url": "http://alpha.onion/leak",
            "timestamp_utc": "2026-10-01T08:00:00Z",
            "status": "CONTENT_ACCESSIBLE",
            "change_state": "CHANGED_UNIQUE",
            "raw_html_sha256": "r1",
            "clean_text_sha256": "c1",
            "clean_text": "Exploit payload for CVE-2024-1234 published on alpha forum.",
            "extracted_links": ["http://beta.onion"],
            "extracted_cves": ["CVE-2024-1234"],
            "extracted_malware": ["Loki"],
            "extracted_iocs": [{"indicator_type": "CVE", "normalized_value": "CVE-2024-1234"}],
            "stix_bundle_id": "bundle--111",
            "mitre_techniques": ["T1190"],
            "fusion_risk_score": 0.85,
            "risk_severity": "HIGH",
            "xai_summary": "High risk RCE vulnerability",
            "provenance": {}
        }
        obs2 = {
            "observation_id": "obs_002",
            "source_id": "src_beta",
            "canonical_url": "http://beta.onion/leak",
            "timestamp_utc": "2026-10-03T09:00:00Z",
            "status": "CONTENT_ACCESSIBLE",
            "change_state": "CHANGED_UNIQUE",
            "raw_html_sha256": "r2",
            "clean_text_sha256": "c2",
            "clean_text": "Recurrence of CVE-2024-1234 exploit source code.",
            "extracted_links": [],
            "extracted_cves": ["CVE-2024-1234"],
            "extracted_malware": [],
            "extracted_iocs": [{"indicator_type": "CVE", "normalized_value": "CVE-2024-1234"}],
            "stix_bundle_id": "bundle--222",
            "mitre_techniques": ["T1190"],
            "fusion_risk_score": 0.78,
            "risk_severity": "ELEVATED",
            "xai_summary": "Elevated vulnerability recurrence",
            "provenance": {}
        }

        self.history_store.save_observation(obs1)
        self.history_store.save_observation(obs2)

        # Correlate CVE-2024-1234
        res = self.correlator.correlate_entity("CVE-2024-1234")
        self.assertTrue(res["match_found"])
        self.assertEqual(res["first_seen_utc"], "2026-10-01T08:00:00Z")
        self.assertEqual(res["last_seen_utc"], "2026-10-03T09:00:00Z")
        self.assertEqual(res["observation_count"], 2)
        self.assertEqual(res["unique_sources_count"], 2)
        self.assertEqual(res["relationship"], "HISTORICAL_INDICATOR_RECURRENCE")

    def test_alert_engine_rules(self):
        obs_data = {
            "observation_id": "obs_alert_test",
            "source_id": "src_alert",
            "url": "http://alerttarget.onion",
            "change_state": "CHANGED_UNIQUE"
        }
        bridge_output = {
            "risk_score": 0.88,
            "risk_severity": "HIGH",
            "cti": {
                "indicators": [
                    {"indicator_type": "CVE", "normalized_value": "CVE-2024-9999"},
                    {"indicator_type": "MALWARE", "normalized_value": "DarkBot"}
                ]
            }
        }

        alerts = self.alert_engine.evaluate_and_alert(obs_data, bridge_output)
        self.assertGreaterEqual(len(alerts), 2)  # High risk alert + CVE alert + Malware alert

        recent = self.alert_engine.get_recent_alerts()
        self.assertGreaterEqual(len(recent), 2)
        event_types = [a["event_type"] for a in recent]
        self.assertIn("NEW_HIGH_RISK_THREAT", event_types)
        self.assertIn("NEW_CVE_DISCOVERED", event_types)

    def test_continuous_observer_single_pass(self):
        observer = Stage1ContinuousObserver(
            registry_db=self.registry_db,
            queue_db=self.queue_db,
            history_db=self.history_db,
            alerts_db=self.alerts_db,
            enforce_whonix=False
        )
        observer.registry.add_source(
            source_id="src_pass_1",
            url="http://127.0.0.1:5000/synthetic_test_feed",
            source_type="GENERIC_WEBSITE"
        )

        res = observer.run_single_scheduled_pass()
        self.assertEqual(res["processed_sources_count"], 1)
        item = res["results"][0]
        self.assertEqual(item["source_id"], "src_pass_1")
        self.assertTrue(item["dispatched_to_bridge"])

        # Second pass on same source -> Unchanged content -> Heartbeat recorded without dispatching to bridge
        src = observer.registry.get_source_by_url("http://127.0.0.1:5000/synthetic_test_feed")
        item2 = observer.observe_source_entry(src)
        self.assertFalse(item2["dispatched_to_bridge"])

    def test_live_dashboard_apis(self):
        resp_status = self.app.get("/api/live_status")
        self.assertEqual(resp_status.status_code, 200)

        resp_alerts = self.app.get("/api/alerts")
        self.assertEqual(resp_alerts.status_code, 200)

        resp_timeline = self.app.get("/api/timeline_data")
        self.assertEqual(resp_timeline.status_code, 200)

        resp_graph = self.app.get("/api/discovery_graph")
        self.assertEqual(resp_graph.status_code, 200)

        resp_corr = self.app.get("/api/history/correlate?entity=CVE-2024-1234")
        self.assertEqual(resp_corr.status_code, 200)


if __name__ == "__main__":
    unittest.main()
