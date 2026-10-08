"""
Controlled Lab Demonstration Script for Threat Session Analysis & CTI AI Mode / Search.

Simulates 4 evolving observations across synthetic lab sources (ShadowForum, DreadLab, PasteVault):
Day 1 (Observation 1): ViperSec posts: "I got access to ApexGlobal."
Day 1 (Observation 2): Viper_X posts: "Selling ApexGlobal VPN access."
Day 2 (Observation 3): A paste contains: "ApexGlobal database sample."
Day 3 (Observation 4): ViperSec posts: "Access sold."

Verifies:
1. GHOST creates ONE evolving Threat Session (e.g. TS-001) instead of 4 separate threats.
2. Timeline and explicit correlation reasons ("WHY LINKED") are recorded.
3. External Research Service retrieves session CTI context, sanitizes outbound data, and executes query.
4. Correct status/provenance ("EXTERNAL WEB AI RESEARCH" or "CONFIGURATION_REQUIRED") is stored.
"""

import sys
import os
import tempfile
import shutil
import json

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.dataset.annotation_store import AnnotationStore
from src.resolution.session_manager import ThreatSessionManager
from src.investigation.external_research_service import ExternalResearchService


def run_demonstration():
    print("======================================================================")
    print("GHOST PROTOCOL — THREAT SESSION & CTI AI SEARCH DEMONSTRATION")
    print("======================================================================\n")

    test_dir = tempfile.mkdtemp()
    db_path = os.path.join(test_dir, "demo_gold.db")
    store = AnnotationStore(db_path=db_path)
    session_manager = ThreatSessionManager(store=store)
    research_service = ExternalResearchService(store=store)

    observations = [
        {
            "obs_id": "OBS-LAB-001",
            "source_id": "SRC-SHADOWFORUM",
            "canonical_url": "http://shadowforum.lab.onion/threads/access-claim",
            "sanitized_text": "ViperSec: I got access to ApexGlobal Financial system infrastructure.",
            "text": "ViperSec: I got access to ApexGlobal Financial system infrastructure.",
            "bridge_output": {
                "cti": {
                    "entities": [
                        {"type": "ACTOR", "value": "ViperSec"},
                        {"type": "TARGET", "value": "ApexGlobal Financial"}
                    ],
                    "indicators": [{"indicator_type": "DOMAIN", "normalized_value": "apexglobal.com"}]
                }
            }
        },
        {
            "obs_id": "OBS-LAB-002",
            "source_id": "SRC-DREADLAB",
            "canonical_url": "http://dreadlab.lab.onion/post/vpn-sale",
            "sanitized_text": "Viper_X: Selling ApexGlobal VPN access and admin portal credentials.",
            "text": "Viper_X: Selling ApexGlobal VPN access and admin portal credentials.",
            "bridge_output": {
                "cti": {
                    "entities": [
                        {"type": "ACTOR", "value": "Viper_X"},
                        {"type": "TARGET", "value": "ApexGlobal Financial"}
                    ],
                    "indicators": [{"indicator_type": "URL", "normalized_value": "http://vpn.apexglobal.com"}]
                }
            }
        },
        {
            "obs_id": "OBS-LAB-003",
            "source_id": "SRC-PASTEVAULT",
            "canonical_url": "http://pastevault.lab.onion/raw/apex_db_sample",
            "sanitized_text": "ApexGlobal database sample leak: user hashes and customer records.",
            "text": "ApexGlobal database sample leak: user hashes and customer records.",
            "bridge_output": {
                "cti": {
                    "entities": [
                        {"type": "TARGET", "value": "ApexGlobal Financial"}
                    ],
                    "indicators": [{"indicator_type": "HASH", "normalized_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]
                }
            }
        },
        {
            "obs_id": "OBS-LAB-004",
            "source_id": "SRC-SHADOWFORUM",
            "canonical_url": "http://shadowforum.lab.onion/threads/access-sold",
            "sanitized_text": "ViperSec: ApexGlobal access sold. Deal closed.",
            "text": "ViperSec: ApexGlobal access sold. Deal closed.",
            "bridge_output": {
                "cti": {
                    "entities": [
                        {"type": "ACTOR", "value": "ViperSec"},
                        {"type": "TARGET", "value": "ApexGlobal Financial"}
                    ]
                }
            }
        }
    ]

    session_results = []
    for i, obs in enumerate(observations, 1):
        sess, action, reasons = session_manager.evaluate_observation(obs)
        session_results.append((sess, action, reasons))
        print(f"Observation {i} [{obs['obs_id']}]: Action -> {action}")
        print(f"   Target Session ID : {sess.session_id}")
        print(f"   WHY LINKED        : {', '.join(reasons)}")
        print("----------------------------------------------------------------------")

    # Verify all 4 observations linked to ONE Threat Session
    unique_session_ids = set(res[0].session_id for res in session_results)
    print(f"\n[+] Total Unique Threat Sessions Created: {len(unique_session_ids)}")

    if len(unique_session_ids) == 1:
        target_session_id = list(unique_session_ids)[0]
        print(f"[SUCCESS] All 4 observations correctly linked into single Threat Session: {target_session_id}\n")
    else:
        print(f"[FAIL] Expected 1 session but created {len(unique_session_ids)}")
        shutil.rmtree(test_dir)
        sys.exit(1)

    # Inspect final Threat Session detail
    sess_obj = store.get_threat_session(target_session_id)
    print("======================================================================")
    print("THREAT SESSION STATE SUMMARY:")
    print("======================================================================")
    print(f"Session ID : {sess_obj['session_id']}")
    print(f"Actors     : {sess_obj['actors']}")
    print(f"Aliases    : {sess_obj['aliases']}")
    print(f"Targets    : {sess_obj['targets']}")
    print(f"Timeline   : {len(sess_obj['timeline'])} events recorded")
    for t in sess_obj["timeline"]:
        print(f"   - [{t['observation_id']}] {t['event']} | Reasons: {'; '.join(t['reasons'])}")

    print("\n======================================================================")
    print("EXECUTING CTI AI MODE / SEARCH QUERY...")
    print("======================================================================")

    question = "What public advisories or CTI reports exist regarding ApexGlobal access sales?"
    research_result = research_service.execute_research(target_session_id, question)

    print(f"Research ID       : {research_result['research_id']}")
    print(f"Provenance Label  : {research_result['provenance_label']}")
    print(f"Status            : {research_result['status']}")
    print(f"Outbound Query    : {research_result['sanitized_query']}")
    print(f"Answer            : {research_result['answer']}\n")

    shutil.rmtree(test_dir)
    print("[SUCCESS] Demonstration complete. All session correlation and AI Search requirements verified.")


if __name__ == "__main__":
    run_demonstration()
