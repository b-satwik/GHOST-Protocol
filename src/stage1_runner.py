"""
Stage 1 Real-Time Orchestrator Runner for DarkWatch GHOST PROTOCOL.
Coordinates Discovery Queue, Source Registry, Whonix Transport, Change Detection,
Link Extraction, and downstream DarkWatch Lab Bridge.
"""

import sys
import os
import time
import datetime
from typing import Dict, Any, List, Optional

# Ensure repository root is in sys.path
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


class Stage1Runner:
    """
    Main orchestrator for Stage 1 Real-Time Source Discovery and Observation Layer.
    Processes mock or live observations through change detection and feeds new unique CTI
    directly into the existing DarkWatch pipeline.
    """

    def __init__(
        self,
        registry_db: str = ":memory:",
        queue_db: str = ":memory:",
        enforce_whonix: bool = False,
        jaccard_threshold: float = 0.80,
        lab_bridge: Optional[DarkWatchLabBridge] = None
    ):
        self.registry = SourceRegistry(db_path=registry_db)
        self.queue = DiscoveryQueue(db_path=queue_db)
        self.transport = WhonixTransport(enforce_fail_closed=enforce_whonix)
        self.change_detector = ChangeDetector(jaccard_threshold=jaccard_threshold)
        self.link_extractor = LinkExtractor()
        self.lab_bridge = lab_bridge or DarkWatchLabBridge()

    def add_initial_source(
        self,
        source_id: str,
        url: str,
        source_type: str = "LOCAL_MOCK",
        discovered_via: str = "INITIAL_SEED"
    ) -> bool:
        """Helper to populate initial seed source in registry."""
        return self.registry.add_source(
            source_id=source_id,
            url=url,
            source_type=source_type,
            discovered_via=discovered_via
        )

    def process_mock_observation(
        self,
        source_id: str,
        url: str,
        raw_html: str = "",
        clean_text: str = "",
        discovered_via: str = "MOCK_FEED"
    ) -> Dict[str, Any]:
        """
        Executes single mock observation through the complete Stage 1 workflow:
        1. Check source registration (register if new)
        2. Perform Change Detection (SHA-256 + MinHash)
        3. Extract newly discovered links and enqueue them
        4. If content changed/new: Send ObservationRecord downstream to lab_bridge
        5. Return execution summary result
        """
        # Ensure URL is canonicalized
        canonical_url = self.registry.canonicalize_url(url)

        # 1. Register source if missing
        existing = self.registry.get_source_by_url(canonical_url)
        if not existing:
            self.registry.add_source(
                source_id=source_id,
                url=canonical_url,
                source_type="LOCAL_MOCK",
                discovered_via=discovered_via
            )

        # 2. Change Detection
        state, raw_sha, clean_sha, dedup_meta = self.change_detector.evaluate_change(
            source_id=source_id,
            raw_html=raw_html,
            clean_text=clean_text
        )

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        obs_status = "CONTENT_ACCESSIBLE" if clean_text else "EMPTY_CONTENT"

        # Update registry state
        self.registry.update_source_observation(
            source_id=source_id,
            status=obs_status,
            raw_html_sha256=raw_sha,
            clean_text_sha256=clean_sha
        )

        # 3. Link Extraction & Enqueueing
        extracted_links = self.link_extractor.extract_links(clean_text or raw_html)
        enqueued_count = 0
        for link in extracted_links:
            inserted = self.queue.enqueue(
                url=link,
                discovered_via=f"LINK_HOPPING_{source_id}",
                parent_source_url=canonical_url
            )
            if inserted:
                enqueued_count += 1

        # 4. Downstream Dispatch (Only if content is changed or unique)
        bridge_result = None
        if state in (ChangeDetector.STATE_CHANGED_UNIQUE, ChangeDetector.STATE_CHANGED_NEAR_DUPLICATE):
            obs_record = ObservationRecord(
                source_id=source_id,
                url=canonical_url,
                timestamp=now_iso,
                status=obs_status,
                raw_sha256=raw_sha,
                clean_sha256=clean_sha,
                discovery_provenance={"discovered_via": discovered_via, "state": state},
                raw_html=raw_html,
                clean_text=clean_text,
                metadata=dedup_meta
            )
            bridge_result = self.lab_bridge.process_stage1_observation(obs_record)

        return {
            "source_id": source_id,
            "url": canonical_url,
            "change_state": state,
            "raw_sha256": raw_sha,
            "clean_sha256": clean_sha,
            "extracted_links_count": len(extracted_links),
            "newly_enqueued_links": enqueued_count,
            "dispatched_to_bridge": bridge_result is not None,
            "bridge_output": bridge_result
        }
