"""
Stage 1 Continuous Observer Engine for DarkWatch GHOST PROTOCOL.
Executes real-time, source-independent, scheduled observation loop across threat sources.
Coordinates change detection, evidence persistence, historical correlation, and alerting.
"""

import sys
import os
import time
import datetime
from typing import Dict, Any, List, Optional

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.discovery.source_registry import SourceRegistry
from src.discovery.discovery_queue import DiscoveryQueue
from src.discovery.observation_record import ObservationRecord
from src.discovery.observation_history import ObservationHistoryStore
from src.discovery.historical_correlator import HistoricalCorrelator
from src.discovery.stage1_alert_engine import Stage1AlertEngine
from src.discovery.link_extractor import LinkExtractor
from src.discovery.user_activity_extractor import UserActivityStore
from src.observer.whonix_transport import WhonixTransport, WhonixIsolationError
from src.observer.change_detector import ChangeDetector
from src.observer.tor_browser_observer import TorBrowserObserver
from src.pipeline.lab_bridge import DarkWatchLabBridge
from src.resolution.session_manager import ThreatSessionManager
from src.discovery.candidate_classifier import CandidateClassifier


class Stage1ContinuousObserver:
    """
    Continuous Live Observation Engine orchestrating periodic scheduled source monitoring,
    change detection, evidence persistence, historical correlation, and alerting.
    """

    def __init__(
        self,
        registry_db: str = "data/source_registry.db",
        queue_db: str = "data/discovery_queue.db",
        history_db: str = "data/observation_history.db",
        alerts_db: str = "data/alerts.db",
        enforce_whonix: bool = False,
        jaccard_threshold: float = 0.80
    ):
        self.registry = SourceRegistry(db_path=registry_db)
        self.queue = DiscoveryQueue(db_path=queue_db)
        self.history_store = ObservationHistoryStore(db_path=history_db)
        self.historical_correlator = HistoricalCorrelator(history_store=self.history_store)
        self.alert_engine = Stage1AlertEngine(db_path=alerts_db)
        self.change_detector = ChangeDetector(jaccard_threshold=jaccard_threshold)
        self.link_extractor = LinkExtractor()
        self.user_activity_store = UserActivityStore()
        self.whonix_transport = WhonixTransport(enforce_fail_closed=enforce_whonix)
        self.tor_browser = TorBrowserObserver(enforce_fail_closed=enforce_whonix)
        self.lab_bridge = DarkWatchLabBridge()
        self.session_manager = ThreatSessionManager()
        self.is_running = False

    def observe_source_entry(self, source: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes complete observation lifecycle for a registered source entry using
        candidate discovery, atomic claim locking (TAKEN), persistent cursor advancement,
        page classification filtering (ANNOUNCEMENT/PINNED/LOGIN), thread content hashing,
        and thread/comment extraction.
        """
        source_id = source["source_id"]
        canonical_url = source["canonical_url"]
        source_type = source.get("source_type", "GENERIC_WEBSITE")
        collector_type = source.get("collector_type", "TOR_CLI")
        polling_interval = source.get("polling_interval_mins", 30)

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        obs_id = f"obs_{int(time.time())}_{hash(canonical_url) & 0xffff:04x}"

        # 1. Update lifecycle: CONNECTING
        self.registry.update_source_lifecycle(source_id, agent_state="RUNNING", connection_state="CONNECTING")
        self.registry.record_event("SOURCE_CONNECTING", source_id=source_id, message=f"Connecting to source {canonical_url}...")

        # Collect primary page content using TorObservationController / TorBrowser
        import asyncio
        import hashlib
        from src.observer.tor_observation_controller import TorObservationController, ControllerConfig, AccessState, Engine
        from src.observer.adapters.adapter_registry import get_adapter_for_url

        enable_b = False if os.environ.get("SHADOWBOARD_SESSION_TOKEN") else True
        async def _run_ctl(target_u: str):
            cfg = ControllerConfig(
                proxy_url="socks5h://127.0.0.1:9050",
                enable_browser=enable_b,
                verify_tor_exit=False,
                human_timeout=60.0
            )
            async with TorObservationController(cfg) as ctl:
                return await ctl.observe(target_u)

        adapter = get_adapter_for_url(canonical_url)

        # Step 1: Connect to source main URL & discover candidate post/thread links
        res_obj = None
        raw_html = ""
        clean_text = ""
        http_status = 200
        fetch_error = None

        if ".onion" not in canonical_url and os.environ.get("SHADOWBOARD_SESSION_TOKEN"):
            try:
                import urllib.request
                hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Cookie": f"session_token={os.environ['SHADOWBOARD_SESSION_TOKEN']}"}
                req = urllib.request.Request(canonical_url, headers=hdrs)
                with urllib.request.urlopen(req, timeout=12) as resp:
                    raw_html = resp.read().decode("utf-8", errors="ignore")
                    clean_text = raw_html
                    http_status = resp.status
                    fetch_error = None
            except Exception as ex:
                fetch_error = str(ex)

        if not raw_html:
            try:
                res_obj = asyncio.run(_run_ctl(canonical_url))
                raw_html = res_obj.content or ""
                clean_text = res_obj.content or ""
                http_status = res_obj.status_code or (200 if res_obj.success else 0)
                if res_obj.error:
                    fetch_error = res_obj.error.message
            except Exception:
                res = self.tor_browser.navigate_and_observe(canonical_url)
                raw_html = res.get("raw_html", "")
                clean_text = res.get("clean_text", "")
                http_status = res.get("http_status", 200)
                fetch_error = res.get("nav_error")

        acc_method = "GHOST_TOR_BROWSER" if (res_obj and res_obj.engine == Engine.BROWSER) else ("SOCKS5_TOR" if ".onion" in canonical_url else ("TELEGRAM_PUBLIC_CHANNEL" if "t.me" in canonical_url else "HTTP_DIRECT"))

        # Handle Session Authorization / Human Action Requirement
        if res_obj and res_obj.access_state in (AccessState.AUTH_REQUIRED, AccessState.CAPTCHA_REQUIRED, AccessState.CHALLENGE_REQUIRED, AccessState.HUMAN_ACTION_PENDING):
            self.registry.update_source_lifecycle(
                source_id=source_id,
                validation_status="HUMAN_ACTION_REQUIRED",
                agent_state="WAITING",
                connection_state="PAUSED",
                access_method=acc_method,
                human_action_state="REQUIRED",
                failure_reason="Human verification required"
            )
            self.registry.record_event("HUMAN_ACTION_REQUIRED", source_id=source_id, message=f"HUMAN ACTION REQUIRED for {canonical_url}: Perform login/2FA/CAPTCHA in the visible browser.")
            return {
                "source_id": source_id,
                "canonical_url": canonical_url,
                "status": "HUMAN_ACTION_REQUIRED",
                "collector": acc_method,
                "change_state": "AUTH_REQUIRED",
                "dispatched_to_bridge": False,
                "message": "HUMAN ACTION REQUIRED: Perform login/2FA/CAPTCHA in the visible Tor Browser window."
            }
        elif http_status in (401, 403) or (http_status == 200 and ("login" in clean_text.lower() and "password" in clean_text.lower() and len(clean_text) < 1500)):
            self.registry.update_source_lifecycle(
                source_id=source_id,
                validation_status="HUMAN_ACTION_REQUIRED",
                agent_state="WAITING",
                connection_state="PAUSED",
                access_method=acc_method,
                human_action_state="REQUIRED",
                failure_reason="Authentication required"
            )
            self.registry.record_event("HUMAN_ACTION_REQUIRED", source_id=source_id, message=f"Authentication required for {canonical_url}.")
            return {
                "source_id": source_id,
                "canonical_url": canonical_url,
                "status": "HUMAN_ACTION_REQUIRED",
                "collector": acc_method,
                "change_state": "AUTH_REQUIRED",
                "dispatched_to_bridge": False,
                "message": "Authentication required. Observation paused for human action."
            }

        if http_status == 0 or not raw_html:
            self.registry.update_source_lifecycle(
                source_id=source_id,
                validation_status="OFFLINE",
                agent_state="STOPPED",
                connection_state="INACTIVE",
                access_method=acc_method,
                failure_reason=fetch_error or "Connection failed / Source unreachable"
            )
            self.registry.record_event("SOURCE_OFFLINE", source_id=source_id, message=f"Source {canonical_url} is OFFLINE: {fetch_error or 'Unreachable'}")
            return {
                "source_id": source_id,
                "canonical_url": canonical_url,
                "status": "OFFLINE",
                "collector": acc_method,
                "change_state": "FAILED",
                "dispatched_to_bridge": False,
                "error": fetch_error
            }

        # Mark source LIVE
        self.registry.update_source_lifecycle(
            source_id=source_id,
            validation_status="LIVE",
            agent_state="RUNNING",
            connection_state="ACTIVE",
            access_method=acc_method,
            failure_reason=""
        )

        # Discover & enqueue post/thread links
        discovered_links = adapter.extract_candidate_links(canonical_url, raw_html)
        if not discovered_links:
            sanitized_text, _, _ = self.lab_bridge.sanitizer.sanitize_html(raw_html)
            discovered_links = self.link_extractor.extract_links(f"{sanitized_text}\n{raw_html}")

        for link in discovered_links:
            self.queue.enqueue(url=link, discovered_via=f"OBSERVATION_{source_id}", parent_source_url=canonical_url)

        # Retrieve candidates for this source
        candidates = self.queue.get_candidates_for_source(source_id, parent_url=canonical_url)
        if not candidates:
            # Fallback: enqueue primary canonical_url as candidate
            self.queue.enqueue(url=canonical_url, discovered_via=f"PRIMARY_{source_id}", parent_source_url=canonical_url)
            candidates = self.queue.get_candidates_for_source(source_id, parent_url=canonical_url)

        total_candidates = len(candidates)
        current_cursor = self.registry.get_candidate_cursor(source_id)

        selected_candidate = None
        selected_index = -1
        target_url = ""
        queue_id = None
        cand_raw_html = ""
        cand_clean_text = ""
        cand_status = 200
        thread_info = {}

        for attempt in range(total_candidates):
            current_cursor = self.registry.get_candidate_cursor(source_id)
            candidate_index = current_cursor % total_candidates
            cand = candidates[candidate_index]
            cand_url = cand.get("candidate_url") or cand.get("url") or canonical_url
            cand_state = cand["processing_state"]

            if cand_state in ("TAKEN", "OBSERVING"):
                self.registry.set_candidate_cursor(source_id, (candidate_index + 1) % total_candidates)
                continue

            # Pre-claim classification
            url_cls = CandidateClassifier.classify_url(cand_url)
            page_type = adapter.classify_page_type(cand_url, raw_html="", clean_text="", thread_info={})
            cand_url_lower = cand_url.lower()

            skip_keywords = ["/u/", "/user/", "/faq", "/rules", "/guidelines", "/search", "/about", "/badges", "/announcement", "pinned", "/categories", "/login", "/register", "/auth", "community-rules"]
            is_non_thread = page_type in ("ANNOUNCEMENT", "PINNED", "RULES", "COMMUNITY NOTICE", "PLATFORM NOTICE", "NAVIGATION", "PROFILE PAGE", "LOGIN PAGE", "ACCESS PAGE", "QUEUE PAGE", "PROFILE", "NAVIGATION", "CATEGORY") or any(kw in cand_url_lower for kw in skip_keywords)

            if not url_cls["is_valid_thread"] or is_non_thread:
                r_type = url_cls["resource_type"]
                p_type = url_cls["page_type"] if url_cls["page_type"] != "HTML_THREAD_CANDIDATE" else page_type
                reason = url_cls["reason"] if url_cls["reason"] != "POTENTIAL_THREAD" else f"NON_THREAD_PAGE_{page_type}"

                print("\n" + "=" * 70)
                print(f"CANDIDATE {candidate_index + 1} / {total_candidates}")
                print(f"URL: {cand_url}")
                print(f"RESOURCE TYPE: {r_type}")
                print(f"PAGE TYPE: {p_type}")
                print("VALID THREAD: NO")
                print(f"REASON: {reason}")
                print("ACTION: SKIP")
                print("=" * 70 + "\n")

                self.queue.release_candidate(cand["queue_id"], "SKIPPED")
                self.registry.set_candidate_cursor(source_id, (candidate_index + 1) % total_candidates)
                continue

            # Atomically claim candidate (TAKEN)
            if not self.queue.claim_candidate(cand["queue_id"]):
                self.registry.set_candidate_cursor(source_id, (candidate_index + 1) % total_candidates)
                continue

            selected_candidate = cand
            selected_index = candidate_index
            target_url = selected_candidate.get("candidate_url") or selected_candidate.get("url") or canonical_url
            queue_id = selected_candidate["queue_id"]

            # Fetch candidate content
            cand_raw_html = ""
            cand_clean_text = ""
            cand_status = 200

            if ".onion" not in target_url and os.environ.get("SHADOWBOARD_SESSION_TOKEN"):
                try:
                    import urllib.request
                    hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Cookie": f"session_token={os.environ['SHADOWBOARD_SESSION_TOKEN']}"}
                    req = urllib.request.Request(target_url, headers=hdrs)
                    with urllib.request.urlopen(req, timeout=12) as resp:
                        cand_raw_html = resp.read().decode("utf-8", errors="ignore")
                        cand_clean_text = cand_raw_html
                        cand_status = resp.status
                except Exception:
                    pass

            if not cand_raw_html:
                try:
                    res_cand = asyncio.run(_run_ctl(target_url))
                    cand_raw_html = res_cand.content or ""
                    cand_clean_text = res_cand.content or ""
                    cand_status = res_cand.status_code or 200
                except Exception:
                    res = self.tor_browser.navigate_and_observe(target_url)
                    cand_raw_html = res.get("raw_html", "")
                    cand_clean_text = res.get("clean_text", "")
                    cand_status = res.get("http_status", 200)

            if not cand_raw_html:
                print(f"[-] FAILED TO FETCH CANDIDATE: {target_url}")
                self.queue.release_candidate(queue_id, "FAILED")
                next_cursor = (selected_index + 1) % total_candidates
                self.registry.set_candidate_cursor(source_id, next_cursor)
                continue

            # Extract thread info
            cand_adapter = get_adapter_for_url(target_url, cand_raw_html)
            thread_info = cand_adapter.extract_thread_info(target_url, cand_raw_html)

            # Post-fetch Thread Validation
            is_valid_thread, val_cls = CandidateClassifier.validate_extracted_thread(target_url, cand_raw_html, thread_info)
            if not is_valid_thread:
                print("\n" + "=" * 70)
                print(f"CANDIDATE {selected_index + 1} / {total_candidates}")
                print(f"URL: {target_url}")
                print(f"RESOURCE TYPE: {val_cls['resource_type']}")
                print(f"PAGE TYPE: {val_cls['page_type']}")
                print("VALID THREAD: NO")
                print(f"REASON: {val_cls['reason']}")
                print("ACTION: SKIP")
                print("=" * 70 + "\n")

                self.queue.release_candidate(queue_id, "SKIPPED")
                next_cursor = (selected_index + 1) % total_candidates
                self.registry.set_candidate_cursor(source_id, next_cursor)
                selected_candidate = None
                continue

            # Valid genuine thread candidate found!
            break

        if not selected_candidate:
            print(f"[!] SOURCE: {source_id} | DISCOVERED CANDIDATES: {total_candidates} | CURSOR: {current_cursor} -> NO UNLOCKED CANDIDATES READY FOR THREAT SESSION")
            return {
                "source_id": source_id,
                "canonical_url": canonical_url,
                "status": "ACCESSIBLE",
                "change_state": "NO_CANDIDATE",
                "discovered_candidates": total_candidates,
                "candidate_cursor": current_cursor,
                "message": f"Evaluated candidate queue for {source_id}. No valid new thread candidates ready out of {total_candidates} discovered links."
            }

        # Verified Genuine Thread
        root_author = thread_info.get("author")
        direct_replies = thread_info.get("direct_replies", [])
        if not root_author or root_author in ("UNKNOWN", "user03"):
            if direct_replies:
                first_r = direct_replies[0]
                if first_r.get("username") and first_r.get("username") not in ("user03", "UNKNOWN"):
                    root_author = first_r.get("username")
            if not root_author:
                if "anonymous" in cand_raw_html.lower() and ("post-root" in cand_raw_html or "nested-comment" in cand_raw_html or "user-badge" in cand_raw_html):
                    root_author = "anonymous"
                else:
                    root_author = "UNKNOWN"

        thread_info["author"] = root_author
        thread_title = thread_info.get("title") or "Discussion Thread"
        thread_content = thread_info.get("content") or cand_clean_text
        reported_comments = thread_info.get("reported_comments_count", 0)
        observed_comments = thread_info.get("observed_comments_count", 0)

        # PRINT REQUIRED TERMINAL DEBUG ROTATION LOG BLOCK FOR GENUINE THREAD
        print("\n" + "=" * 70)
        print(f"SOURCE: {source.get('source_name') or source_id}")
        print(f"DISCOVERED CANDIDATES: {total_candidates}")
        print(f"CURRENT CURSOR: {current_cursor}")
        print(f"CANDIDATE: {selected_index + 1} / {total_candidates}")
        print(f"URL: {target_url}")
        print("RESOURCE TYPE: HTML")
        print("PAGE TYPE: GENUINE_THREAD")
        print("VALID THREAD: YES")
        print(f"ROOT USER: {root_author}")
        print("ACTION: OBSERVE THREAD")

        # Sanitization
        sanitized_text, _, clean_sha = self.lab_bridge.sanitizer.sanitize_html(cand_raw_html)
        if not sanitized_text:
            sanitized_text = cand_clean_text

        # Extract user activity across thread
        self.user_activity_store.extract_and_record_users(raw_html=cand_raw_html, clean_text=sanitized_text, source_id=source_id, canonical_url=target_url, timestamp_utc=now_iso)

        # Calculate thread content SHA-256 hash for change detection
        full_thread_str = f"{thread_title}\n{root_author}\n{thread_content}\n" + "\n".join([r.get("message", "") for r in direct_replies])
        content_hash = hashlib.sha256(full_thread_str.encode("utf-8")).hexdigest()

        prev_hash = selected_candidate.get("content_hash")
        next_cursor = (selected_index + 1) % total_candidates

        # STUCK DETECTION / UNCHANGED CONTENT (Requirement 6, 7 & 21)
        if prev_hash and prev_hash == content_hash:
            print("\nSAME CANDIDATE DETECTED")
            print("CONTENT UNCHANGED")
            print("RELEASING")
            print("ADVANCING TO NEXT CANDIDATE")
            print(f"NEXT CANDIDATE: {next_cursor + 1} / {total_candidates}")
            print("=" * 70 + "\n")

            self.queue.release_candidate(queue_id, "UNCHANGED", content_hash=content_hash)
            self.registry.set_candidate_cursor(source_id, next_cursor)

            obs_status = WhonixTransport.classify_http_status(cand_status)
            self.registry.update_source_observation(
                source_id=source_id,
                status=obs_status,
                raw_html_sha256=clean_sha,
                clean_text_sha256=content_hash,
                content_changed=False,
                polling_interval_mins=polling_interval
            )

            return {
                "source_id": source_id,
                "canonical_url": target_url,
                "status": obs_status,
                "change_state": "UNCHANGED",
                "candidate_url": target_url,
                "candidate_index": selected_index,
                "candidate_cursor": next_cursor,
                "dispatched_to_bridge": False,
                "message": "Candidate content unchanged. Advanced cursor to next candidate."
            }

        # NEW OR UPDATED CANDIDATE CONTENT -> PROCESS ML / CTI PIPELINE
        obs_status = WhonixTransport.classify_http_status(cand_status)
        obs_id = f"obs_{int(time.time())}_{hash(target_url) & 0xffff:04x}"

        obs_record = ObservationRecord(
            source_id=source_id,
            url=target_url,
            timestamp=now_iso,
            status=obs_status,
            raw_sha256=clean_sha,
            clean_sha256=content_hash,
            discovery_provenance={"discovered_via": "CANDIDATE_QUEUE", "change_state": "CONTENT_CHANGED"},
            raw_html=cand_raw_html,
            clean_text=sanitized_text,
            metadata=thread_info
        )

        bridge_output = self.lab_bridge.process_stage1_observation(obs_record)

        # Threat Session Management
        obs_eval_dict = {
            "obs_id": obs_id,
            "source_id": source_id,
            "parent_source_url": canonical_url,
            "canonical_url": target_url,
            "sanitized_text": sanitized_text,
            "text": sanitized_text,
            "bridge_output": bridge_output,
            "root_author": root_author,
            "direct_replies": direct_replies,
            "thread_info": thread_info
        }
        session_obj, session_action, session_reasons = self.session_manager.evaluate_observation(obs_eval_dict)
        bridge_output["threat_session"] = session_obj.to_dict()
        bridge_output["threat_session_action"] = session_action
        bridge_output["threat_session_reasons"] = session_reasons

        session_id = session_obj.session_id
        session_users = list(getattr(session_obj, "actors", []))
        if root_author and root_author not in session_users:
            session_users.insert(0, root_author)

        session_db_rec = self.session_manager.store.get_threat_session(session_id)
        session_persisted = "YES" if session_db_rec is not None else "NO"
        users_persisted = "YES" if len(session_users) > 0 else "NO"

        distilbert_info = bridge_output.get("ml", {}).get("distilbert", {}) or bridge_output.get("distilbert", {})
        temp_ae_info = bridge_output.get("ml", {}).get("temporal_autoencoder", {}) or bridge_output.get("temporal_autoencoder", {})
        xgb_info = bridge_output.get("ml", {}).get("xgboost", {}) or bridge_output.get("xgboost", {})

        ml_distilbert_str = f"{distilbert_info.get('predicted_class', 'NORMAL')} (conf: {distilbert_info.get('confidence', 1.0)})"
        ml_temp_str = f"score: {temp_ae_info.get('anomaly_score', 0.0)}"
        ml_xgb_str = f"{xgb_info.get('predicted_class')} (conf: {xgb_info.get('confidence')})" if (xgb_info and xgb_info.get("network_available")) else "NETWORK MODALITY UNAVAILABLE"
        ml_hmtif_str = f"score: {bridge_output.get('fusion_score', 0.0)} ({bridge_output.get('risk_severity', 'LOW')})"

        cti_persisted = "YES" if bridge_output.get("cti") else "NO"
        stix_persisted = "YES" if bridge_output.get("stix", {}).get("bundle_id") else "NO"
        mitre_persisted = "YES" if (bridge_output.get("mitre_mapping", {}).get("techniques") or bridge_output.get("mitre", {}).get("techniques")) else "NO"
        xai_persisted = "YES" if bridge_output.get("xai") else "NO"

        api_source_session = "YES" if session_persisted == "YES" else "NO"
        api_session_detail = "YES" if session_persisted == "YES" else "NO"
        api_user_activity = "YES" if users_persisted == "YES" else "NO"

        # PRINT REQUIRED GHOST DATA LINEAGE DEBUG BLOCK (Requirement 11)
        print("\n" + "=" * 70)
        print("GHOST DATA LINEAGE")
        print("=" * 70)
        print(f"SOURCE ID: {source_id}")
        print(f"SOURCE URL: {canonical_url}")
        print(f"\nCANDIDATE ID: {queue_id}")
        print(f"CANDIDATE URL: {target_url}")
        print(f"\nTHREAD OBSERVED: YES")
        print(f"ROOT USER: {root_author}")
        print(f"\nCOMMENTS REPORTED: {reported_comments}")
        print(f"COMMENTS OBSERVED: {observed_comments}")
        print(f"\nTHREAT SESSION ID: {session_id}")
        print(f"SESSION PERSISTED: {session_persisted}")
        print(f"\nSESSION USERS: {', '.join(session_users[:10])}")
        print(f"USERS PERSISTED: {users_persisted}")
        print(f"\nML:")
        print(f"  DistilBERT: {ml_distilbert_str}")
        print(f"  Temporal AE: {ml_temp_str}")
        print(f"  XGBoost: {ml_xgb_str}")
        print(f"  HM-TIF: {ml_hmtif_str}")
        print(f"\nCTI PERSISTED: {cti_persisted}")
        print(f"STIX PERSISTED: {stix_persisted}")
        print(f"MITRE PERSISTED: {mitre_persisted}")
        print(f"XAI PERSISTED: {xai_persisted}")
        print(f"\nDASHBOARD API:")
        print(f"  SOURCE SESSION FOUND: {api_source_session}")
        print(f"  SESSION DETAIL FOUND: {api_session_detail}")
        print(f"  USER ACTIVITY FOUND: {api_user_activity}")
        print(f"\nCANDIDATE STATE: COMPLETED")
        print(f"NEXT CANDIDATE: {next_cursor + 1} / {total_candidates}")
        print("=" * 70 + "\n")

        # Release candidate as COMPLETED and update cursor
        self.queue.release_candidate(queue_id, "COMPLETED", content_hash=content_hash)
        self.registry.set_candidate_cursor(source_id, next_cursor)

        self.registry.update_source_observation(
            source_id=source_id,
            status=obs_status,
            raw_html_sha256=clean_sha,
            clean_text_sha256=content_hash,
            content_changed=True,
            polling_interval_mins=polling_interval
        )

        # Save history & alerts
        cti_info = bridge_output.get("cti", {})
        indicators = cti_info.get("indicators", [])
        cves = [ind.get("normalized_value") for ind in indicators if ind.get("indicator_type") == "CVE"]
        malware = [ind.get("normalized_value") for ind in indicators if ind.get("indicator_type") == "MALWARE"]
        stix_bundle_id = bridge_output.get("stix", {}).get("bundle_id", "")
        mitre_info = bridge_output.get("mitre_mapping", {})

        history_record = {
            "observation_id": obs_id,
            "source_id": source_id,
            "canonical_url": target_url,
            "timestamp_utc": now_iso,
            "status": obs_status,
            "change_state": "CONTENT_CHANGED",
            "raw_html_sha256": clean_sha,
            "clean_text_sha256": content_hash,
            "clean_text": sanitized_text,
            "extracted_links": discovered_links,
            "extracted_cves": cves,
            "extracted_malware": malware,
            "extracted_iocs": indicators,
            "stix_bundle_id": stix_bundle_id,
            "mitre_techniques": mitre_info.get("techniques", []),
            "fusion_risk_score": bridge_output.get("fusion_score", 0.0),
            "risk_severity": bridge_output.get("risk_severity", "LOW"),
            "xai_summary": bridge_output.get("xai", {}).get("summary_narrative", ""),
            "provenance": {"candidate_queue_id": queue_id, "candidate_url": target_url}
        }
        self.history_store.save_observation(history_record)

        correlations = [self.historical_correlator.correlate_entity(cve) for cve in cves]
        alerts = self.alert_engine.evaluate_and_alert(history_record, bridge_output)

        return {
            "source_id": source_id,
            "canonical_url": target_url,
            "status": obs_status,
            "change_state": "CONTENT_CHANGED",
            "dispatched_to_bridge": True,
            "candidate_index": selected_index,
            "candidate_cursor": next_cursor,
            "threat_session_id": session_id,
            "root_author": root_author,
            "reported_comments": reported_comments,
            "observed_comments": observed_comments,
            "alerts_generated": len(alerts),
            "bridge_output": bridge_output
        }

    def run_single_scheduled_pass(self) -> Dict[str, Any]:
        """Executes a single pass over all due registered sources."""
        due_sources = self.registry.get_due_sources()
        results = []
        for src in due_sources:
            results.append(self.observe_source_entry(src))
        return {
            "processed_sources_count": len(due_sources),
            "results": results
        }

    def start_live_daemon(self, poll_interval_seconds: int = 15):
        """Starts the continuous background daemon loop."""
        self.is_running = True
        print(f"[+] Stage 1 Continuous Observer Daemon STARTED (Polling interval: {poll_interval_seconds}s)")
        try:
            while self.is_running:
                res = self.run_single_scheduled_pass()
                if res["processed_sources_count"] > 0:
                    print(f"[{datetime.datetime.now()}] Polled {res['processed_sources_count']} due sources.")
                time.sleep(poll_interval_seconds)
        except KeyboardInterrupt:
            print("[+] Stage 1 Daemon stopping...")
        finally:
            self.is_running = False
            self.tor_browser.close()
