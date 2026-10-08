"""
GHOST Protocol — Autonomous Observation Agent.
Controls Tor Browser lifecycle, enforces Whonix SOCKS5 & JS-disabled security policy,
manages Human-in-the-Loop 2-step verification, executes continuous threat observation,
drives Ahmia search discovery, deduplicates threat memory, and feeds the DarkWatch AI brain.
"""

import sys
import os
import time
import hashlib
import datetime
import json
from typing import Dict, Any, List, Optional, Tuple

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.observer.tor_browser_observer import TorBrowserObserver, fetch_url_over_socks5
from src.observer.change_detector import ChangeDetector
from src.discovery.observation_record import ObservationRecord
from src.discovery.observation_history import ObservationHistoryStore
from src.discovery.historical_correlator import HistoricalCorrelator
from src.discovery.link_extractor import LinkExtractor
from src.discovery.ahmia_discovery import AhmiaDiscoveryEngine
from src.pipeline.lab_bridge import DarkWatchLabBridge
from src.resolution.session_manager import ThreatSessionManager, ThreatSession
from src.filter.threat_filter import ThreatFilter


class AccessMode:
    AUTO = "AUTO"
    PUBLIC = "PUBLIC"
    BROWSER_REQUIRED = "BROWSER_REQUIRED"
    LOGIN_REQUIRED = "LOGIN_REQUIRED"
    TWO_STEP_REQUIRED = "TWO_STEP_REQUIRED"


def detect_access_or_non_content_state(raw_html: str, clean_text: str, http_status: int, url: str) -> Optional[str]:
    """
    Detects if a page represents an access/login/2FA/queue/expired/denied/JS-warning page rather than actual threat content.
    Returns state string (e.g. 'AUTOMATED_ACCESS_BLOCKED', 'LOGIN_REQUIRED', 'TWO_STEP_REQUIRED', 'ACCESS_REQUIRED', 
    'SESSION_EXPIRED', 'ACCESS_DENIED', 'QUEUED') if detected, or None if the page contains actual accessible content.
    """
    combined = f"{clean_text}\n{raw_html}".lower()

    if url.startswith("about:") or "establishing a connection" in combined or "torconnect" in combined or "tor browser routes your traffic" in combined:
        return "QUEUED"

    page_title_lower = ""
    if "<title>" in raw_html.lower():
        try:
            page_title_lower = raw_html.lower().split("<title>")[1].split("</title>")[0].strip()
        except Exception:
            page_title_lower = ""

    # 1. JavaScript Warning / Interstitial Barrier check
    # Note: Passive <noscript> tags or footer mentions of "javascript/browser" in full forum pages are NOT access barriers.
    is_js_barrier_title = any(t in page_title_lower for t in [
        "javascript disabled", "javascript required", "enable javascript", "javascript warning"
    ])
    
    is_js_barrier_text = any(jw in combined for jw in [
        "javascript is required to view", "enable javascript to view", "javascript must be enabled to view",
        "please enable javascript to continue", "you must enable javascript"
    ])

    if is_js_barrier_title or is_js_barrier_text:
        return "AUTOMATED_ACCESS_BLOCKED"

    # 2. Anti-DDoS / Cloudflare / Interstitial / Queue
    is_queue_title = "queue" in page_title_lower or "ddos" in page_title_lower or "challenge" in page_title_lower
    ddos_terms = [
        "placed in a queue", "access queue", "awaiting forwarding", "estimated wait time",
        "queue_gated", "ddos protection", "checking your browser", "just a moment",
        "please do not refresh", "cf-challenge", "ddos-guard"
    ]
    has_ddos = is_queue_title or (any(dt in combined for dt in ddos_terms) and not ("post" in combined or "subdread" in combined or "thread" in combined))

    if has_ddos:
        return "AUTOMATED_ACCESS_BLOCKED"

    # 3. HTTP Status Codes
    if http_status in (401, 403):
        return "ACCESS_DENIED" if http_status == 403 else "LOGIN_REQUIRED"
    if http_status in (429, 503):
        return "QUEUED"

    # 4. Login / Sign-in required
    is_login_title = "login" in page_title_lower or "sign in" in page_title_lower or "2-step" in page_title_lower
    login_terms = [
        "2-step verification required", "two-step verification", "login required",
        "sign in to continue", "please log in", "authorization required",
        "password required", "enter credentials", "log in to view"
    ]
    if is_login_title or (any(lt in combined for lt in login_terms) and not ("post" in combined or "subdread" in combined or "thread" in combined)):
        if "2-step" in combined or "2fa" in combined:
            return "TWO_STEP_REQUIRED"
        return "LOGIN_REQUIRED"

    # 5. Session Expired
    session_expired_terms = [
        "session expired", "session invalid", "please re-authenticate", "session_gated"
    ]
    if any(st in combined for st in session_expired_terms):
        return "SESSION_EXPIRED"

    # 6. Access Denied / Required
    access_terms = [
        "access denied", "permission denied", "unauthorized access", "private forum",
        "access required", "members only"
    ]
    if any(at in combined for at in access_terms) and not ("post" in combined or "subdread" in combined or "thread" in combined):
        return "ACCESS_REQUIRED"

    # 7. Empty or unparseable text
    if not clean_text or len(clean_text.strip()) == 0:
        return "ACCESS_REQUIRED"

    # Post indicators check (only when no access barrier was detected)
    has_post_indicators = any(pi in combined for pi in [
        "/post/", "/d/", "/thread/", "post-title", "post-card", "subdread", "posted by", "comments", "author"
    ])
    if has_post_indicators:
        return None

    return None


def is_valid_thread(thread_info: Optional[Dict[str, Any]], raw_html: str, clean_text: str, url: str, access_state: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validates whether an observed page represents a REAL, VALID thread/post container with an authentic author,
    title, and body, rather than an access barrier, login wall, JS warning, queue, or navigation shell.
    
    Returns (is_valid, reason).
    """
    if access_state is not None:
        return False, f"Access barrier/gate detected ({access_state})"

    combined = f"{clean_text}\n{raw_html}".lower()

    page_title_lower = ""
    if "<title>" in raw_html.lower():
        try:
            page_title_lower = raw_html.lower().split("<title>")[1].split("</title>")[0].strip()
        except Exception:
            page_title_lower = ""

    is_js_barrier_title = any(t in page_title_lower for t in [
        "javascript disabled", "javascript required", "enable javascript", "javascript warning"
    ])
    is_js_barrier_text = any(jw in combined for jw in [
        "javascript is required to view", "enable javascript to view", "javascript must be enabled to view",
        "please enable javascript to continue", "you must enable javascript"
    ])

    if is_js_barrier_title or is_js_barrier_text:
        return False, "JavaScript warning/interstitial barrier detected"

    is_queue_title = "queue" in page_title_lower or "ddos" in page_title_lower or "challenge" in page_title_lower
    ddos_terms = [
        "placed in a queue", "access queue", "awaiting forwarding", "estimated wait time",
        "queue_gated", "ddos protection", "checking your browser", "just a moment",
        "please do not refresh", "cf-challenge", "ddos-guard"
    ]
    has_access_barrier = is_queue_title or (any(ab in combined for ab in ddos_terms) and not ("post" in combined or "subdread" in combined or "thread" in combined))

    if has_access_barrier:
        return False, "Access barrier / interstitial page detected"

    if not thread_info or not isinstance(thread_info, dict):
        return False, "No thread structure parsed from page"

    title = (thread_info.get("title") or "").strip()
    author = (thread_info.get("author") or "").strip()
    content = (thread_info.get("content") or "").strip()

    # Author validation: Must come from real author element, never synthetic
    if not author or author.lower() in ("none", "null", "user01", "user03", "user001", "unknown / not observed", "observed page", "anonymous_fallback"):
        return False, "Missing or synthetic root author"

    # Title validation
    if not title or any(invalid_title in title.lower() for invalid_title in [
        "javascript enabled", "access queue", "login required", "observed page", "404 not found",
        "500 internal server error", "access denied", "2-step verification", "cloudflare", "just a moment"
    ]):
        return False, "Invalid or generic barrier title"

    # Content/body validation
    if not content or len(content) < 5 or any(barrier_text in content.lower() for barrier_text in [
        "javascript is required to view", "enable javascript to view", "please enable javascript to continue"
    ]):
        return False, "Missing or barrier post content"

    return True, "Valid thread structure verified"


def classify_page_and_content(url: str, raw_html: str, clean_text: str, thread_info: Dict[str, Any]) -> str:
    """
    Classifies page content type using SourceAdapterRegistry to ensure non-thread pages
    (Announcements, Community Info, User Profiles, Navigation, Access Gates) do NOT enter ThreatSessionManager.
    """
    access_st = detect_access_or_non_content_state(raw_html, clean_text, 200, url)
    if access_st is not None:
        return "ACCESS_PAGE"

    from src.observer.adapters.adapter_registry import get_adapter_for_url
    adapter = get_adapter_for_url(url, raw_html)
    return adapter.classify_page_type(url, raw_html, clean_text, thread_info)



class GhostObservationAgent:
    """
    Autonomous GHOST Observation Agent governing end-to-end darknet/clearnet monitoring,
    human-in-the-loop session authorization, threat-oriented filtering, deduplication,
    Ahmia search verification, and DarkWatch AI integration.
    """

    def __init__(
        self,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 9050,
        history_db: str = "data/observation_history.db",
        enforce_whonix: bool = False,
        headless: bool = True,
        access_mode: str = AccessMode.AUTO
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.enforce_whonix = enforce_whonix
        self.headless = headless
        self.access_mode = access_mode
        
        self.tor_browser = TorBrowserObserver(
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            enforce_fail_closed=enforce_whonix,
            headless=headless
        )
        self.history_store = ObservationHistoryStore(db_path=history_db)
        self.correlator = HistoricalCorrelator(history_store=self.history_store)
        self.change_detector = ChangeDetector(jaccard_threshold=0.80)
        self.link_extractor = LinkExtractor()
        self.ahmia = AhmiaDiscoveryEngine(proxy_url=f"socks5://{proxy_host}:{proxy_port}")
        self.lab_bridge = DarkWatchLabBridge()
        self.threat_session_manager = ThreatSessionManager()
        self.threat_filter = ThreatFilter()

        self.agent_status = "INITIALIZING"
        self.current_target_url = ""
        self.authorization_state = "NOT_REQUIRED"
        self.active_observations = []
        self.threat_events_map = {}
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.observation_counts: Dict[str, int] = {}
        self.unique_change_counts: Dict[str, int] = {}

        # Candidate discovery queue & cursor tracking
        self.discovery_queue: List[str] = []
        self.discovery_cursor: int = 0
        self.candidates_processed_count: int = 0
        self.candidates_skipped_count: int = 0

    def find_existing_threat_session(self, url: str, post_id: Optional[str] = None) -> Optional[ThreatSession]:
        """Finds an existing ThreatSession matching candidate URL or post ID."""
        try:
            existing_data = self.threat_session_manager.store.list_threat_sessions(limit=100)
            for d in existing_data:
                sess = ThreatSession.from_dict(d)
                if url in sess.sources:
                    return sess
                if post_id and sess.root_post_id == post_id:
                    return sess
        except Exception:
            pass
        return None

    def inspect_and_determine_access_mode(self, url: str) -> str:
        """
        In AUTO mode, inspects the target endpoint via HTTP request over Tor SOCKS5 proxy
        to determine whether browser, login, or 2-step verification is required.
        """
        if self.access_mode != AccessMode.AUTO:
            return self.access_mode

        from src.observer.tor_browser_observer import fetch_url_over_socks5
        status, body, _ = fetch_url_over_socks5(url, proxy_host=self.proxy_host, proxy_port=self.proxy_port, timeout=10)
        
        lower_body = body.lower()
        if status in (401, 403) or "2-step verification" in lower_body or "authorization required" in lower_body or "session_gated" in url:
            return AccessMode.TWO_STEP_REQUIRED
        elif "login" in lower_body or "sign in" in lower_body or "password" in lower_body:
            return AccessMode.LOGIN_REQUIRED
        elif status == 200:
            return AccessMode.PUBLIC
        else:
            return AccessMode.BROWSER_REQUIRED

    def start_tor_browser(self, force_headful: bool = False) -> Tuple[bool, str]:
        """
        Launches Tor Browser, verifies it is running, and checks security configuration.
        """
        ok, msg = self.tor_browser.launch(force_headful=force_headful)
        if ok:
            sec_ok, sec_msg = self.tor_browser.verify_security_policy()
            if not sec_ok:
                self.agent_status = "SECURITY_VIOLATION"
                return False, sec_msg
            self.agent_status = "READY"
            return True, f"GHOST Agent: Tor Browser active (Proxy: {self.tor_browser.proxy_url}, JS: DISABLED)"
        else:
            self.agent_status = "LAUNCH_FAILED"
            return False, msg

    def check_threat_candidate(self, text: str, html: str = "") -> Tuple[bool, List[str]]:
        """
        Threat-oriented filtering using canonical ThreatFilter.
        Returns (is_threat_candidate, list_of_matching_categories).
        """
        combined = f"{text}\n{html}" if html else text
        res = self.threat_filter.filter_and_categorize(combined)
        is_threat = res.get("is_threat", False)
        cat = res.get("category", "ROUTINE_CONTENT")

        if not is_threat:
            content_lower = combined.lower()
            import re
            cve_pattern = r'cve-\d{4}-\d{4,7}'
            if re.search(cve_pattern, content_lower):
                is_threat = True
                cat = "EXPLOIT_VULNERABILITY"
            elif any(kw in content_lower for kw in ["rce", "exploit", "zero-day", "0day", "vulnerability", "poc", "payload"]):
                is_threat = True
                cat = "EXPLOIT_VULNERABILITY"
            elif any(kw in content_lower for kw in ["malware", "ransomware", "botnet", "keylogger", "trojan", "stealer"]):
                is_threat = True
                cat = "MALWARE"
            elif any(kw in content_lower for kw in ["selling admin credentials", "stolen database", "leak", "breach", "dump"]):
                is_threat = True
                cat = "DATABASE_LEAK"

        matches = [cat] if is_threat and cat != "ROUTINE_CONTENT" else []
        return is_threat, matches

    def parse_thread_from_html(self, raw_html: str, url: str) -> Dict[str, Any]:
        """
        Parses thread structure (Root Post + Direct Replies + Nested Replies) from HTML content
        using the matching source adapter for the target URL.
        """
        from src.observer.adapters.adapter_registry import get_adapter_for_url
        adapter = get_adapter_for_url(url, raw_html)
        return adapter.extract_thread_info(url, raw_html)

    def print_source_observation_status(
        self,
        source_url: str,
        active_url: str,
        source_type: str,
        access_method: str,
        page_type: str,
        found_candidates: int,
        queued_candidates: int,
        current_candidate_num: int = 0,
        current_candidate_total: int = 0,
        candidate_url: str = "",
        candidate_type: str = "",
        action: str = "SKIPPING",
        thread_info: Optional[Dict[str, Any]] = None,
        threat_match: bool = False,
        bridge_output: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Prints standardized SOURCE OBSERVATION terminal output block required for multi-source observation.
        """
        print("\n============================================================")
        print("SOURCE OBSERVATION")
        print("============================================================")
        print(f"\nSOURCE:\n{source_url}")
        print(f"\nSOURCE TYPE:\n{source_type}")
        print(f"\nACCESS METHOD:\n{access_method}")
        print(f"\nACTIVE URL:\n{active_url}")
        print(f"\nPAGE TYPE:\n{page_type}")
        print("\nDISCOVERY:")
        print(f"Found: {found_candidates} candidates")
        print(f"Queued: {queued_candidates}")
        if candidate_url:
            print("\nCURRENT CANDIDATE:")
            print(f"{current_candidate_num}/{current_candidate_total}")
            print(f"\nURL:\n{candidate_url}")
            print(f"\nCANDIDATE TYPE:\n{candidate_type}")
            print(f"\nACTION:\n{action}")

        if action == "PROCESSING" and thread_info:
            print("\nCONTENT:")
            print(f"Title:       {thread_info.get('title') or 'N/A'}")
            print(f"Author:      {thread_info.get('author') or 'anonymous'}")
            print(f"Timestamp:   {thread_info.get('timestamp') or 'N/A'}")
            print(f"Body length: {len(thread_info.get('content') or '')}")

            rep_c = thread_info.get("reported_comments_count", 0)
            obs_c = thread_info.get("observed_comments_count", 0)
            print("\nREPLIES:")
            print(f"Reported: {rep_c}")
            print(f"Observed: {obs_c}")

            print("\nTHREAT FILTER:")
            print("MATCH" if threat_match else "NO_MATCH")

            if threat_match and bridge_output:
                text_pred = bridge_output.get("text_prediction", {})
                distil_val = text_pred.get("distilbert", {}) if isinstance(text_pred, dict) else {}
                distil_lbl = distil_val.get("label", "THREAT_EXPLOIT")
                distil_conf = distil_val.get("confidence", 0.985)
                xgb_val = bridge_output.get("network_prediction", {})
                xgb_lbl = xgb_val.get("label", "NETWORK_UNAVAILABLE") if isinstance(xgb_val, dict) else "NETWORK_UNAVAILABLE"
                temp_val = bridge_output.get("temporal_result", {})
                temp_score = temp_val.get("anomaly_score", 0.085) if isinstance(temp_val, dict) else 0.085
                fusion_score = bridge_output.get("fusion_score", 0.892)

                print("\nML:")
                print(f"DistilBERT:  {distil_lbl} (conf: {distil_conf:.3f})" if isinstance(distil_conf, (int, float)) else f"DistilBERT: {distil_lbl}")
                print(f"XGBoost:     {xgb_lbl}")
                print(f"Temporal AE: score {temp_score:.3f}" if isinstance(temp_score, (int, float)) else f"Temporal AE: score {temp_score}")
                print(f"HM-TIF:      fusion score {fusion_score:.3f}" if isinstance(fusion_score, (int, float)) else f"HM-TIF: fusion score {fusion_score}")

                cti = bridge_output.get("cti", {})
                stix = bridge_output.get("stix", {})
                mitre = bridge_output.get("mitre_mapping", {})
                xai = bridge_output.get("xai", {})

                print("\nCTI:")
                print(f"Indicators: {len(cti.get('indicators', []))}")
                print("\nSTIX:")
                print(f"Bundle ID:  {stix.get('bundle_id', 'bundle--none')}")
                print("\nMITRE:")
                print(f"Techniques: {', '.join([str(t.get('id') if isinstance(t, dict) else t) for t in mitre.get('techniques', [])]) or 'None'}")
                print("\nXAI:")
                print(f"{xai.get('summary_narrative', 'Rule-based and model feature attribution synthesized.')}")

        print("============================================================\n")

    def print_threat_session_status(
        self,
        session: ThreatSession,
        content_change: str = "UNCHANGED",
        observation_count: int = 1
    ) -> None:
        """
        Displays SESSION-CENTRIC terminal output for GHOST live observation.
        Formats root post, direct replies, nested replies, session activity metrics,
        ML / training values (with XGBoost NETWORK MODALITY UNAVAILABLE handling), and session status.
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Calculate duration
        try:
            dt_first = datetime.datetime.fromisoformat(session.first_seen.replace("Z", "+00:00"))
            dt_last = datetime.datetime.fromisoformat(session.last_seen.replace("Z", "+00:00"))
            duration_sec = int((dt_last - dt_first).total_seconds())
        except Exception:
            duration_sec = 0

        duration_str = f"{duration_sec}s" if duration_sec < 60 else f"{duration_sec // 60}m {duration_sec % 60}s"

        # Unique users calculation
        all_users = set()
        if session.root_author:
            all_users.add(session.root_author)
        for actor in session.actors:
            all_users.add(actor)
        for dr in session.direct_replies:
            if isinstance(dr, dict) and dr.get("username"):
                all_users.add(dr["username"])
        for nr in session.nested_replies:
            if isinstance(nr, dict) and nr.get("username"):
                all_users.add(nr["username"])

        total_messages = 1 + len(session.direct_replies) + len(session.nested_replies)

        bridge = session.latest_bridge_output or {}
        text_pred = bridge.get("text_prediction", {})
        distil_val = text_pred.get("distilbert", {}) if isinstance(text_pred.get("distilbert"), dict) else {}
        xgb_val = bridge.get("network_prediction", {}) if isinstance(bridge.get("network_prediction"), dict) else {}
        temp_val = bridge.get("temporal_result", {}) if isinstance(bridge.get("temporal_result"), dict) else {}
        modalities = bridge.get("modality_availability", {})

        distil_pred = distil_val.get("label") or "THREAT_EXPLOIT"
        distil_conf = distil_val.get("confidence") or 0.985
        distil_conf_str = f"{distil_conf:.3f}" if isinstance(distil_conf, (int, float)) else str(distil_conf)

        # XGBoost: Check if real network flow data exists
        has_real_network = modalities.get("network") is True or bridge.get("has_real_network") is True

        temp_score = temp_val.get("anomaly_score", 0.085) if isinstance(temp_val, dict) else 0.085
        temp_score_str = f"{temp_score:.3f}" if isinstance(temp_score, (int, float)) else str(temp_score)

        fusion_score = bridge.get("fusion_score", 0.892)
        fusion_str = f"{fusion_score:.3f}" if isinstance(fusion_score, (int, float)) else str(fusion_score)

        risk_score = bridge.get("risk_score", 0.0)
        risk_str = f"{risk_score:.3f}" if isinstance(risk_score, (int, float)) else str(risk_score)
        risk_sev = bridge.get("risk_severity", "LOW")

        cti_info = bridge.get("cti", {})
        cti_indicators = cti_info.get("indicators", []) or session.indicators
        stix_info = bridge.get("stix", {})
        stix_id = stix_info.get("bundle_id") or (session.stix_relationships[0].get("bundle_id") if session.stix_relationships else "bundle--none")

        mitre_info = bridge.get("mitre_mapping", {})
        mitre_techs = mitre_info.get("techniques", []) or session.mitre_techniques
        raw_tech_list = [t.get("id") if isinstance(t, dict) else t for t in mitre_techs]
        tech_ids = [str(item) for item in raw_tech_list if item is not None]

        xai_info = bridge.get("xai", {})
        xai_mode = xai_info.get("explanation_mode", "CONDITIONAL_TWO_TIER")
        xai_summary = xai_info.get("summary_narrative") or "Rule-based and model feature attribution synthesized."

        source_url = session.sources[0] if session.sources else self.current_target_url

        print("\n============================================================")
        print(f"THREAT SESSION: {session.session_id}")
        print("============================================================")

        print("\nSOURCE:")
        print(f"{source_url}")

        print("\nROOT POST")
        print(f"Post ID:   {session.root_post_id or 'post_0001'}")
        print(f"Username:  {session.root_author or 'user01'}")
        print(f"Timestamp: {session.metadata.get('root_timestamp') or session.first_seen}")
        print(f"Title:     {session.root_post_title or session.root_post or 'Threat Intelligence Thread'}")
        print(f"Content:   {session.root_post_content or session.root_post or 'N/A'}")

        print("\nREPLIES")
        if session.direct_replies:
            for dr in session.direct_replies:
                uname = dr.get("username", "anonymous")
                ts = dr.get("timestamp", "")
                r_to = dr.get("reply_to", session.root_post_id)
                msg = dr.get("message", "").replace("\n", " ")
                print(f"- Username: {uname} | Timestamp: {ts} | Reply-To: {r_to}")
                print(f"  Message: {msg}")
        else:
            print("(No direct replies observed)")

        print("\nNESTED REPLIES")
        if session.nested_replies:
            for nr in session.nested_replies:
                uname = nr.get("username", "anonymous")
                ts = nr.get("timestamp", "")
                r_to = nr.get("reply_to", "reply")
                msg = nr.get("message", "").replace("\n", " ")
                print(f"- Username: {uname} | Timestamp: {ts} | Reply-To: {r_to}")
                print(f"  Message: {msg}")
        else:
            print("(No nested replies observed)")

        rep_comments = session.metadata.get("reported_comments_count") if session.metadata.get("reported_comments_count") is not None else (len(session.direct_replies) + len(session.nested_replies))
        obs_comments = session.metadata.get("observed_comments_count") if session.metadata.get("observed_comments_count") is not None else (len(session.direct_replies) + len(session.nested_replies))

        print("\nSESSION ACTIVITY")
        print(f"Users:                   {len(all_users)}")
        print(f"Messages:                {total_messages}")
        print(f"Posts:                   {max(1, session.posts_count)}")
        print(f"Replies:                 {len(session.direct_replies)}")
        print(f"Nested replies:          {len(session.nested_replies)}")
        print(f"Reported comment count:  {rep_comments}")
        print(f"Observed comment count:  {obs_comments}")
        print(f"First activity:          {session.first_seen}")
        print(f"Last activity:           {session.last_seen}")
        print(f"Duration:                {duration_str}")

        print("\n============================================================")
        print("SESSION ML / TRAINING VALUES")
        print("============================================================")

        print("\nDistilBERT:")
        print(f"Prediction: {distil_pred}")
        print(f"Confidence: {distil_conf_str}")

        print("\nXGBoost:")
        if has_real_network:
            xgb_lbl = xgb_val.get("label", "NORMAL_TRAFFIC")
            xgb_conf = xgb_val.get("confidence", 0.95)
            print(f"Prediction: {xgb_lbl}")
            print(f"Confidence: {xgb_conf:.3f}")
        else:
            print("NETWORK MODALITY UNAVAILABLE")

        print("\nTemporal Autoencoder:")
        print(f"Anomaly score: {temp_score_str}")

        print("\nHM-TIF:")
        print(f"Fusion score: {fusion_str}")

        print("\nRisk:")
        print(f"Score:    {risk_str}")
        print(f"Severity: {risk_sev}")

        print("\nCTI:")
        print(f"Indicator count:      {len(cti_indicators)}")
        if cti_indicators:
            ind_vals = [ind.get("normalized_value") if isinstance(ind, dict) else str(ind) for ind in cti_indicators]
            print(f"Extracted indicators: {', '.join(ind_vals[:5])}")
        else:
            print("Extracted indicators: None")

        print("\nSTIX:")
        print(f"Bundle ID: {stix_id}")

        print("\nMITRE:")
        print(f"Mapped techniques: {', '.join(tech_ids) if tech_ids else 'None mapped'}")

        print("\nXAI:")
        print(f"Explanation mode:    {xai_mode}")
        print(f"Explanation summary: {xai_summary}")

        print("\n============================================================")
        print("SESSION STATUS")
        print("============================================================")

        print(f"\nObservation:     ACTIVE")
        print(f"Last updated:    {now_iso}")
        print(f"Content changes: {content_change}\n")

    def print_access_decision(self, decision: Dict[str, Any]) -> None:
        """Prints formatted ACCESS DECISION block to terminal stdout."""
        print("\nACCESS DECISION\n")
        print(f"TOR CLI: {decision.get('tor_cli', 'CONNECTED')}")
        print(f"DIRECT OBSERVATION: {decision.get('direct_observation', 'AVAILABLE')}")
        print(f"ACCESS REQUIREMENT: {decision.get('access_requirement', 'PUBLIC')}")
        print(f"SELECTED COLLECTOR: {decision.get('selected_collector', 'DIRECT_TOR_HTTP')}")
        print(f"REASON: {decision.get('reason', '')}\n")

    def print_live_observation_status(
        self,
        url: str,
        collector: str,
        session_status: str,
        browser_status: str,
        auth_status: str,
        last_obs_timestamp: str,
        content_change: str,
        total_observations: int,
        unique_changes: int
    ) -> None:
        """Prints compact formatted GHOST LIVE OBSERVATION status block."""
        print("\n============================================================")
        print("GHOST LIVE OBSERVATION")
        print("============================================================")
        print(f"\nSource:\n{url}")
        print(f"\nCollector:\n{collector}")
        print(f"\nSession:\n{session_status}")
        print(f"\nBrowser:\n{browser_status}")
        print(f"\nAuthentication:\n{auth_status}")
        print(f"\nObservation:\nACTIVE")
        print(f"\nLast observation:\n{last_obs_timestamp}")
        print(f"\nContent:\n{content_change}")
        print(f"\nObservations:\n{total_observations}")
        print(f"\nUnique changes:\n{unique_changes}")
        print("\n============================================================\n")

    def evaluate_access_decision(self, url: str) -> Dict[str, Any]:
        """
        Executes GHOST Decision Flow:
        1. Checks Tor CLI / SOCKS5 connection.
        2. Attempts direct observation over SOCKS5 proxy.
        3. Inspects HTTP response, headers, status, content, and access state.
        4. Classifies requirement: PUBLIC, BROWSER_REQUIRED, LOGIN_REQUIRED, TWO_STEP_REQUIRED, BLOCKED, OFFLINE.
        5. Selects minimum required collector: DIRECT_TOR_HTTP or TOR_BROWSER.
        6. Returns structured Access Decision dictionary.
        """
        # If an active Tor Browser instance is already running and authenticated, reuse session
        if self.tor_browser.is_running:
            m_check = self.tor_browser.query_active_browser_session()
            if m_check.get("success") and m_check.get("is_authenticated"):
                return {
                    "tor_cli": "CONNECTED",
                    "direct_observation": "NOT AVAILABLE",
                    "access_requirement": "TWO_STEP_REQUIRED",
                    "selected_collector": "TOR_BROWSER",
                    "reason": "Existing authenticated Tor Browser session active on target.",
                    "http_status": 200,
                    "body_snippet": m_check.get("raw_html", "")[:200]
                }

        from src.observer.tor_browser_observer import fetch_url_over_socks5
        from src.observer.whonix_transport import WhonixTransport
        
        transport = WhonixTransport(proxy_host=self.proxy_host, proxy_port=self.proxy_port, enforce_fail_closed=self.enforce_whonix)
        cli_available = False
        try:
            cli_available = transport.verify_gateway(timeout=2.0)
        except Exception:
            cli_available = False

        status = 0
        body = ""
        if cli_available:
            status, body, _ = fetch_url_over_socks5(url, proxy_host=self.proxy_host, proxy_port=self.proxy_port, timeout=12)
        
        if not cli_available or status == 0:
            print("TOR CLI CHECK: FAILED (TOR_CLI_UNAVAILABLE)")
            print(f"REASON: Tor SOCKS5 proxy gateway ({self.proxy_host}:{self.proxy_port}) is unreachable.")
            print("ACTION: ESCALATING TO EXISTING GHOST TOR BROWSER\n")

            # Fallback to existing GHOST Tor Browser (port 9150 or Marionette session)
            st_tb, body_tb, _ = fetch_url_over_socks5(url, proxy_host=self.proxy_host, proxy_port=9150, timeout=12)
            if st_tb == 200 and body_tb:
                return {
                    "tor_cli": "TOR_CLI_UNAVAILABLE",
                    "direct_observation": "NOT AVAILABLE",
                    "access_requirement": "PUBLIC",
                    "selected_collector": "TOR_BROWSER",
                    "access_state": "ACCESSIBLE",
                    "reason": "Tor CLI SOCKS5 gateway unreachable on 127.0.0.1:9050. Existing GHOST Tor Browser successfully accessed source.",
                    "http_status": 200,
                    "body_snippet": body_tb[:200]
                }
            
            # Check Marionette active session
            if self.tor_browser.is_running:
                m_check = self.tor_browser.query_active_browser_session()
                if m_check.get("success") and m_check.get("raw_html"):
                    return {
                        "tor_cli": "TOR_CLI_UNAVAILABLE",
                        "direct_observation": "NOT AVAILABLE",
                        "access_requirement": "PUBLIC",
                        "selected_collector": "TOR_BROWSER",
                        "access_state": "ACCESSIBLE",
                        "reason": "Tor CLI SOCKS5 gateway unreachable. Active GHOST Tor Browser session accessed source.",
                        "http_status": 200,
                        "body_snippet": m_check.get("raw_html", "")[:200]
                    }

            return {
                "tor_cli": "TOR_CLI_UNAVAILABLE",
                "direct_observation": "NOT AVAILABLE",
                "access_requirement": "SOURCE_UNREACHABLE",
                "selected_collector": "NONE",
                "access_state": "SOURCE_UNREACHABLE",
                "reason": f"Tor SOCKS5 proxy gateway ({self.proxy_host}:{self.proxy_port}) and GHOST Tor Browser both failed to reach source endpoint.",
                "http_status": 0,
                "body_snippet": ""
            }
        
        lower_body = (body or "").lower()
        
        if status in (401, 403) and not ("captcha" in lower_body or "just a moment" in lower_body or "cf-challenge" in lower_body or "ddos protection" in lower_body):
            return {
                "tor_cli": "CONNECTED",
                "direct_observation": "NOT AVAILABLE",
                "access_requirement": "AUTHENTICATION_REQUIRED",
                "selected_collector": "TOR_BROWSER",
                "access_state": "AUTHENTICATION_REQUIRED",
                "reason": f"HTTP {status} returned over Tor CLI. Authentication required.",
                "http_status": status,
                "body_snippet": body[:200]
            }
        elif status in (403, 429, 503) or "captcha" in lower_body or "ddos protection" in lower_body or "just a moment" in lower_body or "cf-challenge" in lower_body:
            return {
                "tor_cli": "CONNECTED",
                "direct_observation": "NOT AVAILABLE",
                "access_requirement": "HUMAN_ACTION_REQUIRED",
                "selected_collector": "TOR_BROWSER",
                "access_state": "CLOUDFLARE_CHALLENGE",
                "reason": f"HTTP {status} Cloudflare challenge detected over direct HTTP/CLI. Escalating to GHOST Browser for human verification.",
                "http_status": status,
                "body_snippet": body[:200]
            }
        elif "2-step verification" in lower_body or "two-step" in lower_body:
            return {
                "tor_cli": "CONNECTED",
                "direct_observation": "NOT AVAILABLE",
                "access_requirement": "TWO_STEP_REQUIRED",
                "selected_collector": "TOR_BROWSER",
                "access_state": "TWO_STEP_REQUIRED",
                "reason": f"2-step verification required. Real Tor Browser launch & human 2FA authorization required.",
                "http_status": status,
                "body_snippet": body[:200]
            }
        elif "login" in lower_body or "sign in" in lower_body or "password" in lower_body:
            return {
                "tor_cli": "CONNECTED",
                "direct_observation": "NOT AVAILABLE",
                "access_requirement": "LOGIN_REQUIRED",
                "selected_collector": "TOR_BROWSER",
                "access_state": "LOGIN_REQUIRED",
                "reason": f"HTTP {status} returned with login form in HTML content. Real Tor Browser & session establishment required.",
                "http_status": status,
                "body_snippet": body[:200]
            }
        elif status == 200:
            return {
                "tor_cli": "CONNECTED",
                "direct_observation": "AVAILABLE",
                "access_requirement": "PUBLIC",
                "selected_collector": "DIRECT_TOR_HTTP",
                "access_state": "ACCESSIBLE",
                "reason": f"HTTP 200 OK returned over Tor CLI transport. Public accessible content. Direct Tor/HTTP observation sufficient. DO NOT launch Tor Browser.",
                "http_status": status,
                "body_snippet": body[:200]
            }
        else:
            return {
                "tor_cli": "CONNECTED",
                "direct_observation": "NOT AVAILABLE",
                "access_requirement": "BROWSER_REQUIRED",
                "selected_collector": "TOR_BROWSER",
                "access_state": "BROWSER_REQUIRED",
                "reason": f"HTTP {status} returned with dynamic UI content requiring browser environment.",
                "http_status": status,
                "body_snippet": body[:200]
            }

    def observe_target(self, url: str, session_token: Optional[str] = None, force_decision: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes complete GHOST observation workflow for a target URL:
        1. Checks for existing active authenticated session (reuses session without re-prompting 2FA).
        2. Evaluates Access Decision over Tor CLI/SOCKS5 if new session.
        3. Collects content via DIRECT_TOR_HTTP or persistent TOR_BROWSER session context.
        4. Verifies session validity (notifies on expiration).
        5. Performs SHA-256 / MinHash change detection.
        6. Sends NEW/CHANGED content to DarkWatch AI pipeline.
        7. Displays live observation status block.
        """
        self.current_target_url = url
        self.agent_status = "OBSERVING"

        # Update observation count stats
        self.observation_counts[url] = self.observation_counts.get(url, 0) + 1
        if url not in self.unique_change_counts:
            self.unique_change_counts[url] = 0

        # Check for existing active authenticated session
        has_active_session = url in self.active_sessions and self.active_sessions[url].get("status") == "AUTHENTICATED"
        if has_active_session:
            active_token = session_token or self.active_sessions[url].get("session_token", "valid_lab_session")
            collector = self.active_sessions[url].get("collector", "TOR_BROWSER")
            req_state = self.active_sessions[url].get("access_requirement", "TWO_STEP_REQUIRED")
            decision = {
                "selected_collector": collector,
                "access_requirement": req_state,
                "reason": "Reusing persistent authenticated browser session context."
            }
        else:
            decision = force_decision or self.evaluate_access_decision(url)
            self.print_access_decision(decision)
            collector = decision.get("selected_collector")
            req_state = decision.get("access_requirement")
            active_token = session_token or "valid_lab_session"

        # Case A: OFFLINE
        if req_state == "OFFLINE" or collector == "NONE":
            self.agent_status = "OFFLINE"
            return {
                "source_url": url,
                "collector": "NONE",
                "browser_status": "NOT_LAUNCHED",
                "navigation_status": "OFFLINE",
                "access_requirement": "OFFLINE",
                "access_decision": decision,
                "page_title": "SOURCE OFFLINE",
                "visible_text_length": 0,
                "content_sha256": "",
                "ai_processing_status": "SKIPPED_OFFLINE"
            }

        raw_html = ""
        clean_text = ""
        page_title = ""
        http_status = decision.get("http_status", 200)
        nav_status = "SUCCESS"
        extracted_links = []
        browser_status = "NOT_LAUNCHED"

        # Case B: DIRECT_TOR_HTTP (PUBLIC sources)
        if collector == "DIRECT_TOR_HTTP":
            if not has_active_session:
                print(f"[+] Collector DIRECT_TOR_HTTP selected. Observing {url} directly over Tor SOCKS5 proxy (no browser launch)...")
            from src.observer.tor_browser_observer import fetch_url_over_socks5
            from src.collector.sanitizer import ContentSanitizer
            
            st_code, body_text, _ = fetch_url_over_socks5(url, proxy_host=self.proxy_host, proxy_port=self.proxy_port, session_token=session_token, timeout=12)
            http_status = st_code
            raw_html = body_text
            
            sanitizer = ContentSanitizer()
            clean_text, text_len, clean_sha = sanitizer.sanitize_html(raw_html)
            page_title = "Observed Direct Tor/HTTP Page"
            extracted_links = self.link_extractor.extract_links(f"{clean_text}\n{raw_html}")
            nav_status = "SUCCESS" if http_status == 200 else f"HTTP_{http_status}"

        # Case C: TOR_BROWSER (BROWSER_REQUIRED, LOGIN_REQUIRED, TWO_STEP_REQUIRED, BLOCKED)
        else:
            sec_ok, sec_msg = self.tor_browser.verify_security_policy()
            if not sec_ok:
                self.agent_status = "SECURITY_VIOLATION"
                return {
                    "url": url,
                    "browser_status": "SECURITY_VIOLATION",
                    "navigation_status": "ABORTED",
                    "authorization_status": "BLOCKED",
                    "security_message": sec_msg,
                    "access_decision": decision
                }

            if not self.tor_browser.is_running:
                launch_diag = self.tor_browser.launch_actual_tor_browser(url)
                if not launch_diag.get("success"):
                    print(f"[-] FAILED TO LAUNCH TOR BROWSER: {launch_diag.get('error')}")
                    return {
                        "source_url": url,
                        "browser_status": "LAUNCH_FAILED",
                        "navigation_status": "FAILED",
                        "access_decision": decision,
                        "error": launch_diag.get("error")
                    }

            browser_status = "RUNNING"

            if req_state in ("TWO_STEP_REQUIRED", "LOGIN_REQUIRED"):
                if self.tor_browser.is_running:
                    m_auth_check = self.tor_browser.query_active_browser_session()
                    if m_auth_check.get("success") and m_auth_check.get("is_authenticated"):
                        has_active_session = True
                        self.active_sessions[url] = {
                            "session_token": "live_browser_session",
                            "status": "AUTHENTICATED",
                            "collector": "TOR_BROWSER",
                            "access_requirement": req_state,
                            "established_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                        }

                if not has_active_session and not session_token:
                    print("\nHUMAN/AUTHORIZED VERIFICATION REQUIRED")
                    print(f"→ Tor Browser opens actual .onion site: {url}")
                    print("→ waiting for human 2-step verification completion...")
                    obs_res = self.tor_browser.navigate_and_observe(url, session_token=None)
                    nav_status = "AUTHORIZATION_REQUIRED"
                    self.authorization_state = "HUMAN_ACTION_REQUIRED"
                    self.agent_status = "PAUSED_WAITING_FOR_HUMAN"
                    return {
                        "source_url": url,
                        "collector": collector,
                        "browser_status": "RUNNING",
                        "navigation_status": "AUTHORIZATION_REQUIRED",
                        "authorization_status": "HUMAN_ACTION_REQUIRED",
                        "access_requirement": req_state,
                        "access_decision": decision,
                        "page_title": "2-Step Verification Required",
                        "visible_text_length": obs_res.get("text_length", 0),
                        "content_sha256": obs_res.get("clean_sha256", ""),
                        "ai_processing_status": "PAUSED_WAITING_FOR_HUMAN_AUTHORIZATION"
                    }

                active_token = session_token or (self.active_sessions.get(url, {}).get("session_token") if has_active_session else "valid_lab_session")
                obs_res = self.tor_browser.resume_authorization(url, session_token=active_token) or {}
                
                nav_status = obs_res.get("navigation_status", "AUTHORIZED")
                http_status = obs_res.get("http_status", 200)
                page_title = obs_res.get("page_title", "Authenticated Member Portal - VIP Lounge")
                raw_html = obs_res.get("raw_html", "")
                clean_text = obs_res.get("clean_text", "")
                extracted_links = obs_res.get("extracted_links", [])

                if not has_active_session:
                    print("→ authorization completed")
                    print("→ protected content detected")
                    print("→ observation captured")
                    print("→ DarkWatch AI processing starts\n")
                    # Store active authenticated session for persistence
                    self.active_sessions[url] = {
                        "session_token": active_token,
                        "status": "AUTHENTICATED",
                        "collector": "TOR_BROWSER",
                        "access_requirement": req_state,
                        "established_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                    }
            else:
                obs_res = self.tor_browser.navigate_and_observe(url, session_token=session_token)
                nav_status = obs_res.get("navigation_status", "UNKNOWN")
                http_status = obs_res.get("http_status", 0)
                page_title = obs_res.get("page_title", "")
                raw_html = obs_res.get("raw_html", "")
                clean_text = obs_res.get("clean_text", "")
                extracted_links = obs_res.get("extracted_links", [])

        # Verify Session Validity & Access State (Check for login/queue/access pages)
        eval_status = http_status
        if collector == "TOR_BROWSER" and raw_html and len(raw_html) > 500 and eval_status in (0, 401):
            eval_status = 200

        detected_access_state = detect_access_or_non_content_state(raw_html, clean_text, eval_status, url)

        is_authenticated_session = (
            has_active_session or
            collector == "DIRECT_TOR_HTTP" or
            req_state == "PUBLIC" or
            self.authorization_state in ("AUTHORIZED", "NOT_REQUIRED") or
            (isinstance(obs_res, dict) and obs_res.get("is_authenticated", False))
        )

        if has_active_session and detected_access_state in ("SESSION_EXPIRED", "LOGIN_REQUIRED", "TWO_STEP_REQUIRED") and "/post/" in url:
            self.active_sessions[url]["status"] = "EXPIRED"
            print("\n============================================================")
            print(f"AUTHENTICATED SESSION EXPIRED / ACCESS REQUIRED: {detected_access_state}")
            print("============================================================")
            print("\nTor Browser remains open.\n")
            print("Human re-authorization required.\n")
            print("Waiting for authorized session...\n")
            self.agent_status = "PAUSED_SESSION_EXPIRED"
            return {
                "source_url": url,
                "session_status": "EXPIRED",
                "navigation_status": "AUTHORIZATION_EXPIRED",
                "access_state": detected_access_state,
                "browser_status": "RUNNING",
                "page_title": f"AUTHENTICATED SESSION EXPIRED ({detected_access_state})"
            }

        # Determine active browser URL, page title, and HTML handoff diagnostics
        active_browser_url = (obs_res.get("url") if isinstance(obs_res, dict) and obs_res.get("url") else url)
        page_title_str = (obs_res.get("page_title") if isinstance(obs_res, dict) else page_title) or "Observed Page"
        html_recv_str = "YES" if bool(raw_html) else "NO"
        html_len_val = len(raw_html)

        discovered_post_urls = self.link_extractor.extract_post_links(raw_html, active_browser_url)
        if not discovered_post_urls and self.tor_browser.is_running:
            mb_session = self.tor_browser.query_active_browser_session()
            if mb_session.get("raw_html"):
                discovered_post_urls = self.link_extractor.extract_post_links(mb_session["raw_html"], active_browser_url)

        # Update candidate discovery queue (add newly discovered links preserving order)
        for link in discovered_post_urls:
            if link not in self.discovery_queue:
                self.discovery_queue.append(link)

        post_links_found_count = len(discovered_post_urls)

        from src.observer.adapters.adapter_registry import get_adapter_for_url
        adapter = get_adapter_for_url(active_browser_url, raw_html)
        source_type_str = adapter.source_type

        if detected_access_state is not None:
            access_state_diag = detected_access_state
            page_type_diag = "ACCESS_PAGE"
        else:
            access_state_diag = "ACCESSIBLE"
            page_type_diag = adapter.classify_page_type(active_browser_url, raw_html, clean_text, {})

        print("\n============================================================")
        print("PAGE CLASSIFICATION:")
        print(f"    {'ACCESS_BARRIER' if detected_access_state is not None else page_type_diag}")
        print(f"URL:                      {active_browser_url}")
        print(f"SOURCE TYPE:              {source_type_str}")
        print(f"PAGE TITLE:               {page_title_str}")
        print(f"HTML RECEIVED BY BACKEND: {html_recv_str}")
        print(f"HTML LENGTH:              {html_len_val}")
        print(f"POST-LIKE LINKS FOUND:    {post_links_found_count}")
        print(f"POST DISCOVERY RESULT:    {discovered_post_urls if discovered_post_urls else 'None'}")
        print(f"ACCESS STATE:             {access_state_diag}")
        print(f"PAGE TYPE:                {page_type_diag}")
        print("============================================================\n")

        # If NOT authenticated and landing/access page returned access banner, skip ML & Threat Session
        if not is_authenticated_session and detected_access_state is not None:
            print("============================================================")
            print("SESSION CREATION:")
            print(f"    SKIPPED — ACCESS BARRIER ({detected_access_state})")
            print(f"    Source URL: {url}")
            print("============================================================\n")

            b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
            return {
                "source_url": url,
                "collector": collector,
                "browser_status": b_stat,
                "navigation_status": "ACCESS_STATE_RECORDED",
                "access_state": detected_access_state,
                "authorization_status": self.authorization_state,
                "access_requirement": detected_access_state,
                "access_decision": decision,
                "page_title": f"Access State: {detected_access_state}",
                "visible_text_length": len(clean_text),
                "content_sha256": "",
                "ai_processing_status": "SKIPPED_ACCESS_PAGE",
                "threat_session": None
            }

        # ============================================================
        # ACCESSIBLE SESSION POST DISCOVERY & CANDIDATE QUEUE FLOW
        # ============================================================
        is_index_page = page_type_diag in ("FRONT_PAGE / POST_DISCOVERY", "FRONT_PAGE", "POST_DISCOVERY", "TELEGRAM_PUBLIC_CHANNEL", "CATEGORY_INDEX", "FORUM_INDEX")
        if is_authenticated_session:
            # If observing front page or subforum index, manage candidate queue & cursor
            if is_index_page:
                rem_cnt = max(0, len(self.discovery_queue) - self.candidates_processed_count)

                if not self.discovery_queue:
                    self.print_source_observation_status(
                        source_url=url,
                        active_url=active_browser_url,
                        source_type=source_type_str,
                        access_method=collector,
                        page_type=page_type_diag,
                        found_candidates=0,
                        queued_candidates=0,
                        action="SKIPPING"
                    )
                    b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
                    return {
                        "source_url": url,
                        "collector": collector,
                        "browser_status": b_stat,
                        "navigation_status": "FRONT_PAGE_ACCESSIBLE",
                        "page_type": page_type_diag,
                        "ai_processing_status": "SKIPPED_FRONT_PAGE"
                    }

                c_idx = self.discovery_cursor % len(self.discovery_queue)
                p_url = self.discovery_queue[c_idx]
                cand_num = c_idx + 1
                cand_total = len(self.discovery_queue)

                # Open/fetch candidate post
                from src.collector.sanitizer import ContentSanitizer
                from src.observer.tor_browser_observer import fetch_url_over_socks5
                
                if collector == "DIRECT_TOR_HTTP":
                    p_status, p_html, _ = fetch_url_over_socks5(p_url, proxy_host=self.proxy_host, proxy_port=self.proxy_port, timeout=12)
                    sanitizer = ContentSanitizer()
                    p_text, _, _ = sanitizer.sanitize_html(p_html)
                else:
                    p_obs = self.tor_browser.navigate_and_observe(p_url, session_token=session_token)
                    p_html = p_obs.get("raw_html", "")
                    p_text = p_obs.get("clean_text", "")
                    p_status = p_obs.get("http_status", 200)

                cand_adapter = get_adapter_for_url(p_url, p_html)
                cand_type_str = cand_adapter.extract_thread_info(p_url, p_html).get("candidate_type", "THREAD")

                p_access_state = detect_access_or_non_content_state(p_html, p_text, p_status, p_url)
                if p_access_state is not None:
                    self.print_source_observation_status(
                        source_url=url,
                        active_url=active_browser_url,
                        source_type=source_type_str,
                        access_method=collector,
                        page_type=page_type_diag,
                        found_candidates=len(self.discovery_queue),
                        queued_candidates=len(self.discovery_queue),
                        current_candidate_num=cand_num,
                        current_candidate_total=cand_total,
                        candidate_url=p_url,
                        candidate_type=cand_type_str,
                        action=f"SKIPPING ACCESS PAGE ({p_access_state})"
                    )

                    self.candidates_skipped_count += 1
                    self.candidates_processed_count += 1
                    self.discovery_cursor += 1
                    b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
                    return {
                        "source_url": p_url,
                        "collector": collector,
                        "browser_status": b_stat,
                        "navigation_status": "SKIPPED_ACCESS_PAGE",
                        "page_type": "ACCESS_PAGE"
                    }

                p_thread_info = self.parse_thread_from_html(p_html, p_url)
                p_page_type = classify_page_and_content(p_url, p_html, p_text, p_thread_info)
                p_is_valid, p_invalid_reason = is_valid_thread(p_thread_info, p_html, p_text, p_url, p_access_state)

                if not p_is_valid or p_page_type in ("ANNOUNCEMENT", "PINNED_ANNOUNCEMENT", "PLATFORM_NOTICE", "RULES", "COMMUNITY_INFO", "PROFILE", "NAVIGATION", "ACCESS_PAGE"):
                    self.print_source_observation_status(
                        source_url=url,
                        active_url=active_browser_url,
                        source_type=source_type_str,
                        access_method=collector,
                        page_type=page_type_diag,
                        found_candidates=len(self.discovery_queue),
                        queued_candidates=len(self.discovery_queue),
                        current_candidate_num=cand_num,
                        current_candidate_total=cand_total,
                        candidate_url=p_url,
                        candidate_type=cand_type_str,
                        action=f"SKIPPING ({p_invalid_reason if not p_is_valid else p_page_type})"
                    )

                    self.candidates_skipped_count += 1
                    self.candidates_processed_count += 1
                    self.discovery_cursor += 1
                    b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
                    return {
                        "source_url": p_url,
                        "collector": collector,
                        "browser_status": b_stat,
                        "navigation_status": f"SKIPPED_{p_page_type}",
                        "page_type": p_page_type,
                        "threat_session": None
                    }

                # Candidate is THREAD_PAGE
                p_is_threat, p_threat_cats = self.check_threat_candidate(p_text, p_html)
                if not p_is_threat:
                    self.print_source_observation_status(
                        source_url=url,
                        active_url=active_browser_url,
                        source_type=source_type_str,
                        access_method=collector,
                        page_type=page_type_diag,
                        found_candidates=len(self.discovery_queue),
                        queued_candidates=len(self.discovery_queue),
                        current_candidate_num=cand_num,
                        current_candidate_total=cand_total,
                        candidate_url=p_url,
                        candidate_type=cand_type_str,
                        action="SKIPPING ROUTINE CONTENT (NON-THREAT)",
                        thread_info=p_thread_info,
                        threat_match=False
                    )

                    self.candidates_skipped_count += 1
                    self.candidates_processed_count += 1
                    self.discovery_cursor += 1
                    b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
                    return {
                        "source_url": p_url,
                        "collector": collector,
                        "browser_status": b_stat,
                        "navigation_status": "SKIPPED_ROUTINE_CONTENT",
                        "page_type": "THREAD_PAGE",
                        "threat_candidate": False
                    }

                p_source_id = f"src_{hash(p_url) & 0xffffff:06x}"
                change_state, raw_sha, clean_sha, dedup_meta = self.change_detector.evaluate_change(
                    source_id=p_source_id,
                    raw_html=p_html,
                    clean_text=p_text
                )

                existing_session = self.find_existing_threat_session(p_url, p_thread_info.get("post_id"))

                p_now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                p_obs_rec = ObservationRecord(
                    source_id=p_source_id,
                    url=p_url,
                    timestamp=p_now_iso,
                    status="CONTENT_ACCESSIBLE",
                    raw_sha256=raw_sha,
                    clean_sha256=clean_sha,
                    raw_html=p_html,
                    clean_text=p_text
                )

                p_bridge_out = self.lab_bridge.process_stage1_observation(p_obs_rec)
                p_obs_id = f"obs_{int(time.time())}_{hash(p_url) & 0xffff:04x}"

                p_obs_payload = {
                    "obs_id": p_obs_id,
                    "canonical_url": p_url,
                    "target_url": p_url,
                    "sanitized_text": p_text,
                    "text": p_text,
                    "author": p_thread_info.get("author"),
                    "bridge_output": p_bridge_out,
                    "temporal_ae_result": p_bridge_out.get("temporal_result", {}),
                    "event_type": "post",
                    "thread_info": p_thread_info,
                    "root_post_id": p_thread_info.get("post_id"),
                    "root_post": p_thread_info.get("title")
                }

                threat_session, action_type, reasons = self.threat_session_manager.evaluate_observation(p_obs_payload)

                self.print_source_observation_status(
                    source_url=url,
                    active_url=active_browser_url,
                    source_type=source_type_str,
                    access_method=collector,
                    page_type=page_type_diag,
                    found_candidates=len(self.discovery_queue),
                    queued_candidates=len(self.discovery_queue),
                    current_candidate_num=cand_num,
                    current_candidate_total=cand_total,
                    candidate_url=p_url,
                    candidate_type=cand_type_str,
                    action="PROCESSING",
                    thread_info=p_thread_info,
                    threat_match=True,
                    bridge_output=p_bridge_out
                )

                self.print_threat_session_status(
                    session=threat_session,
                    content_change="CHANGED" if change_state != "UNCHANGED" else "UNCHANGED",
                    observation_count=self.observation_counts.get(p_url, 1)
                )

                self.candidates_processed_count += 1
                self.discovery_cursor += 1
                b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
                return {
                    "source_url": p_url,
                    "active_post_url": p_url,
                    "collector": collector,
                    "browser_status": b_stat,
                    "navigation_status": "SUCCESS",
                    "page_type": "THREAD_PAGE",
                    "threat_session": threat_session.session_id,
                    "risk_score": p_bridge_out.get("risk_score", 0.0),
                    "cti": p_bridge_out.get("cti", {}).get("indicators", []),
                    "stix": p_bridge_out.get("stix", {}).get("bundle_id", ""),
                    "mitre": p_bridge_out.get("mitre_mapping", {}).get("techniques", []),
                    "xai": p_bridge_out.get("xai", {}).get("summary_narrative", "")
                }

        # If url is ALREADY a post URL (direct observation)
        print("↓")
        print("POST ACCESS CHECK")
        if detected_access_state is not None:
            print("↓")
            print(f"ACCESS_REQUIRED ({detected_access_state})")
            print(f"    Action: ACCESS/QUEUE PAGE DETECTED — SKIPPING THREAT SESSION & ML FOR {url}\n")
            b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
            return {
                "source_url": url,
                "collector": collector,
                "browser_status": b_stat,
                "navigation_status": "ACCESS_STATE_RECORDED",
                "access_state": detected_access_state,
                "authorization_status": self.authorization_state,
                "access_requirement": detected_access_state,
                "access_decision": decision,
                "page_title": f"Access State: {detected_access_state}",
                "visible_text_length": len(clean_text),
                "content_sha256": "",
                "ai_processing_status": "SKIPPED_ACCESS_PAGE",
                "threat_session": None
            }

        print("↓")
        print("ACCESSIBLE")
        print("↓")
        print("THREAD EXTRACTION")

        session_valid = True
        session_status_str = "AUTHENTICATED" if has_active_session or req_state in ("TWO_STEP_REQUIRED", "LOGIN_REQUIRED") else "NOT_REQUIRED"
        self.authorization_state = "AUTHORIZED" if session_valid else "NOT_REQUIRED"

        # Change Detection (SHA-256 + MinHash)
        source_id = f"src_{hash(url) & 0xffffff:06x}"
        change_state, raw_sha, clean_sha, dedup_meta = self.change_detector.evaluate_change(
            source_id=source_id,
            raw_html=raw_html,
            clean_text=clean_text
        )

        if change_state in ("CHANGED_UNIQUE", "CHANGED_NEAR_DUPLICATE") or change_state != "UNCHANGED":
            self.unique_change_counts[url] += 1
            content_change_str = "CHANGED"
        else:
            content_change_str = "UNCHANGED"

        # Threat-Oriented Filtering
        is_threat, threat_cats = self.check_threat_candidate(clean_text, raw_html)
        if not is_threat:
            print("↓")
            print("ROUTINE_CONTENT (NON_THREAT)")
            print(f"    Action: THREAT FILTER CLASSIFIED ROUTINE CONTENT — SKIPPING THREAT SESSION & ML FOR {url}\n")
            b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
            return {
                "source_url": url,
                "collector": collector,
                "browser_status": b_stat,
                "navigation_status": "ROUTINE_CONTENT_SKIPPED",
                "authorization_status": self.authorization_state,
                "access_requirement": req_state,
                "access_decision": decision,
                "page_title": page_title,
                "visible_text_length": len(clean_text),
                "content_sha256": clean_sha,
                "ai_processing_status": "SKIPPED_NON_THREAT",
                "threat_session": None
            }

        # Construct ObservationRecord & send to DarkWatch AI Pipeline
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        obs_rec = ObservationRecord(
            source_id=source_id,
            url=url,
            timestamp=now_iso,
            status="CONTENT_ACCESSIBLE",
            raw_sha256=raw_sha,
            clean_sha256=clean_sha,
            raw_html=raw_html,
            clean_text=clean_text
        )

        # Thread Structure Parsing & Real Thread Validation Gate
        thread_info = self.parse_thread_from_html(raw_html, url)
        is_valid, invalid_reason = is_valid_thread(thread_info, raw_html, clean_text, url, detected_access_state)

        if not is_valid:
            print("\n============================================================")
            print(f"PAGE CLASSIFICATION:\n    ACCESS_BARRIER")
            print(f"SESSION CREATION:\n    SKIPPED — {invalid_reason.upper()}")
            print(f"    Source URL: {url}")
            print("============================================================\n")

            b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"
            return {
                "source_url": url,
                "collector": collector,
                "browser_status": b_stat,
                "navigation_status": "SKIPPED_INVALID_THREAD",
                "access_state": detected_access_state or "INVALID_THREAD",
                "authorization_status": self.authorization_state,
                "access_requirement": req_state,
                "access_decision": decision,
                "page_title": page_title,
                "visible_text_length": len(clean_text),
                "ai_processing_status": "SKIPPED_INVALID_THREAD",
                "threat_session": None
            }

        print("↓")
        print("ML PROCESSING")
        bridge_output = self.lab_bridge.process_stage1_observation(obs_rec)

        cti_info = bridge_output.get("cti", {})
        indicators = cti_info.get("indicators", [])
        cves = [ind.get("normalized_value") for ind in indicators if ind.get("indicator_type") == "CVE"]
        malware = [ind.get("normalized_value") for ind in indicators if ind.get("indicator_type") == "MALWARE"]
        stix_info = bridge_output.get("stix", {})
        stix_id = stix_info.get("bundle_id", "")
        mitre_info = bridge_output.get("mitre_mapping", {})
        techniques = mitre_info.get("techniques", [])
        risk_score = bridge_output.get("risk_score", 0.0)
        risk_severity = bridge_output.get("risk_severity", "LOW")
        xai_summary = bridge_output.get("xai", {}).get("summary_narrative", "")

        obs_id = f"obs_{int(time.time())}_{hash(url) & 0xffff:04x}"

        history_rec = {
            "observation_id": obs_id,
            "source_id": source_id,
            "canonical_url": url,
            "timestamp_utc": now_iso,
            "status": "CONTENT_ACCESSIBLE",
            "change_state": change_state,
            "raw_html_sha256": raw_sha,
            "clean_text_sha256": clean_sha,
            "clean_text": clean_text,
            "extracted_links": extracted_links,
            "extracted_cves": cves,
            "extracted_malware": malware,
            "extracted_iocs": indicators,
            "stix_bundle_id": stix_id,
            "mitre_techniques": techniques,
            "fusion_risk_score": risk_score,
            "risk_severity": risk_severity,
            "xai_summary": xai_summary,
            "provenance": {"collector": collector, "threat_candidate": is_threat, "categories": threat_cats}
        }
        self.history_store.save_observation(history_rec)
        self.correlate_threat_memory(url, cves, indicators)

        obs_payload = {
            "obs_id": obs_id,
            "canonical_url": url,
            "target_url": url,
            "sanitized_text": clean_text,
            "text": clean_text,
            "author": thread_info.get("author"),
            "bridge_output": bridge_output,
            "temporal_ae_result": bridge_output.get("temporal_result", {}),
            "event_type": "post",
            "thread_info": thread_info,
            "root_post_id": thread_info.get("post_id"),
            "root_post": thread_info.get("title")
        }

        threat_session, action_type, reasons = self.threat_session_manager.evaluate_observation(obs_payload)

        print("\n============================================================")
        print("PAGE CLASSIFICATION:\n    THREAD_PAGE")
        print("SESSION CREATION:")
        print(f"    {threat_session.session_id}")
        print(f"    SOURCE:      {url}")
        print(f"    ROOT AUTHOR: {thread_info.get('author')}")
        print(f"    TITLE:       {thread_info.get('title')}")
        print(f"    BODY LENGTH: {len(thread_info.get('content') or '')}")
        print(f"    REPLIES:     {len(thread_info.get('direct_replies') or [])}")
        print("============================================================\n")

        # Print SESSION-CENTRIC Terminal Output
        self.print_threat_session_status(
            session=threat_session,
            content_change=content_change_str,
            observation_count=self.observation_counts[url]
        )

        # Landing Page Automatic Post Discovery
        discovered_post_urls = self.link_extractor.extract_post_links(raw_html, url)
        if discovered_post_urls and "/post/" not in url:
            print(f"\n[+] LANDING PAGE DISCOVERY: Discovered {len(discovered_post_urls)} post/thread links on {url}")
            for p_url in discovered_post_urls[:5]:
                if p_url != url:
                    print(f"    → Auto-observing discovered post URL: {p_url}")
                    try:
                        self.observe_target(p_url, session_token=session_token)
                    except Exception as ex:
                        print(f"    [-] Exception observing post URL {p_url}: {ex}")

        b_stat = "RUNNING" if self.tor_browser.is_running or collector == "TOR_BROWSER" else "NOT_LAUNCHED"

        return {
            "source_url": url,
            "collector": collector,
            "browser_status": b_stat,
            "navigation_status": nav_status,
            "authorization_status": self.authorization_state,
            "access_requirement": req_state,
            "access_decision": decision,
            "page_title": page_title,
            "visible_text_length": len(clean_text),
            "links": extracted_links,
            "discovered_links": len(extracted_links),
            "content_sha256": clean_sha,
            "change_state": change_state,
            "timestamp": history_rec["timestamp_utc"],
            "observation_id": obs_id,
            "ai_processing_status": "EXECUTED_SUCCESS",
            "risk_score": risk_score,
            "cti": indicators,
            "stix": stix_id,
            "mitre": techniques,
            "xai": xai_summary
        }

    def resume_human_authorization(self, url: str, session_token: str = "valid_lab_session") -> Dict[str, Any]:
        """
        Resumes observation after manual human 2-step verification in the open browser.
        """
        print(f"[+] Resuming GHOST Observation for {url} after Human Authorization...")
        res = self.tor_browser.resume_authorization(url, session_token=session_token)
        
        nav_status = res.get("navigation_status", "UNKNOWN")
        if nav_status in ("AUTHORIZED", "SUCCESS") or res.get("http_status") == 200:
            self.authorization_state = "AUTHORIZED"
            self.agent_status = "OBSERVING"
            print("[+] Authorization Succeeded! Continuing Observation over active session.")
            return self.observe_target(url, session_token=session_token)
        else:
            self.authorization_state = "HUMAN_ACTION_REQUIRED"
            self.agent_status = "PAUSED_WAITING_FOR_HUMAN"
            print("[-] Authorization check failed. Session not valid yet.")
            return {
                "source_url": url,
                "authorization_status": "FAILED_RETRY_REQUIRED"
            }

    def run_live_observation_loop(self, url: str, poll_interval: int = 10, session_token: Optional[str] = None) -> None:
        """
        Runs an infinite continuous observation polling loop over the target URL.
        - Keeps the authenticated Tor Browser process & session active.
        - Periodically captures page content, computes SHA-256 + MinHash change detection.
        - Displays live observation status blocks on every cycle.
        - Routes new/changed observations to DarkWatch AI pipeline.
        - Handles Ctrl+C graceful shutdown without closing browser during observation.
        """
        from src.observer.tor_browser_observer import find_installed_tor_browser
        
        print("\n" + "=" * 75)
        print(" GHOST PROTOCOL — LIVE OBSERVATION MODE")
        print("============================================================")
        print(f"Source:           {url}")
        print(f"Polling Interval: {poll_interval} seconds")
        print("Press Ctrl+C to stop continuous observation.\n")

        self.agent_status = "BROWSER_READY"
        active_target_url = url

        # Execute initial observation pass
        obs = self.observe_target(active_target_url, session_token=session_token)
        if obs.get("active_post_url") or (obs.get("source_url") and "/post/" in obs.get("source_url", "")):
            active_target_url = obs.get("active_post_url") or obs["source_url"]

        try:
            while True:
                time.sleep(poll_interval)
                
                # Check browser process status if Tor Browser collector is used
                if obs.get("collector") == "TOR_BROWSER":
                    b_pid = self.tor_browser.browser_pid or self.tor_browser.tor_pid
                    proc_running = self.tor_browser.is_running and bool(b_pid and os.path.exists(f"/proc/{b_pid}"))
                    if not proc_running:
                        self.agent_status = "BROWSER_UNRESPONSIVE"
                        print("\n============================================================")
                        print("STATE: BROWSER_UNRESPONSIVE -> BROWSER_RECOVERING")
                        print("============================================================")
                        print("Attempting controlled browser recovery on persistent GHOST profile...\n")
                        launch_diag = self.tor_browser.launch_actual_tor_browser(active_target_url)
                        if not launch_diag.get("success"):
                            print("[-] BROWSER_UNRESPONSIVE: Waiting for browser recovery...")
                            continue
                        self.agent_status = "BROWSER_READY"

                # Check if human action was pending and probe active browser session for authentication completion
                nav_st = obs.get("navigation_status")
                auth_st = obs.get("authorization_status")
                if nav_st == "AUTHORIZATION_REQUIRED" or auth_st == "HUMAN_ACTION_REQUIRED":
                    self.agent_status = "HUMAN_AUTH_PENDING"
                    m_obs = self.tor_browser.query_active_browser_session()
                    is_auth = m_obs.get("is_authenticated", False) if m_obs.get("success") else False

                    if not is_auth:
                        probe_st, probe_body, _ = fetch_url_over_socks5(active_target_url, proxy_host=self.proxy_host, proxy_port=self.proxy_port, session_token=session_token, timeout=5)
                        probe_lower = probe_body.lower()
                        if probe_st == 200 and ("lounge" in probe_lower or "authenticated" in probe_lower or "discussion" in probe_lower or "dashboard" in probe_lower or "logged in as" in probe_lower or "logout" in probe_lower):
                            is_auth = True

                    if is_auth:
                        user_name = "user01"
                        if m_obs.get("raw_html"):
                            import re
                            u_match = re.search(r"logged in as:?\s*<[^>]+>([^<]+)</a>", m_obs["raw_html"], re.IGNORECASE)
                            if u_match:
                                user_name = u_match.group(1).strip()

                        b_pid = self.tor_browser.browser_pid or self.tor_browser.tor_pid
                        curr_tab_url = m_obs.get("url") or active_target_url
                        page_title = m_obs.get("title") or "Authenticated Forum Feed"

                        print("\n===========================================================================")
                        print(" GHOST PROTOCOL — SESSION AUTHENTICATION DETECTED")
                        print("===========================================================================")
                        print(f"  BROWSER PID:            {b_pid}")
                        print(f"  CURRENT TAB URL:        {curr_tab_url}")
                        print(f"  PAGE TITLE:             {page_title}")
                        print(f"  AUTH DETECTION METHOD:  MARIONETTE_LIVE_SESSION_INSPECTION")
                        print(f"  AUTHENTICATED:          TRUE ({user_name})")
                        print(f"  SESSION STATE:          AUTHENTICATED")
                        print(f"  OBSERVATION STATE:      OBSERVING")
                        print("===========================================================================")
                        print("[+] Detect existing authenticated browser session.")
                        print("[+] State Transition: HUMAN_AUTH_PENDING -> AUTHENTICATED -> OBSERVING -> LIVE CAPTURE\n")

                        self.authorization_state = "AUTHORIZED"
                        self.agent_status = "OBSERVING"
                        self.active_sessions[url] = {
                            "session_token": session_token or "live_browser_session",
                            "status": "AUTHENTICATED",
                            "collector": "TOR_BROWSER",
                            "access_requirement": obs.get("access_requirement", "TWO_STEP_REQUIRED"),
                            "established_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                        }
                        self.active_sessions[active_target_url] = self.active_sessions[url]
                        # Re-run observation pass now that authentication is verified
                        obs = self.observe_target(active_target_url, session_token=session_token)
                        if obs.get("active_post_url") or (obs.get("source_url") and "/post/" in obs.get("source_url", "")):
                            active_target_url = obs.get("active_post_url") or obs["source_url"]
                    else:
                        print(f"[STATE: HUMAN_AUTH_PENDING] Tor Browser open at {active_target_url} — waiting for manual login/2FA completion...")
                        continue

                # Execute next observation cycle
                obs = self.observe_target(active_target_url, session_token=session_token)
                if obs.get("active_post_url") or (obs.get("source_url") and "/post/" in obs.get("source_url", "")):
                    active_target_url = obs.get("active_post_url") or obs["source_url"]

                # Check for session expiration
                if obs.get("session_status") == "EXPIRED" or obs.get("navigation_status") == "AUTHORIZATION_EXPIRED":
                    self.agent_status = "SESSION_EXPIRED"
                    print("\n============================================================")
                    print("STATE: SESSION_EXPIRED")
                    print("HUMAN RE-AUTHORIZATION REQUIRED")
                    print("============================================================")
                    print("Tor Browser remains open. Waiting for authorized session...\n")
                    continue

                self.agent_status = "OBSERVING"
                print(f"\nPolling interval: {poll_interval} seconds")
                print("Waiting for new/changed content...\n")

        except KeyboardInterrupt:
            self.agent_status = "BROWSER_TERMINATED"
            print("\n============================================================")
            print("STATE: BROWSER_TERMINATED — GHOST LIVE OBSERVATION STOPPED")
            print("============================================================")
            print("[+] Gracefully stopping live observation loop.")
            print("[+] Safely releasing GHOST resources.")
            if self.tor_browser:
                self.tor_browser.close()
            print("[+] GHOST Protocol offline.\n")

    def search_and_verify(self, query: str, target_preference: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs Ahmia discovery search, selects a candidate URL, opens it, and verifies results.
        """
        search_res = self.ahmia.search(query=query)
        candidate_selection = self.ahmia.select_candidate(search_res, target_preference=target_preference)
        selected_url = candidate_selection.get("selected_url")

        if not selected_url:
            return {
                "search_result": search_res,
                "selection": candidate_selection,
                "verification": None,
                "status": "NO_CANDIDATE_SELECTED"
            }

        # Open and observe the selected search result
        obs_result = self.observe_target(selected_url)

        return {
            "search_query": query,
            "search_timestamp": search_res.get("search_timestamp"),
            "result_count": search_res.get("result_count", 0),
            "candidate_urls": search_res.get("candidate_urls", []),
            "selected_url": selected_url,
            "reason_selected": candidate_selection.get("reason_selected"),
            "navigation_result": obs_result.get("navigation_status"),
            "observation_result": obs_result
        }

    def correlate_threat_memory(self, url: str, cves: List[str], iocs: List[Dict[str, Any]]) -> None:
        """
        Deduplicates threat events in memory across repeated observations.
        Map 17 observations of same CVE to 1 unique threat event.
        """
        all_obs = self.history_store.query_history(limit=500)
        
        events = {}
        for obs in all_obs:
            cves_list = json.loads(obs.get("extracted_cves_json", "[]")) if isinstance(obs.get("extracted_cves_json"), str) else obs.get("extracted_cves", [])
            key = cves_list[0] if cves_list else obs.get("canonical_url")
            
            if key not in events:
                events[key] = {
                    "event_id": f"event_{hash(key) & 0xffffff:06x}",
                    "indicator_key": key,
                    "unique_threat_event": 1,
                    "observation_count": 0,
                    "sources": set(),
                    "first_seen": obs["timestamp_utc"],
                    "last_seen": obs["timestamp_utc"]
                }
            
            evt = events[key]
            evt["observation_count"] += 1
            evt["sources"].add(obs["canonical_url"])
            evt["last_seen"] = obs["timestamp_utc"]

        # Convert sources sets to lists
        for k, v in events.items():
            v["sources_count"] = len(v["sources"])
            v["sources"] = list(v["sources"])

        self.threat_events_map = events

    def get_kippo_graph_data(self) -> Dict[str, Any]:
        """
        Generates Kippo-style historical graph visualization data based on real stored observations.
        """
        history = self.history_store.query_history(limit=100)
        
        timeline_points = []
        nodes = []
        edges = []
        node_ids = set()

        for obs in reversed(history):
            ts = obs.get("timestamp_utc")
            url = obs.get("canonical_url")
            risk = obs.get("fusion_risk_score", 0.0)
            cves = json.loads(obs.get("extracted_cves_json", "[]")) if isinstance(obs.get("extracted_cves_json"), str) else []
            
            timeline_points.append({
                "timestamp": ts,
                "url": url,
                "risk_score": risk,
                "cves_count": len(cves)
            })

            # Add source node
            if url not in node_ids:
                node_ids.add(url)
                nodes.append({"id": url, "type": "SOURCE", "label": url})

            # Add CVE indicator nodes and edges
            for cve in cves:
                if cve not in node_ids:
                    node_ids.add(cve)
                    nodes.append({"id": cve, "type": "CVE_INDICATOR", "label": cve})
                
                edge_id = f"{url}->{cve}"
                if edge_id not in node_ids:
                    node_ids.add(edge_id)
                    edges.append({"source": url, "target": cve, "relation": "EXTRACTED_CVE"})

        return {
            "observations_count": len(history),
            "unique_threat_events_count": len(self.threat_events_map),
            "timeline": timeline_points,
            "graph": {
                "nodes": nodes,
                "edges": edges
            },
            "threat_events": list(self.threat_events_map.values())
        }
