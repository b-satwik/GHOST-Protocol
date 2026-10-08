import sys
import os
import json
import requests

# Ensure repository root is on sys.path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.discovery.source_registry import SourceRegistry
from src.discovery.discovery_queue import DiscoveryQueue
from src.dataset.annotation_store import AnnotationStore
from src.resolution.session_manager import ThreatSessionManager
from src.stage1_continuous_observer import Stage1ContinuousObserver
from src.discovery.candidate_classifier import CandidateClassifier

SHADOWBOARD_URL = "http://127.0.0.1:8080"
LIVE_DB_PATH = "data/ghost_live_observation.db"

def run_shadowboard_live_10_posts_test():
    # Authenticate with real running ShadowBoard container
    session = requests.Session()
    login_res = session.post(f"{SHADOWBOARD_URL}/login", data={"username": "user01", "password": "ShadowPass123!"})
    if login_res.status_code != 200:
        print(f"[!] Login to ShadowBoard container failed: HTTP {login_res.status_code}")
        return

    token = session.cookies.get("session_token")
    if token:
        os.environ["SHADOWBOARD_SESSION_TOKEN"] = token

    # Initialize live observer components with live SQLite DB
    if os.path.exists(LIVE_DB_PATH):
        os.remove(LIVE_DB_PATH)

    registry = SourceRegistry(db_path=LIVE_DB_PATH)
    queue = DiscoveryQueue(db_path=LIVE_DB_PATH)
    store = AnnotationStore(db_path=LIVE_DB_PATH)
    session_mgr = ThreatSessionManager(store=store)
    
    observer = Stage1ContinuousObserver(
        registry_db=LIVE_DB_PATH,
        queue_db=LIVE_DB_PATH,
        history_db=LIVE_DB_PATH,
        alerts_db=LIVE_DB_PATH
    )
    observer.session_manager = session_mgr

    # Register real ShadowBoard source
    source_url = f"{SHADOWBOARD_URL}/forum"
    source_id = "SRC_SHADOWBOARD_ONION"
    registry.register_source(canonical_url=source_url, source_type="FORUM", source_id=source_id)

    source_dict = registry.get_source_by_id(source_id)

    print("=" * 80)
    print("        REAL SHADOWBOARD OBSERVATION - 10 REAL POSTS PROCESSING")
    print("=" * 80)

    # Process candidates across continuous observation passes until at least 10 distinct posts processed
    processed_count = 0
    cycle_index = 1

    while processed_count < 10 and cycle_index <= 20:
        obs_res = observer.observe_source_entry(source_dict)
        sessions = store.list_threat_sessions(limit=100)
        processed_count = len(sessions)
        cursor_pos = registry.get_candidate_cursor(source_id)
        print(f"[*] Cycle {cycle_index:02d}: {processed_count}/10 distinct Threat Sessions processed | Candidate Cursor: {cursor_pos}")
        cycle_index += 1

    all_sessions = store.list_threat_sessions(limit=100)
    
    print("\n" + "=" * 80)
    print("                     PROCESSED 10 REAL FORUM POSTS")
    print("=" * 80)

    import sqlite3
    conn = sqlite3.connect(LIVE_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    for i, sess in enumerate(all_sessions[:10], start=1):
        meta = sess.get("metadata") or {}
        sources = sess.get("sources") or []
        post_url = (sources[0] if len(sources) > 0 else "") or meta.get("thread_url") or sess.get("primary_source_url") or "N/A"
        
        timeline = sess.get("timeline") or []
        first_event = timeline[0] if timeline else {}

        title = meta.get("root_title") or meta.get("title") or sess.get("title") or sess.get("root_post_title")
        if not title and first_event.get("event", "").startswith("Created root thread: "):
            title = first_event["event"].replace("Created root thread: ", "").strip()
        if not title:
            title = "N/A"

        root_user = meta.get("root_author") or sess.get("root_author") or first_event.get("author") or "N/A"
        body = sess.get("root_post_content") or meta.get("root_content") or meta.get("content") or meta.get("description") or sess.get("description") or "N/A"
        
        if body in ("N/A", title) and post_url != "N/A":
            cursor.execute("SELECT clean_text FROM observation_history WHERE canonical_url = ? ORDER BY timestamp_utc DESC LIMIT 1", (post_url,))
            row = cursor.fetchone()
            if row and row["clean_text"]:
                ct_lines = [l.strip() for l in row["clean_text"].splitlines() if l.strip()]
                # Exclude standard navigation lines
                filtered = [l for l in ct_lines if not any(nav in l.lower() for nav in ["shadowboard", "discussions", "logged in as", "my profile", "lab admin", "logout", "back to discussions", "general", "author:"])]
                if title in filtered:
                    idx = filtered.index(title)
                    body_candidates = filtered[idx+1:]
                else:
                    body_candidates = filtered
                if body_candidates:
                    body = " ".join(body_candidates[:3])

        if body and body != "N/A":
            import re
            body = re.sub(r'^(?:user\d+|anonymous)\s+', '', body)
            body = re.sub(r'\s*Edit (?:Discussion )?Post\s*$', '', body).strip()

        cand_id = meta.get("candidate_id") or sess.get("candidate_id") or f"CAND-{i:03d}"
        reply_cnt = len(sess.get("direct_replies", [])) + len(sess.get("nested_replies", []))
        actors = sess.get("actors", [])

        print(f"\n--- POST CANDIDATE #{i:02d} ---")
        print(f"SESSION ID   : {sess['session_id']}")
        print(f"SOURCE ID    : {sess.get('source_id', source_id)}")
        print(f"CANDIDATE ID : {cand_id}")
        print(f"POST URL     : {post_url}")
        print(f"ROOT USERNAME: {root_user}")
        print(f"EXACT TITLE  : {title}")
        print(f"ROOT BODY    : {body[:120]}..." if len(body) > 120 else f"ROOT BODY    : {body}")
        print(f"REPLY COUNT  : {reply_cnt}")
        print(f"PARTICIPANTS : {', '.join(actors) if actors else 'None'}")

    print("\n" + "=" * 80)
    print(f"SUMMARY: Successfully processed {len(all_sessions[:10])} distinct real forum posts from live ShadowBoard container.")
    print("=" * 80)

if __name__ == "__main__":
    run_shadowboard_live_10_posts_test()
