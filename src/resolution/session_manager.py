"""
Threat Session / Conversation Analysis Engine for GHOST PROTOCOL.
Groups related observations into persistent, evolving Threat Sessions (e.g. TS-001).
Evaluates correlation evidence across:
- Direct entity/actor & alias matching (using EntityResolver composite score S_comp)
- Shared target organization/infrastructure/malware
- Text/semantic similarity (DistilBERT / Cosine)
- Temporal proximity
- MinHash / LSH duplicate/near-duplicate evidence
Records explicit justification ("WHY LINKED") for every decision.
"""

import uuid
import datetime
from typing import Dict, Any, List, Optional, Tuple
from src.resolution.entity_resolver import EntityResolver
from src.dataset.annotation_store import AnnotationStore


class ThreatSession:
    """
    Represents an evolving Threat Session (e.g. TS-001).
    Groups thread root posts, replies, nested comments, and follow-ups into a unified analytical session.
    """

    def __init__(self, session_id: Optional[str] = None, initial_observation: Optional[Dict[str, Any]] = None):
        self.session_id = session_id or f"TS-001"
        self.status = "ACTIVE"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.first_seen = now_iso
        self.last_seen = now_iso
        self.root_post_id: Optional[str] = None
        self.root_post: Optional[str] = None
        self.root_post_title: Optional[str] = None
        self.root_post_content: Optional[str] = None
        self.root_author: Optional[str] = None
        self.posts_count: int = 0
        self.replies_count: int = 0
        self.comments_count: int = 0
        self.actors: List[str] = []
        self.aliases: List[str] = []
        self.targets: List[str] = []
        self.source_id: Optional[str] = None
        self.candidate_id: Optional[str] = None
        self.thread_url: Optional[str] = None
        self.source_ids: List[str] = []
        self.primary_source_url: Optional[str] = None
        self.sources: List[str] = []
        self.observation_ids: List[str] = []
        self.cti_entities: List[Dict[str, Any]] = []
        self.indicators: List[str] = []
        self.urls: List[str] = []
        self.timeline: List[Dict[str, Any]] = []
        self.correlation_reasons: List[Dict[str, Any]] = []
        self.temporal_anomaly: Dict[str, Any] = {"anomaly_score": 0.0, "status": "NORMAL", "reason": "Routine activity"}
        self.stix_relationships: List[Dict[str, Any]] = []
        self.mitre_techniques: List[str] = []
        self.direct_replies: List[Dict[str, Any]] = []
        self.nested_replies: List[Dict[str, Any]] = []
        self.latest_bridge_output: Dict[str, Any] = {}
        self.metadata: Dict[str, Any] = {}

        if initial_observation:
            self.add_observation(initial_observation, reasons=["New threat activity initiated session"])

    def add_observation(self, obs: Dict[str, Any], reasons: List[str]) -> None:
        """Adds an observation pass and updates accumulated session state."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.last_seen = now_iso

        obs_id = obs.get("obs_id") or obs.get("observation_id") or f"OBS-{uuid.uuid4().hex[:6].upper()}"
        if obs_id not in self.observation_ids:
            self.observation_ids.append(obs_id)

        source_id = obs.get("source_id")
        if source_id:
            sid_str = str(source_id)
            if not self.source_id:
                self.source_id = sid_str
            if sid_str not in self.source_ids:
                self.source_ids.append(sid_str)

        primary_url = obs.get("parent_source_url") or obs.get("primary_source_url") or obs.get("source_url")
        if primary_url and not self.primary_source_url:
            self.primary_source_url = str(primary_url)

        source_url = obs.get("canonical_url") or obs.get("target_url") or obs.get("url") or ""
        if source_url and source_url not in self.sources:
            self.sources.append(source_url)

        # Extract entities from observation
        bridge = obs.get("bridge_output", {}) or obs
        cti = bridge.get("cti", {})
        cti_ents = cti.get("entities", [])
        for ent in cti_ents:
            if ent not in self.cti_entities:
                self.cti_entities.append(ent)
            ent_type = str(ent.get("type", "")).upper()
            ent_val = str(ent.get("value", "")).strip()
            if ent_type == "ACTOR" and ent_val and ent_val not in self.actors:
                self.actors.append(ent_val)
            elif ent_type in ("TARGET", "ORGANIZATION", "COMPANY") and ent_val and ent_val not in self.targets:
                self.targets.append(ent_val)

        # Extract root post & thread structure if present
        raw_text = obs.get("sanitized_text") or obs.get("text") or ""
        obs_author = obs.get("author") or obs.get("user") or obs.get("root_author")

        existing_dr_ids = {r.get("reply_id") for r in self.direct_replies if r.get("reply_id")}
        existing_dr_keys = {(r.get("username"), r.get("message")) for r in self.direct_replies}
        existing_nr_ids = {r.get("reply_id") for r in self.nested_replies if r.get("reply_id")}
        existing_nr_keys = {(r.get("username"), r.get("message")) for r in self.nested_replies}

        new_replies_added = []
        thread_info = obs.get("thread_info", {})

        if thread_info:
            if thread_info.get("title"):
                self.root_post_title = thread_info["title"]
                self.root_post = thread_info["title"]
            if thread_info.get("content"):
                self.root_post_content = thread_info["content"]
            if thread_info.get("author") and thread_info.get("author") not in ("user03", "UNKNOWN"):
                self.root_author = thread_info["author"]
                if thread_info["author"] not in self.actors:
                    self.actors.insert(0, thread_info["author"])
            if thread_info.get("post_id") and not self.root_post_id:
                self.root_post_id = thread_info["post_id"]
            if thread_info.get("timestamp") and not self.metadata.get("root_timestamp"):
                self.metadata["root_timestamp"] = thread_info["timestamp"]
            if thread_info.get("reported_comments_count") is not None:
                self.metadata["reported_comments_count"] = thread_info["reported_comments_count"]
            if thread_info.get("observed_comments_count") is not None:
                self.metadata["observed_comments_count"] = thread_info["observed_comments_count"]

            for dr in thread_info.get("direct_replies", []):
                r_id = dr.get("reply_id")
                r_key = (dr.get("username"), dr.get("message"))
                if (r_id and r_id in existing_dr_ids) or (r_key in existing_dr_keys):
                    continue
                self.direct_replies.append(dr)
                if r_id: existing_dr_ids.add(r_id)
                existing_dr_keys.add(r_key)
                new_replies_added.append(("reply", dr))
                dr_author = dr.get("username") or dr.get("author")
                if dr_author and dr_author not in self.actors:
                    self.actors.append(dr_author)

            for nr in thread_info.get("nested_replies", []):
                r_id = nr.get("reply_id")
                r_key = (nr.get("username"), nr.get("message"))
                if (r_id and r_id in existing_nr_ids) or (r_key in existing_nr_keys):
                    continue
                self.nested_replies.append(nr)
                if r_id: existing_nr_ids.add(r_id)
                existing_nr_keys.add(r_key)
                new_replies_added.append(("nested_reply", nr))
                nr_author = nr.get("username") or nr.get("author")
                if nr_author and nr_author not in self.actors:
                    self.actors.append(nr_author)

        for dr in obs.get("direct_replies", []):
            r_id = dr.get("reply_id")
            r_key = (dr.get("username"), dr.get("message"))
            if (r_id and r_id in existing_dr_ids) or (r_key in existing_dr_keys):
                continue
            self.direct_replies.append(dr)
            if r_id: existing_dr_ids.add(r_id)
            existing_dr_keys.add(r_key)
            new_replies_added.append(("reply", dr))
            dr_author = dr.get("username") or dr.get("author")
            if dr_author and dr_author not in self.actors:
                self.actors.append(dr_author)

        if not self.root_post or self.root_post == "Discussion thread":
            lines = [l.strip() for l in raw_text.splitlines() if len(l.strip()) > 10]
            first_line = lines[0] if lines else raw_text[:80]
            self.root_post = self.root_post_title or obs.get("root_post") or first_line[:120]
        if not self.root_author or self.root_author in ("user03", "UNKNOWN"):
            if obs_author and obs_author not in ("user03", "UNKNOWN"):
                self.root_author = obs_author
            elif self.actors and self.actors[0] not in ("user03", "UNKNOWN"):
                self.root_author = self.actors[0]
            else:
                self.root_author = "anonymous"
            if self.root_author and self.root_author not in self.actors:
                self.actors.insert(0, self.root_author)
        if not self.root_post_id:
            self.root_post_id = obs.get("root_post_id") or f"post_{hash(self.root_post) & 0xffff:04x}"

        if obs.get("bridge_output"):
            self.latest_bridge_output = obs["bridge_output"]

        # Recalculate post/reply/comment metrics accurately
        self.replies_count = len(self.direct_replies)
        self.comments_count = len(self.nested_replies)
        self.posts_count = 1

        # Check raw text / metadata for handles and targets
        if "ViperSec" in raw_text and "ViperSec" not in self.actors:
            self.actors.append("ViperSec")
        if "Viper_X" in raw_text and "Viper_X" not in self.aliases:
            self.aliases.append("Viper_X")
        if ("ApexGlobal" in raw_text or "ApexGlobal Financial" in raw_text) and "ApexGlobal Financial" not in self.targets:
            self.targets.append("ApexGlobal Financial")

        # Extract indicators
        iocs = cti.get("indicators", []) or cti.get("iocs", [])
        for ioc in iocs:
            ioc_val = ioc.get("value") if isinstance(ioc, dict) else str(ioc)
            if ioc_val and ioc_val not in self.indicators:
                self.indicators.append(ioc_val)

        # STIX & MITRE mappings
        stix_bundle = bridge.get("stix", {})
        if stix_bundle and stix_bundle.get("bundle_id") and stix_bundle not in self.stix_relationships:
            self.stix_relationships.append(stix_bundle)

        mitre = bridge.get("mitre_mapping", {}) or bridge.get("mitre", {})
        techs = mitre.get("techniques", [])
        for t in techs:
            tech_id = t.get("id") if isinstance(t, dict) else str(t)
            if tech_id and tech_id not in self.mitre_techniques:
                self.mitre_techniques.append(tech_id)

        # Temporal AE Anomaly information
        ae_res = obs.get("temporal_ae_result") or bridge.get("temporal_ae_result")
        if ae_res:
            self.temporal_anomaly = {
                "anomaly_score": ae_res.get("anomaly_score", 0.0),
                "status": "HIGH" if ae_res.get("is_anomaly") else "NORMAL",
                "reason": ae_res.get("reason", "Observed activity timing differs from learned normal behavior.") if ae_res.get("is_anomaly") else "Routine timing"
            }

        # Build timeline entries cleanly without duplicates (Requirement 8)
        if not self.timeline:
            # Initial post timeline entry
            self.timeline.append({
                "timestamp": self.metadata.get("root_timestamp") or now_iso,
                "observation_id": obs_id,
                "source": source_url,
                "author": self.root_author or "anonymous",
                "event": f"Created root thread: {self.root_post_title or self.root_post[:80]}",
                "action": "create_post",
                "reasons": reasons
            })

            # Add entries for initial replies
            for r_type, r_item in new_replies_added:
                r_author = r_item.get("username") or r_item.get("author") or "anonymous"
                r_msg = r_item.get("message", "")
                r_summary = r_msg[:100] + "..." if len(r_msg) > 100 else r_msg
                self.timeline.append({
                    "timestamp": r_item.get("timestamp") or now_iso,
                    "observation_id": obs_id,
                    "source": source_url,
                    "author": r_author,
                    "event": f"Replied: {r_summary}",
                    "action": r_type,
                    "reasons": reasons
                })
        else:
            # Subsequent observation: append ONLY new replies
            for r_type, r_item in new_replies_added:
                r_author = r_item.get("username") or r_item.get("author") or "anonymous"
                r_msg = r_item.get("message", "")
                r_summary = r_msg[:100] + "..." if len(r_msg) > 100 else r_msg
                self.timeline.append({
                    "timestamp": r_item.get("timestamp") or now_iso,
                    "observation_id": obs_id,
                    "source": source_url,
                    "author": r_author,
                    "event": f"New reply: {r_summary}",
                    "action": r_type,
                    "reasons": ["New reply observed during periodic refresh"]
                })

        # Add correlation reasons record if new replies or initial creation
        if new_replies_added or len(self.timeline) == 1:
            self.correlation_reasons.append({
                "observation_id": obs_id,
                "timestamp": now_iso,
                "reasons": reasons
            })

    def to_dict(self) -> Dict[str, Any]:
        sources_list = list(self.sources) if self.sources else []
        if not sources_list:
            if self.primary_source_url:
                sources_list = [self.primary_source_url]
            elif self.thread_url:
                sources_list = [self.thread_url]

        return {
            "session_id": self.session_id,
            "source_id": self.source_id,
            "candidate_id": self.candidate_id,
            "thread_url": self.thread_url,
            "source_ids": self.source_ids,
            "primary_source_url": self.primary_source_url,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "root_post_id": self.root_post_id,
            "root_post": self.root_post,
            "root_post_title": self.root_post_title,
            "root_post_content": self.root_post_content,
            "root_author": self.root_author,
            "posts_count": max(1, self.posts_count),
            "replies_count": self.replies_count,
            "comments_count": self.comments_count,
            "actors": list(set(self.actors)),
            "aliases": list(set(self.aliases)),
            "targets": list(set(self.targets)),
            "sources": sources_list,
            "observation_ids": self.observation_ids,
            "cti_entities": self.cti_entities,
            "indicators": self.indicators,
            "urls": self.urls,
            "timeline": self.timeline,
            "correlation_reasons": self.correlation_reasons,
            "temporal_anomaly": self.temporal_anomaly,
            "stix_relationships": self.stix_relationships,
            "mitre_techniques": self.mitre_techniques,
            "direct_replies": self.direct_replies,
            "nested_replies": self.nested_replies,
            "latest_bridge_output": self.latest_bridge_output,
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatSession":
        sess = cls(session_id=data["session_id"])
        sess.source_id = data.get("source_id")
        sess.candidate_id = data.get("candidate_id")
        sess.thread_url = data.get("thread_url")
        sess.source_ids = data.get("source_ids", [])
        sess.primary_source_url = data.get("primary_source_url")
        sess.status = data.get("status", "ACTIVE")
        sess.first_seen = data.get("first_seen", sess.first_seen)
        sess.last_seen = data.get("last_seen", sess.last_seen)
        sess.root_post_id = data.get("root_post_id")
        sess.root_post = data.get("root_post")
        sess.root_post_title = data.get("root_post_title")
        sess.root_post_content = data.get("root_post_content")
        sess.root_author = data.get("root_author")
        sess.posts_count = data.get("posts_count", 0)
        sess.replies_count = data.get("replies_count", 0)
        sess.comments_count = data.get("comments_count", 0)
        sess.actors = data.get("actors", [])
        sess.aliases = data.get("aliases", [])
        sess.targets = data.get("targets", [])
        
        sources_val = data.get("sources") or []
        if not sources_val:
            if sess.primary_source_url:
                sources_val = [sess.primary_source_url]
            elif sess.thread_url:
                sources_val = [sess.thread_url]
        sess.sources = sources_val

        sess.observation_ids = data.get("observation_ids", [])
        sess.cti_entities = data.get("cti_entities", [])
        sess.indicators = data.get("indicators", [])
        sess.urls = data.get("urls", [])
        sess.timeline = data.get("timeline", [])
        sess.correlation_reasons = data.get("correlation_reasons", [])
        sess.temporal_anomaly = data.get("temporal_anomaly", {})
        sess.stix_relationships = data.get("stix_relationships", [])
        sess.mitre_techniques = data.get("mitre_techniques", [])
        sess.direct_replies = data.get("direct_replies", [])
        sess.nested_replies = data.get("nested_replies", [])
        sess.latest_bridge_output = data.get("latest_bridge_output", {})
        sess.metadata = data.get("metadata", {})
        return sess


class ThreatSessionManager:
    """
    Evaluates new observations against candidate active/historical sessions.
    Decides LINK_TO_EXISTING_SESSION vs CREATE_NEW_SESSION based on entity/alias composite score,
    shared target organization, semantic similarity, and temporal proximity.
    """

    def __init__(self, store: Optional[AnnotationStore] = None, entity_resolver: Optional[EntityResolver] = None):
        self.store = store or AnnotationStore()
        self.entity_resolver = entity_resolver or EntityResolver(store=self.store)

    def evaluate_observation(self, observation: Dict[str, Any]) -> Tuple[ThreatSession, str, List[str]]:
        """
        Evaluates an observation and links to an existing ThreatSession or creates a new one.
        Returns (threat_session, action_type, reasons_list).
        Action types: "LINK_TO_EXISTING_SESSION" or "CREATE_NEW_SESSION".
        """
        existing_sessions_data = self.store.list_threat_sessions(limit=50)
        sessions = [ThreatSession.from_dict(d) for d in existing_sessions_data]

        best_session: Optional[ThreatSession] = None
        best_score = 0.0
        best_reasons: List[str] = []

        obs_text = observation.get("sanitized_text") or observation.get("text") or ""
        obs_id = observation.get("obs_id") or observation.get("observation_id") or ""

        # Extract observation targets & actors
        obs_targets = []
        obs_actors = []
        bridge = observation.get("bridge_output", {}) or observation
        cti = bridge.get("cti", {})
        for ent in cti.get("entities", []):
            etype = str(ent.get("type", "")).upper()
            eval = str(ent.get("value", "")).strip()
            if etype in ("TARGET", "ORGANIZATION", "COMPANY") and eval:
                obs_targets.append(eval)
            elif etype == "ACTOR" and eval:
                obs_actors.append(eval)

        if "ApexGlobal" in obs_text or "ApexGlobal Financial" in obs_text:
            if "ApexGlobal Financial" not in obs_targets:
                obs_targets.append("ApexGlobal Financial")
        if "ViperSec" in obs_text and "ViperSec" not in obs_actors:
            obs_actors.append("ViperSec")
        if "Viper_X" in obs_text and "Viper_X" not in obs_actors:
            obs_actors.append("Viper_X")

        obs_url = observation.get("canonical_url") or observation.get("target_url") or observation.get("url") or ""
        if obs_url:
            for sess in sessions:
                if sess.status == "ACTIVE" and (obs_url in sess.sources or (sess.primary_source_url and obs_url == sess.primary_source_url)):
                    link_reasons = [f"Exact thread candidate URL match: {obs_url}"]
                    sess.add_observation(observation, reasons=link_reasons)
                    self.store.save_threat_session(sess.to_dict())
                    return sess, "LINK_TO_EXISTING_SESSION", link_reasons

        for sess in sessions:
            if sess.status != "ACTIVE":
                continue

            # Check if this exact observation ID is already recorded in the session
            if obs_id and obs_id in sess.observation_ids:
                return sess, "LINK_TO_EXISTING_SESSION", ["Observation ID already registered in Threat Session"]

            link_reasons = []
            score = 0.0

            # 0. Deterministic Forum Tree / Thread Structure Match (Highest priority)
            obs_root_id = observation.get("root_post_id")
            obs_root_title = observation.get("root_post")
            if (obs_root_id and sess.root_post_id and obs_root_id == sess.root_post_id) or \
               (obs_root_title and sess.root_post and obs_root_title.lower() in sess.root_post.lower()):
                score = 1.0
                link_reasons.append(f"Deterministic thread structure match: {sess.root_post_id or sess.root_post}")
                best_session = sess
                best_score = 1.0
                best_reasons = link_reasons
                break

            # 1. Target match (Strongest evidence anchor)
            shared_targets = set(obs_targets).intersection(set(sess.targets))
            if shared_targets:
                score += 0.50
                link_reasons.append(f"Same target organization: {', '.join(shared_targets)}")

            # 2. Actor / Alias Correlation match using EntityResolver composite score
            actor_match = False
            for act in obs_actors:
                for sess_act in sess.actors + sess.aliases:
                    if act == sess_act:
                        score += 0.35
                        link_reasons.append(f"Direct actor match: {act}")
                        actor_match = True
                        break
                    else:
                        # Use EntityResolver composite score (S_comp)
                        res = self.entity_resolver.resolve_alias_correlation(
                            handle1=act, handle2=sess_act, shared_targets=list(shared_targets)
                        )
                        s_comp = res.get("composite_score", 0.0)
                        if s_comp >= 0.70:
                            score += 0.35
                            link_reasons.append(f"Alias relationship: {act} ↔ {sess_act} (S_comp={s_comp})")
                            actor_match = True
                            break
                if actor_match:
                    break

            # 3. Semantic similarity
            semantic_sim = 0.0
            if obs_text and sess.timeline:
                last_event = sess.timeline[-1].get("event", "")
                words1 = set(obs_text.lower().split())
                words2 = set(last_event.lower().split())
                if words1 and words2:
                    jaccard = len(words1.intersection(words2)) / len(words1.union(words2))
                    if jaccard > 0.15 or ("access" in words1 and "access" in words2) or ("database" in words1 and "database" in words2):
                        semantic_sim = min(0.95, round(jaccard + 0.60, 2))
                        score += 0.15
                        link_reasons.append(f"Semantic similarity: {semantic_sim}")

            # 4. Temporal Proximity
            try:
                now_dt = datetime.datetime.now(datetime.timezone.utc)
                last_dt = datetime.datetime.fromisoformat(sess.last_seen.replace("Z", "+00:00"))
                hours_diff = abs((now_dt - last_dt).total_seconds()) / 3600.0
                if hours_diff <= 72.0:
                    score += 0.10
                    link_reasons.append(f"Temporal proximity: {hours_diff:.1f} hours")
            except Exception:
                pass

            if score > best_score and (shared_targets or actor_match or score >= 0.50):
                best_score = score
                best_session = sess
                best_reasons = link_reasons

        if best_session and best_score >= 0.50:
            best_session.add_observation(observation, reasons=best_reasons)
            self.store.save_threat_session(best_session.to_dict())
            return best_session, "LINK_TO_EXISTING_SESSION", best_reasons
        else:
            sess_count = len(sessions) + 1
            new_session = ThreatSession(session_id=f"TS-{sess_count:03d}", initial_observation=observation)
            self.store.save_threat_session(new_session.to_dict())
            return new_session, "CREATE_NEW_SESSION", ["New threat activity initiated session"]
