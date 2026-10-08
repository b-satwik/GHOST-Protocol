"""
User Activity Extractor & Analytics Engine for GHOST PROTOCOL.
Extracts visible usernames, handles, and user activity metrics (posts, replies, threads, edits)
from observed darkweb forum pages and paste dumps, maintaining real observed activity records.
"""

import re
import datetime
from typing import Dict, Any, List, Optional


class UserActivityStore:
    """
    Maintains real observed user activity records, post/reply counts, timelines, and cross-source appearances.
    """

    def __init__(self):
        self.user_records: Dict[str, Dict[str, Any]] = {}

    def extract_and_record_users(self, raw_html: str, clean_text: str, source_id: str, canonical_url: str, timestamp_utc: Optional[str] = None, thread_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Extracts visible usernames strictly from post/reply author DOM elements.
        Never infers usernames from generic regex matches over raw HTML navigation/sidebar.
        """
        ts = timestamp_utc or datetime.datetime.now(datetime.timezone.utc).isoformat()
        extracted = []
        found_usernames = set()

        if thread_info and isinstance(thread_info, dict):
            root_author = thread_info.get("author")
            if root_author and root_author.strip() and root_author.lower() not in ("user01", "user03", "user001", "anonymous", "unknown / not observed"):
                found_usernames.add(root_author.strip())

            for reply in thread_info.get("direct_replies", []) + thread_info.get("nested_replies", []):
                r_author = reply.get("author") if isinstance(reply, dict) else None
                if r_author and r_author.strip() and r_author.lower() not in ("user01", "user03", "user001", "anonymous", "unknown / not observed"):
                    found_usernames.add(r_author.strip())

        # Count specific post/reply actions
        for uname in found_usernames:
            user_key = uname.lower()
            if user_key not in self.user_records:
                self.user_records[user_key] = {
                    "username": uname,
                    "user_id": f"usr_{hash(user_key) & 0xffffff:06x}",
                    "first_seen": ts,
                    "last_seen": ts,
                    "sources": set(),
                    "posts": 0,
                    "replies": 0,
                    "nested_replies": 0,
                    "edits": 0,
                    "threads": 0,
                    "observation_count": 0,
                    "observations": [],
                    "threads_list": [],
                    "related_users": set(),
                    "extracted_entities": set()
                }

            rec = self.user_records[user_key]
            rec["last_seen"] = ts
            rec["sources"].add(source_id)
            rec["observation_count"] += 1
            if canonical_url not in rec["observations"]:
                rec["observations"].append(canonical_url)

            # Measure post vs reply vs thread count from text context
            uname_regex = re.escape(uname)
            posts_count = len(re.findall(rf'{uname_regex}\s*:\s*[^:\n]+', clean_text))
            replies_count = len(re.findall(rf'Re:\s*{uname_regex}|reply\s+by\s+{uname_regex}', clean_text, re.IGNORECASE))
            threads_count = len(re.findall(rf'Thread\s+by\s+{uname_regex}|Author:\s*{uname_regex}', clean_text, re.IGNORECASE))

            rec["posts"] += max(1, posts_count)
            rec["replies"] += replies_count
            rec["threads"] += threads_count

            # Record related users co-occurring in the same observation
            for other_u in found_usernames:
                if other_u.lower() != user_key:
                    rec["related_users"].add(other_u)

            extracted.append(self.get_user_summary(user_key))

        return extracted

    def get_user_summary(self, username_or_key: str) -> Optional[Dict[str, Any]]:
        """Returns structured activity summary for a user."""
        user_key = username_or_key.lower()
        rec = self.user_records.get(user_key)
        if not rec:
            return None

        total_activity = rec["posts"] + rec["replies"] + rec["nested_replies"] + rec["edits"] + rec["threads"]
        return {
            "username": rec["username"],
            "user_id": rec["user_id"],
            "first_seen": rec["first_seen"],
            "last_seen": rec["last_seen"],
            "sources": list(rec["sources"]),
            "posts": rec["posts"],
            "replies": rec["replies"],
            "nested_replies": rec["nested_replies"],
            "edits": rec["edits"],
            "threads": rec["threads"],
            "observation_count": rec["observation_count"],
            "total_activity": total_activity,
            "observations": rec["observations"],
            "related_users": list(rec["related_users"])
        }

    def get_all_user_activity(self) -> List[Dict[str, Any]]:
        """Returns list of all observed users sorted by total activity descending."""
        summaries = [self.get_user_summary(k) for k in self.user_records.keys()]
        return sorted([s for s in summaries if s], key=lambda x: x["total_activity"], reverse=True)

    def get_top_users(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns top users by activity count."""
        all_act = self.get_all_user_activity()
        return [{"username": u["username"], "activity_count": u["total_activity"]} for u in all_act[:limit]]
