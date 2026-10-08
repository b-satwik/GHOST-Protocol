"""
ShadowBoard / Dread Laboratory Adapter for GHOST Protocol.
Preserves existing Dread/ShadowBoard /post/<id> candidate discovery and thread extraction.
"""

import re
import uuid
import datetime
import copy
from typing import Dict, Any, List
from src.observer.adapters.base_adapter import BaseSourceAdapter
from src.filter.threat_filter import ThreatFilter


class ShadowBoardAdapter(BaseSourceAdapter):
    """
    Adapter for ShadowBoard Docker Lab and Dread-compatible forums.
    """

    source_type: str = "SHADOWBOARD_LAB"

    def match_url(self, url: str, raw_html: str = "") -> bool:
        url_lower = url.lower()
        comb = f"{url_lower}\n{raw_html.lower()}"
        return any(kw in comb for kw in ["shadowboard", "dread", ":8080", "/d/", "/post/"])

    def extract_candidate_links(self, url: str, raw_html: str) -> List[str]:
        if not raw_html:
            return []

        post_urls = set()
        base_clean = url.rstrip("/")
        if "://" in base_clean:
            domain_base = "/".join(base_clean.split("/")[:3])
        else:
            domain_base = base_clean

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw_html, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if "/post/" in href or "/thread/" in href or "/discussion/" in href:
                    if href.startswith("http://") or href.startswith("https://"):
                        full_url = href.split("#")[0].rstrip("/")
                    else:
                        if not href.startswith("/"):
                            href = "/" + href
                        full_url = (domain_base + href).split("#")[0].rstrip("/")
                    if full_url and full_url != base_clean and full_url != domain_base:
                        post_urls.add(full_url)
        except Exception:
            pass

        # Regex fallback for /post/<id>
        matches = re.findall(r'/post/([a-zA-Z0-9_-]+)', raw_html)
        for m in matches:
            full_url = f"{domain_base}/post/{m}"
            if full_url != base_clean:
                post_urls.add(full_url)

        return sorted(list(post_urls))

    def classify_page_type(self, url: str, raw_html: str, clean_text: str, thread_info: Dict[str, Any]) -> str:
        url_lower = url.lower()
        comb = f"{clean_text}\n{raw_html}".lower()

        if any(p_kw in url_lower for p_kw in ["/u/", "/user/", "/profile/"]):
            return "PROFILE"

        if any(nav_kw in url_lower for nav_kw in ["/rules", "/faq", "/help", "/search", "/settings", "/terms"]):
            return "NAVIGATION"

        title = (thread_info.get("title") or "").lower()
        ann_keywords = [
            "[announcement]", "announcement", "sticky:", "pinned", "forum rules", "dread rules",
            "dread update", "welcome to dread", "system notice", "platform notice", "terms of service",
            "dread wiki", "official notice", "read the rules", "community rules", "re-vamped dread", "re-vamped"
        ]
        if any(ak in title for ak in ann_keywords) or any(ak in comb[:500] for ak in ann_keywords):
            return "ANNOUNCEMENT"
        if "/d/community/post/rev-" in url_lower or "/d/announcements/" in url_lower:
            return "ANNOUNCEMENT"

        if "/d/" in url_lower and "/post/" not in url_lower:
            if "community rules" in comb[:500] or "subdread info" in comb[:500] or "community information" in comb[:500]:
                return "COMMUNITY_INFO"
            return "FRONT_PAGE"

        if "/post/" not in url_lower:
            return "FRONT_PAGE"

        return "THREAD_PAGE"

    def extract_thread_info(self, url: str, raw_html: str) -> Dict[str, Any]:
        thread_info = {
            "post_id": None,
            "title": None,
            "content": None,
            "author": None,
            "timestamp": None,
            "reported_comments_count": 0,
            "observed_comments_count": 0,
            "direct_replies": [],
            "nested_replies": []
        }

        if not raw_html:
            return thread_info

        try:
            import hashlib
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw_html, "html.parser")

            post_id_match = re.search(r'/post/([a-zA-Z0-9_-]+)', url)
            if post_id_match:
                thread_info["post_id"] = f"post_{post_id_match.group(1)}"

            # Locate root post container explicitly
            root_container = (
                soup.find(id="post-root") or
                soup.find(class_=["post-detail", "post-card", "main-post"]) or
                soup.find("div", class_=["card", "post"])
            )

            if not root_container:
                all_cards = soup.find_all(class_=["post-card", "card", "post"])
                if all_cards:
                    root_container = all_cards[0]

            search_scope = root_container if root_container else soup

            # Root Title
            title_el = search_scope.find(class_=["post-title", "thread-title", "title"]) or soup.find(class_=["post-title", "thread-title"]) or soup.find(["h1", "h2"])
            if title_el:
                t_text = title_el.get_text().strip()
                if not any(b in t_text.lower() for b in ["access queue", "login", "2-step", "user profile", "discussions", "dashboard"]):
                    thread_info["title"] = t_text

            # Root Author
            author_el = search_scope.find(class_=["user-badge", "author", "username", "poster"])
            if author_el:
                a_text = author_el.get_text().strip()
                a_clean = re.sub(r'^(?:/u/|u/)', '', a_text).strip()
                if a_clean.endswith('A') and len(a_clean) > 2 and not a_clean.lower().startswith('http'):
                    a_clean = a_clean[:-1]
                if a_clean and len(a_clean) < 40 and "login" not in a_clean.lower() and "profile" not in a_clean.lower():
                    thread_info["author"] = a_clean

            # Root Timestamp
            time_el = search_scope.find("time") or search_scope.find(class_=["timestamp", "date", "post-time"])
            if time_el:
                thread_info["timestamp"] = time_el.get_text().strip()

            # Root Body Content strictly from root body element
            body_el = search_scope.find(class_=["post-content", "post-body", "message-body", "thread-body", "entry-content"])
            if body_el:
                body_clone = copy.copy(body_el)
                for noise in body_clone.find_all(class_=["user-badge", "meta-tag", "btn", "timestamp", "reply-form"]):
                    noise.decompose()
                c_lines = [l.strip() for l in body_clone.get_text().splitlines() if l.strip()]
                thread_info["content"] = "\n".join(c_lines)
            elif root_container:
                c_clone = copy.copy(root_container)
                for noise in c_clone.find_all(class_=["nested-comment", "comment-tree", "btn", "nav", "header", "user-badge", "meta-tag"]):
                    noise.decompose()
                c_lines = [l.strip() for l in c_clone.get_text().splitlines() if l.strip() and not any(k in l.lower() for k in ["logged in as", "my profile", "lab admin", "logout", "start a new discussion"])]
                thread_info["content"] = "\n".join(c_lines)
            # If body element is missing, thread_info["content"] remains None

            if not thread_info["post_id"]:
                if thread_info["title"]:
                    thread_info["post_id"] = f"post_{hash(thread_info['title']) & 0xffff:04x}"
                else:
                    thread_info["post_id"] = f"post_{hash(url) & 0xffff:04x}"

            # Extract replies from comment tree / nested comments strictly
            comment_tree = soup.find(class_=["comment-tree", "comments-section"]) or soup
            comments = comment_tree.find_all(class_=["nested-comment", "comment", "reply"])

            for comment in comments:
                raw_id = comment.get("id", "").strip()
                if raw_id:
                    clean_id = raw_id.replace("reply-", "").replace("comment-", "")
                    r_id = f"reply_{clean_id}"
                else:
                    c_text_preview = comment.get_text().strip()[:40]
                    stable_hash = hashlib.sha256(f"{c_text_preview}_{url}".encode("utf-8")).hexdigest()[:10]
                    r_id = f"reply_{stable_hash}"

                c_author_el = comment.find(class_=["user-badge", "author", "username"])
                if c_author_el:
                    c_author = c_author_el.get_text().strip()
                    c_author = re.sub(r'^/u/', '', c_author).strip()
                    if c_author.endswith('A') and len(c_author) > 2 and not c_author.lower().startswith('http'):
                        c_author = c_author[:-1]
                else:
                    c_author = "anonymous" if "anonymous" in comment.get_text().lower() else "UNKNOWN"

                c_time = ""
                time_el = comment.find("time") or comment.find("span", class_=["timestamp", "text-muted"])
                if time_el:
                    c_time = time_el.get_text().strip()

                c_clone = copy.copy(comment)
                for sub_c in c_clone.find_all(class_=["nested-comment", "comment", "reply"]):
                    sub_c.decompose()

                for btn in c_clone.find_all(["button", "a"], class_=["btn", "user-badge"]):
                    if btn.name == "button" or "btn" in btn.get("class", []):
                        btn.decompose()

                c_raw = c_clone.get_text().strip()
                c_lines = [l.strip() for l in c_raw.splitlines() if l.strip() and not any(k in l.lower() for k in ["logged in as", "my profile", "edit", "reply"])]
                c_msg = "\n".join(c_lines)

                parent_comment = comment.find_parent(class_=["nested-comment", "comment"])
                parent_reply_id = None
                if parent_comment and parent_comment.get("id"):
                    parent_reply_id = f"reply_{parent_comment.get('id').replace('reply-', '').replace('comment-', '')}"

                reply_obj = {
                    "reply_id": r_id,
                    "username": c_author,
                    "timestamp": c_time or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    "message": c_msg,
                    "reply_to": parent_reply_id or thread_info["post_id"]
                }

                if parent_reply_id:
                    thread_info["nested_replies"].append(reply_obj)
                else:
                    thread_info["direct_replies"].append(reply_obj)

            thread_info["observed_comments_count"] = len(thread_info["direct_replies"]) + len(thread_info["nested_replies"])
            thread_info["reported_comments_count"] = max(thread_info.get("reported_comments_count", 0), thread_info["observed_comments_count"])

            # Set root author and title from synthetic thread creation message ONLY if present
            if thread_info["direct_replies"]:
                first_r = thread_info["direct_replies"][0]
                msg_text = first_r.get("message", "")
                if "Created root thread:" in msg_text:
                    extracted_title = msg_text.split("Created root thread:")[-1].strip().strip('"').strip()
                    if extracted_title:
                        thread_info["title"] = extracted_title
                        thread_info["content"] = msg_text
                    if first_r.get("username") and first_r.get("username") not in ("UNKNOWN", "anonymous"):
                        thread_info["author"] = first_r.get("username")

        except Exception as e:
            print(f"[-] ShadowBoardAdapter parse warning: {e}")

        return thread_info
