"""
XenForo Forum Adapter for GHOST Protocol (BlackHatWorld & Darknet77 .onion).
"""

import re
import uuid
import datetime
import copy
from typing import Dict, Any, List
from src.observer.adapters.base_adapter import BaseSourceAdapter


class XenForoAdapter(BaseSourceAdapter):
    """
    Adapter for XenForo-based forums such as BlackHatWorld and Darknet77 .onion.
    """

    source_type: str = "XENFORO_FORUM"

    def match_url(self, url: str, raw_html: str = "") -> bool:
        url_lower = url.lower()
        comb = f"{url_lower}\n{raw_html.lower()}"
        return any(kw in comb for kw in ["blackhatworld.com", "darknet77", "xenforo", "/threads/", "/forums/", "/seo/"])

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
                if ("/threads/" in href or "/seo/" in href) and not href.endswith("/unread") and not href.endswith(".rss"):
                    if href.startswith("http://") or href.startswith("https://"):
                        full_url = href.split("#")[0].rstrip("/")
                    else:
                        if not href.startswith("/"):
                            href = "/" + href
                        full_url = (domain_base + href).split("#")[0].rstrip("/")
                    if "/post-" in full_url:
                        full_url = full_url.split("/post-")[0]
                    if full_url and full_url != base_clean and full_url != domain_base:
                        post_urls.add(full_url)
        except Exception:
            pass

        # Regex fallback for XenForo thread links: /threads/title.12345/ or /seo/title.12345/
        matches = re.findall(r'/(?:threads|seo)/([a-zA-Z0-9_.-]+\.\d+)/?', raw_html)
        prefix = "/seo/" if "blackhatworld.com" in url or "/seo/" in raw_html else "/threads/"
        for m in matches:
            full_url = f"{domain_base}{prefix}{m}"
            if full_url != base_clean:
                post_urls.add(full_url)

        return sorted(list(post_urls))

    def classify_page_type(self, url: str, raw_html: str, clean_text: str, thread_info: Dict[str, Any]) -> str:
        url_lower = url.lower()
        comb = f"{clean_text}\n{raw_html}".lower()

        if any(p_kw in url_lower for p_kw in ["/members/", "/u/", "/user/"]):
            return "PROFILE"

        if any(nav_kw in url_lower for nav_kw in ["/help/", "/rules", "/terms", "/search/"]):
            return "NAVIGATION"

        title = (thread_info.get("title") or "").lower()
        ann_keywords = ["sticky:", "pinned", "[announcement]", "forum rules", "terms of service", "official notice"]
        if any(ak in title for ak in ann_keywords) or any(ak in comb[:400] for ak in ann_keywords):
            return "ANNOUNCEMENT"

        if "/threads/" not in url_lower and "/seo/" not in url_lower:
            if "/forums/" in url_lower:
                return "CATEGORY"
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
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw_html, "html.parser")

            # XenForo thread ID: /threads/title.12345/ or /seo/title.12345/
            thread_id_match = re.search(r'/(?:threads|seo)/[^/]+\.(\d+)', url)
            if thread_id_match:
                thread_info["post_id"] = f"thread_{thread_id_match.group(1)}"

            # Title
            title_el = soup.find(class_=["p-title-value", "title", "thread-title"]) or soup.find("h1")
            if title_el:
                t_str = title_el.get_text().strip()
                if t_str and len(t_str) < 200:
                    thread_info["title"] = t_str

            # Message items
            messages = soup.find_all(class_=["message--post", "message", "post-item"])
            root_msg = messages[0] if messages else soup

            # Author
            author_el = root_msg.find(class_=["username", "message-name"]) or root_msg.find(attrs={"data-author": True})
            if author_el:
                a_str = author_el.get("data-author") or author_el.get_text().strip()
                if a_str and len(a_str) < 40:
                    thread_info["author"] = a_str

            # Timestamp
            time_el = root_msg.find("time") or root_msg.find(class_=["u-dt", "timestamp"])
            if time_el:
                thread_info["timestamp"] = time_el.get("datetime") or time_el.get_text().strip()

            # Content body
            body_el = root_msg.find(class_=["bbWrapper", "message-body", "message-content"])
            if body_el:
                thread_info["content"] = body_el.get_text().strip()
            else:
                body_lines = [line.strip() for line in root_msg.get_text().splitlines() if len(line.strip()) > 10]
                thread_info["content"] = "\n".join(body_lines[:15]) if body_lines else (thread_info["title"] or "Content Unavailable")

            if not thread_info["post_id"]:
                thread_info["post_id"] = f"thread_{hash(url) & 0xffff:04x}"

            # Replies (messages 1+)
            if len(messages) > 1:
                import hashlib
                for idx, reply_el in enumerate(messages[1:], start=1):
                    raw_id = reply_el.get("id") or reply_el.get("data-content-id") or reply_el.get("data-post-id")
                    r_author = "anonymous"
                    r_author_el = reply_el.find(class_=["username", "message-name"]) or reply_el.find(attrs={"data-author": True})
                    if r_author_el:
                        r_author = r_author_el.get("data-author") or r_author_el.get_text().strip()

                    r_time = ""
                    r_time_el = reply_el.find("time")
                    if r_time_el:
                        r_time = r_time_el.get("datetime") or r_time_el.get_text().strip()

                    r_body = reply_el.find(class_=["bbWrapper", "message-body"])
                    r_text = r_body.get_text().strip() if r_body else reply_el.get_text().strip()

                    if raw_id:
                        r_id = f"reply_{str(raw_id).replace('post-', '').replace('js-post-', '')}"
                    else:
                        stable_hash = hashlib.sha256(f"{r_author}_{r_time}_{r_text[:30]}".encode()).hexdigest()[:10]
                        r_id = f"reply_{stable_hash}"

                    reply_obj = {
                        "reply_id": r_id,
                        "username": r_author,
                        "timestamp": r_time or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "message": r_text,
                        "reply_to": thread_info["post_id"]
                    }
                    thread_info["direct_replies"].append(reply_obj)

            # Reported reply count
            rep_cnt_el = soup.find(class_=["pairs--inline", "reply-count", "message-count"])
            if rep_cnt_el:
                m = re.search(r'(\d+)', rep_cnt_el.get_text())
                if m:
                    thread_info["reported_comments_count"] = int(m.group(1))

            thread_info["observed_comments_count"] = len(thread_info["direct_replies"])
            thread_info["reported_comments_count"] = max(thread_info["reported_comments_count"], thread_info["observed_comments_count"])

        except Exception as e:
            print(f"[-] XenForoAdapter parse error: {e}")

        return thread_info
