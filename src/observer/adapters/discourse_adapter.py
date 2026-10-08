"""
Discourse Forum Adapter for GHOST Protocol (0x00sec.org).
"""

import re
import uuid
import datetime
import copy
from typing import Dict, Any, List
from src.observer.adapters.base_adapter import BaseSourceAdapter


class DiscourseAdapter(BaseSourceAdapter):
    """
    Adapter for Discourse-based security/hacking forums such as 0x00sec.org.
    """

    source_type: str = "DISCOURSE_FORUM"

    def match_url(self, url: str, raw_html: str = "") -> bool:
        url_lower = url.lower()
        comb = f"{url_lower}\n{raw_html.lower()}"
        return "0x00sec.org" in url_lower or "discourse" in comb or "/t/" in url_lower

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
                if ("/t/" in href or href.startswith("t/")) and not any(skip in href for skip in ["/t/categories", "/t/badges", "/t/tags", "/about", "/tag"]):
                    if href.startswith("http://") or href.startswith("https://"):
                        full_url = href.split("#")[0].rstrip("/").replace(".html", "")
                    else:
                        if not href.startswith("/"):
                            href = "/" + href
                        full_url = (domain_base + href).split("#")[0].rstrip("/").replace(".html", "")
                    if full_url and full_url != base_clean and full_url != domain_base:
                        post_urls.add(full_url)
        except Exception:
            pass

        # Regex fallback for t/topic-name/1234 or /t/topic-name/1234
        matches = re.findall(r'(?:/|^)t/([a-zA-Z0-9_-]+/\d+|\d+)', raw_html)
        for m in matches:
            full_url = f"{domain_base}/t/{m}"
            if full_url != base_clean:
                post_urls.add(full_url)

        return sorted(list(post_urls))

    def classify_page_type(self, url: str, raw_html: str, clean_text: str, thread_info: Dict[str, Any]) -> str:
        url_lower = url.lower()
        comb = f"{clean_text}\n{raw_html}".lower()

        if "/u/" in url_lower or "/user/" in url_lower:
            return "PROFILE"

        if any(nav_kw in url_lower for nav_kw in ["/faq", "/rules", "/guidelines", "/search", "/about", "/badges"]):
            return "NAVIGATION"

        title = (thread_info.get("title") or "").lower()
        ann_keywords = ["announcement", "[announcement]", "welcome to 0x00sec", "site rules", "pinned", "sticky:"]
        if any(ak in title for ak in ann_keywords) or any(ak in comb[:400] for ak in ann_keywords):
            return "ANNOUNCEMENT"

        if "/c/" in url_lower or "/categories" in url_lower:
            return "CATEGORY"

        if not re.search(r'(?:/|^)t/', url_lower):
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

            # Topic ID
            topic_id_match = re.search(r'/t/(?:[a-zA-Z0-9_-]+/)?(\d+)', url)
            if topic_id_match:
                thread_info["post_id"] = f"topic_{topic_id_match.group(1)}"

            # Title
            title_el = soup.find(class_=["fancy-title", "topic-title"]) or soup.find("h1")
            if title_el:
                t_str = title_el.get_text().strip()
                if t_str and len(t_str) < 200:
                    thread_info["title"] = t_str

            if not thread_info["title"]:
                og_title = soup.find("meta", property="og:title") or soup.find("title")
                if og_title:
                    raw_title = og_title.get("content") or og_title.get_text()
                    raw_title = re.sub(r' - 0x00sec.*$', '', raw_title).strip()
                    if raw_title and "Home of the Hacker" not in raw_title:
                        thread_info["title"] = raw_title

            # Root post container
            posts = soup.find_all(class_=["topic-body", "topic-post", "post-stream", "post"])
            if not posts:
                posts = soup.find_all("article")

            root_post_el = posts[0] if posts else soup

            # Author
            author_el = root_post_el.find(class_=["username", "first", "creator"]) or soup.find(class_=["username", "creator"])
            if author_el:
                a_str = author_el.get_text().strip()
                if a_str and len(a_str) < 40:
                    thread_info["author"] = a_str

            if not thread_info["author"]:
                u_link = soup.find("a", href=re.compile(r'u/([a-zA-Z0-9_-]+)'))
                if u_link:
                    u_m = re.search(r'u/([a-zA-Z0-9_-]+)', u_link["href"])
                    if u_m:
                        thread_info["author"] = u_m.group(1)

            # Timestamp
            time_el = root_post_el.find("time") or soup.find("time")
            if time_el:
                thread_info["timestamp"] = time_el.get("datetime") or time_el.get_text().strip()
            else:
                meta_time = soup.find("meta", property=re.compile(r'published_time|date', re.IGNORECASE))
                if meta_time:
                    thread_info["timestamp"] = meta_time.get("content")

            # Content
            cooked_el = root_post_el.find(class_=["cooked", "topic-body", "post"])
            if cooked_el:
                c_text = cooked_el.get_text().strip()
                thread_info["content"] = c_text
            else:
                og_desc = soup.find("meta", property="og:description")
                if og_desc and og_desc.get("content"):
                    thread_info["content"] = og_desc["content"].strip()
                else:
                    body_lines = [line.strip() for line in root_post_el.get_text().splitlines() if len(line.strip()) > 10]
                    thread_info["content"] = "\n".join(body_lines[:15]) if body_lines else (thread_info["title"] or "Content Unavailable")

            if not thread_info["post_id"]:
                thread_info["post_id"] = f"topic_{hash(url) & 0xffff:04x}"

            # Replies (posts 1+)
            if len(posts) > 1:
                import hashlib
                for idx, reply_el in enumerate(posts[1:], start=1):
                    raw_id = reply_el.get("id") or reply_el.get("data-post-id")
                    r_author_el = reply_el.find(class_=["username", "first", "creator"])
                    if r_author_el:
                        r_author = r_author_el.get_text().strip()
                    else:
                        r_author = "anonymous" if "anonymous" in reply_el.get_text().lower() else "UNKNOWN"

                    r_time = ""
                    r_time_el = reply_el.find("time")
                    if r_time_el:
                        r_time = r_time_el.get("datetime") or r_time_el.get_text().strip()

                    r_cooked = reply_el.find(class_="cooked")
                    r_text = r_cooked.get_text().strip() if r_cooked else reply_el.get_text().strip()

                    if raw_id:
                        r_id = f"reply_{raw_id.replace('post_', '')}"
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
            rep_cnt_el = soup.find(class_=["reply-count", "posts-count"])
            if rep_cnt_el:
                m = re.search(r'(\d+)', rep_cnt_el.get_text())
                if m:
                    thread_info["reported_comments_count"] = int(m.group(1))

            thread_info["observed_comments_count"] = len(thread_info["direct_replies"])
            thread_info["reported_comments_count"] = max(thread_info["reported_comments_count"], thread_info["observed_comments_count"])

        except Exception as e:
            print(f"[-] DiscourseAdapter parse error: {e}")

        return thread_info
