"""
Telegram Public Channel Adapter for GHOST Protocol (t.me/s/SliceForLifeee).
"""

import re
import uuid
import datetime
from typing import Dict, Any, List
from src.observer.adapters.base_adapter import BaseSourceAdapter


class TelegramAdapter(BaseSourceAdapter):
    """
    Adapter for Telegram Public Channels (web preview: t.me/s/channel_name).
    Extracts channel posts, message IDs, timestamps, text, and media/link references.
    """

    source_type: str = "TELEGRAM_PUBLIC_CHANNEL"

    def match_url(self, url: str, raw_html: str = "") -> bool:
        url_lower = url.lower()
        comb = f"{url_lower}\n{raw_html.lower()}"
        return "t.me/" in url_lower or "telegram" in comb or "tgme_widget_message" in raw_html

    def extract_candidate_links(self, url: str, raw_html: str) -> List[str]:
        if not raw_html:
            return []

        message_urls = set()
        base_clean = url.rstrip("/")
        # Extract channel name from URL (e.g. t.me/s/SliceForLifeee -> SliceForLifeee)
        ch_match = re.search(r't\.me/(?:s/)?([a-zA-Z0-9_]+)', url)
        ch_name = ch_match.group(1) if ch_match else ""

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw_html, "html.parser")
            for msg_el in soup.find_all(class_="tgme_widget_message"):
                data_post = msg_el.get("data-post")
                if data_post:
                    full_url = f"https://t.me/s/{data_post}"
                    message_urls.add(full_url)
        except Exception:
            pass

        # Regex fallback for data-post="channel/123" or t.me/s/channel/123
        if ch_name:
            matches = re.findall(rf'{re.escape(ch_name)}/(\d+)', raw_html)
            for m in matches:
                message_urls.add(f"https://t.me/s/{ch_name}/{m}")

        return sorted(list(message_urls))

    def classify_page_type(self, url: str, raw_html: str, clean_text: str, thread_info: Dict[str, Any]) -> str:
        # Check if URL ends with message ID e.g. /123
        if re.search(r'/\d+$', url):
            return "THREAD_PAGE"
        return "TELEGRAM_CHANNEL"

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

            # Channel Name
            ch_header = soup.find(class_=["tgme_channel_info_header_title", "tgme_page_title"])
            ch_title = ch_header.get_text().strip() if ch_header else "Telegram Public Channel"
            thread_info["author"] = ch_title

            # Locate target message item or latest message
            msg_el = None
            msg_id_match = re.search(r'/(\d+)$', url)
            if msg_id_match:
                target_num = msg_id_match.group(1)
                for m_el in soup.find_all(class_="tgme_widget_message"):
                    dp = m_el.get("data-post", "")
                    if dp.endswith(f"/{target_num}"):
                        msg_el = m_el
                        thread_info["post_id"] = f"msg_{target_num}"
                        break

            if not msg_el:
                messages = soup.find_all(class_="tgme_widget_message")
                msg_el = messages[0] if messages else soup
                if not thread_info["post_id"]:
                    dp = msg_el.get("data-post") if hasattr(msg_el, "get") else None
                    if dp:
                        thread_info["post_id"] = f"msg_{dp.replace('/', '_')}"

            # Message Title & Author
            owner_el = msg_el.find(class_="tgme_widget_message_owner_name")
            if owner_el:
                thread_info["author"] = owner_el.get_text().strip()

            thread_info["title"] = f"[{thread_info['author']}] Message {thread_info['post_id'] or 'Post'}"

            # Timestamp
            time_el = msg_el.find("time")
            if time_el:
                thread_info["timestamp"] = time_el.get("datetime") or time_el.get_text().strip()

            # Message Content
            text_el = msg_el.find(class_=["tgme_widget_message_text", "js-message_text"])
            if text_el:
                thread_info["content"] = text_el.get_text().strip()
            else:
                thread_info["content"] = msg_el.get_text().strip()[:500] or "Telegram Message Content"

            if not thread_info["post_id"]:
                thread_info["post_id"] = f"msg_{hash(url) & 0xffff:04x}"

        except Exception as e:
            print(f"[-] TelegramAdapter parse error: {e}")

        return thread_info
