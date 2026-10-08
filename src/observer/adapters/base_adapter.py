"""
Base Source Adapter interface for GHOST Protocol multi-source observation.
"""

from typing import Dict, Any, List, Optional
import re


class BaseSourceAdapter:
    """
    Abstract base class for source-specific URL discovery, page classification,
    and normalized thread/content extraction.
    """

    source_type: str = "OTHER_PUBLIC_SOURCE"

    def match_url(self, url: str, raw_html: str = "") -> bool:
        """Returns True if this adapter is suited for the given URL/content."""
        return False

    def extract_candidate_links(self, url: str, raw_html: str) -> List[str]:
        """Discovers post/thread candidate URLs from page HTML."""
        return []

    def classify_page_type(self, url: str, raw_html: str, clean_text: str, thread_info: Dict[str, Any]) -> str:
        """
        Classifies page type:
        - FRONT_PAGE: Landing page, forum home
        - CATEGORY: Subforum/category index
        - THREAD_PAGE: Genuine user post/thread or message
        - TELEGRAM_CHANNEL: Telegram channel feed
        - ANNOUNCEMENT: Platform/site announcements, pinned rules
        - PROFILE: User profile page
        - NAVIGATION: FAQ/rules/search page
        - ACCESS_PAGE: Login, 2FA, Captcha, Queue page
        """
        return "THREAD_PAGE"

    def extract_thread_info(self, url: str, raw_html: str) -> Dict[str, Any]:
        """
        Extracts normalized content dictionary:
        {
            "post_id": str,
            "title": str,
            "content": str,
            "author": str,
            "timestamp": str,
            "reported_comments_count": int,
            "observed_comments_count": int,
            "direct_replies": list,
            "nested_replies": list
        }
        """
        return {
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
