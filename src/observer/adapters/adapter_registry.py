"""
Source Adapter Registry for GHOST Protocol.
Provides factory lookup for matching BaseSourceAdapter instances by URL and HTML content.
"""

from typing import List, Optional
from src.observer.adapters.base_adapter import BaseSourceAdapter
from src.observer.adapters.discourse_adapter import DiscourseAdapter
from src.observer.adapters.xenforo_adapter import XenForoAdapter
from src.observer.adapters.telegram_adapter import TelegramAdapter
from src.observer.adapters.shadowboard_adapter import ShadowBoardAdapter


class SourceAdapterRegistry:
    """
    Registry managing registered Source Adapters and matching target URLs.
    """

    def __init__(self):
        self.adapters: List[BaseSourceAdapter] = [
            DiscourseAdapter(),
            XenForoAdapter(),
            TelegramAdapter(),
            ShadowBoardAdapter()
        ]
        self.default_adapter = ShadowBoardAdapter()

    def get_adapter(self, url: str, raw_html: str = "") -> BaseSourceAdapter:
        """Returns the matching BaseSourceAdapter instance for the given URL/content."""
        url_lower = url.lower()
        
        # Explicit domain matches
        if "0x00sec.org" in url_lower:
            return self.adapters[0]
        if "blackhatworld.com" in url_lower or "darknet77" in url_lower:
            return self.adapters[1]
        if "t.me/" in url_lower or "telegram" in url_lower:
            return self.adapters[2]

        # Dynamic match_url checks
        for adapter in self.adapters:
            if adapter.match_url(url, raw_html):
                return adapter

        return self.default_adapter


_GLOBAL_REGISTRY = SourceAdapterRegistry()


def get_adapter_for_url(url: str, raw_html: str = "") -> BaseSourceAdapter:
    """Utility function returning matching SourceAdapter for URL/content."""
    return _GLOBAL_REGISTRY.get_adapter(url, raw_html)
