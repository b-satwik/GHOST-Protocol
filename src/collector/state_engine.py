"""
State Engine for DarkWatch Collector (Phase 1).
Defines the deterministic source-state machine for dark web onion sources.
"""

from enum import Enum
from typing import Optional, Dict, Any


class SourceState(str, Enum):
    """
    Deterministic source states for onion site verification.
    """
    DISCOVERED = "DISCOVERED"
    REACHABLE = "REACHABLE"
    CONTENT_ACCESSIBLE = "CONTENT_ACCESSIBLE"
    AUTOMATED_ACCESS_BLOCKED = "AUTOMATED_ACCESS_BLOCKED"
    OFFLINE = "OFFLINE"
    UNCERTAIN = "UNCERTAIN"


class StateEngine:
    """
    Deterministic state engine for evaluating onion source reachability and access.
    Does NOT use machine learning models for state classification.
    """

    # Indicators of automated access blocks (anti-bot / CAPTCHA / DDoS-Guard)
    BLOCK_KEYWORDS = [
        "cloudflare",
        "ddos-guard",
        "captcha",
        "verify you are human",
        "security check",
        "access denied",
        "bot detection",
        "pardon our interruption",
        "attention required",
        "ray id:"
    ]

    def __init__(self, min_text_length: int = 20):
        self.min_text_length = min_text_length

    def determine_state(
        self,
        http_status: Optional[int],
        content_type: Optional[str],
        text_length: int,
        raw_html: Optional[str] = None,
        error: Optional[str] = None,
        connection_failed: bool = False
    ) -> SourceState:
        """
        Determines source state deterministically based on network response metrics.

        Args:
            http_status (Optional[int]): HTTP response status code
            content_type (Optional[str]): Header Content-Type
            text_length (int): Length of sanitized clean text
            raw_html (Optional[str]): Raw HTML response string for block checking
            error (Optional[str]): Error description if request failed
            connection_failed (bool): True if TCP/SOCKS connection failed or timed out

        Returns:
            SourceState: Evaluated deterministic state
        """
        # 1. Connection failed or gateway offline errors
        if connection_failed or (http_status in [502, 503, 504]):
            return SourceState.OFFLINE

        if error:
            error_lower = error.lower()
            if any(term in error_lower for term in ["timeout", "refused", "socks", "connection error", "host unreachable"]):
                return SourceState.OFFLINE

        # If http_status is None (and not explicit connection failure), mark UNCERTAIN
        if http_status is None:
            return SourceState.UNCERTAIN

        # 2. Automated access blocks (HTTP 403, 429, or block page content)
        if http_status in [403, 429]:
            return SourceState.AUTOMATED_ACCESS_BLOCKED

        if raw_html:
            html_lower = raw_html.lower()
            if any(keyword in html_lower for keyword in self.BLOCK_KEYWORDS):
                return SourceState.AUTOMATED_ACCESS_BLOCKED

        # 3. Successful HTTP 2xx response
        if 200 <= http_status < 300:
            # Check content type if available
            is_html = True
            if content_type:
                ct_lower = content_type.lower()
                is_html = ("text/html" in ct_lower or "application/xhtml+xml" in ct_lower)

            if not is_html:
                # Connected to host, but non-HTML asset
                return SourceState.REACHABLE

            if text_length >= self.min_text_length:
                return SourceState.CONTENT_ACCESSIBLE
            else:
                # Reachable via HTTP 200, but empty/insufficient text content extracted
                return SourceState.REACHABLE

        # 4. Redirects (3xx) indicate reachability but not direct content access
        if 300 <= http_status < 400:
            return SourceState.REACHABLE

        # 5. Client/Server errors (400, 401, 404, 500) indicate UNCERTAIN state
        if http_status in [400, 401, 404, 500]:
            return SourceState.UNCERTAIN

        # Fallback default
        return SourceState.UNCERTAIN
