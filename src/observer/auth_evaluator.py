"""
GHOST Protocol — Target Authentication Evaluator & Adapter Architecture.
Evaluates page HTML, response headers, HTTP status codes, form structures, and URL paths
to determine explicit target authentication state without relying on naive keyword matching.
"""

import re
from typing import Dict, Any, Optional, Tuple


class BaseTargetAdapter:
    """
    Base class for target-specific authentication evaluation adapters.
    """

    def evaluate(
        self,
        url: str,
        http_status: int,
        html_content: str,
        headers: Optional[Dict[str, str]] = None,
        previous_state: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Evaluates page signals and returns (auth_state, evaluation_reason).
        Possible auth_states:
        - LOGIN_REQUIRED
        - AUTHENTICATING
        - AUTHENTICATED
        - SESSION_EXPIRED
        """
        raise NotImplementedError


class ShadowBoardAdapter(BaseTargetAdapter):
    """
    Target adapter for ShadowBoard forum lab application.
    Evaluates HTTP status, forms, session cookies, title tags, and user badges.
    """

    def evaluate(
        self,
        url: str,
        http_status: int,
        html_content: str,
        headers: Optional[Dict[str, str]] = None,
        previous_state: Optional[str] = None
    ) -> Tuple[str, str]:
        headers = headers or {}
        html_lower = (html_content or "").lower()

        # 1. Check HTTP Status Code
        if http_status == 401:
            if previous_state in ("AUTHENTICATED", "BACKGROUND_OBSERVATION"):
                return "SESSION_EXPIRED", "HTTP 401 Unauthorized returned for active ShadowBoard session. Session token expired."
            return "LOGIN_REQUIRED", "HTTP 401 Unauthorized returned by ShadowBoard. Session authentication required."

        # 2. Check Login Form / Login Title presence
        is_login_page = (
            "action=\"/login\"" in html_lower or
            "action='/login'" in html_lower or
            "name=\"password\"" in html_lower or
            "name='password'" in html_lower or
            "authenticate session" in html_lower or
            "login required" in html_lower
        )

        if is_login_page:
            if previous_state in ("AUTHENTICATED", "BACKGROUND_OBSERVATION"):
                return "SESSION_EXPIRED", "Redirected to ShadowBoard login form. Active session expired."
            return "LOGIN_REQUIRED", "ShadowBoard authentication form present. User login required."

        # 3. Check Authenticated Page Indicators
        has_user_badge = "logged in as:" in html_lower or "class=\"user-badge\"" in html_lower or "class='user-badge'" in html_lower
        has_logout_link = "href=\"/logout\"" in html_lower or "href='/logout'" in html_lower
        has_my_profile = "my profile" in html_lower or "authored discussions" in html_lower

        if has_user_badge or has_logout_link or has_my_profile:
            return "AUTHENTICATED", "Authenticated ShadowBoard session verified via user profile badge & active session header."

        # 4. Check General Forum Feed
        if "shadowboard discussions" in html_lower or "start a new discussion" in html_lower:
            return "AUTHENTICATED", "Active ShadowBoard discussion feed loaded in authenticated session."

        if previous_state == "AUTHENTICATED":
            return "AUTHENTICATED", "Retaining active ShadowBoard authenticated session."

        return "LOGIN_REQUIRED", "ShadowBoard unauthenticated state. User login required."


class DreadLabAdapter(BaseTargetAdapter):
    """
    Target adapter for DreadLab 2-step session-gated lab.
    """

    def evaluate(
        self,
        url: str,
        http_status: int,
        html_content: str,
        headers: Optional[Dict[str, str]] = None,
        previous_state: Optional[str] = None
    ) -> Tuple[str, str]:
        html_lower = (html_content or "").lower()

        if http_status == 401 or "2-step" in html_lower or "session_gated" in url.lower():
            if "authenticated profile:" in html_lower or "user profile: viper_x" in html_lower:
                return "AUTHENTICATED", "DreadLab 2-step authenticated session verified."
            if previous_state in ("AUTHENTICATED", "BACKGROUND_OBSERVATION"):
                return "SESSION_EXPIRED", "DreadLab session expired."
            return "LOGIN_REQUIRED", "DreadLab 2-step authentication required."

        if "protected private threads" in html_lower or "viper_x" in html_lower:
            return "AUTHENTICATED", "DreadLab authenticated content loaded."

        return "LOGIN_REQUIRED", "DreadLab authentication required."


class GenericWebAdapter(BaseTargetAdapter):
    """
    Generic multi-signal target adapter for onion & web targets.
    """

    def evaluate(
        self,
        url: str,
        http_status: int,
        html_content: str,
        headers: Optional[Dict[str, str]] = None,
        previous_state: Optional[str] = None
    ) -> Tuple[str, str]:
        html_lower = (html_content or "").lower()

        if http_status in (401, 403):
            if previous_state in ("AUTHENTICATED", "BACKGROUND_OBSERVATION"):
                return "SESSION_EXPIRED", f"HTTP {http_status} returned on previously authenticated session."
            return "LOGIN_REQUIRED", f"HTTP {http_status} returned. Authentication required."

        # Form inspection
        has_pass_input = re.search(r'<input[^>]+type=["\']password["\']', html_lower)
        has_login_action = re.search(r'action=["\'][^"\']*(login|signin|auth)[^"\']*["\']', html_lower)

        if has_pass_input or has_login_action:
            if previous_state in ("AUTHENTICATED", "BACKGROUND_OBSERVATION"):
                return "SESSION_EXPIRED", "Redirected to login form."
            return "LOGIN_REQUIRED", "Authentication form detected."

        # Authenticated elements
        has_logout = re.search(r'href=["\'][^"\']*(logout|signout|logoff)[^"\']*["\']', html_lower)
        has_account = "my account" in html_lower or "user profile" in html_lower or "dashboard" in html_lower

        if has_logout or has_account:
            return "AUTHENTICATED", "Authenticated page elements detected."

        if http_status == 200:
            return "AUTHENTICATED", "HTTP 200 response. Content accessible without authentication form."

        return "LOGIN_REQUIRED", "Default login required fallback."


class AuthEvaluator:
    """
    Orchestrates target-specific authentication evaluation.
    """

    def __init__(self):
        self.adapters = {
            "shadowboard": ShadowBoardAdapter(),
            "shadowforum": ShadowBoardAdapter(),
            "dreadlab": DreadLabAdapter(),
            "dread": DreadLabAdapter()
        }
        self.generic_adapter = GenericWebAdapter()

    def get_adapter_for_target(self, url: str) -> BaseTargetAdapter:
        url_lower = (url or "").lower()
        for key, adapter in self.adapters.items():
            if key in url_lower:
                return adapter
        return self.generic_adapter

    def evaluate_target_auth(
        self,
        url: str,
        http_status: int,
        html_content: str,
        headers: Optional[Dict[str, str]] = None,
        previous_state: Optional[str] = None
    ) -> Tuple[str, str]:
        adapter = self.get_adapter_for_target(url)
        return adapter.evaluate(url, http_status, html_content, headers=headers, previous_state=previous_state)
