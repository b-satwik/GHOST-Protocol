"""
Candidate Classification and Thread Validation Module for GHOST Protocol.
Ensures static resources (JS, CSS, images, fonts, maps, CDN assets, API endpoints)
and non-thread pages are never claimed or converted into Threat Sessions.
"""

import re
from typing import Dict, Any, Tuple


class CandidateClassifier:
    """
    Classifies candidate URLs and validates extracted thread payloads prior to
    Threat Session creation or ML model execution.
    """

    STATIC_EXTENSIONS = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".xml", ".rss",
        ".atom", ".json", ".zip", ".tar", ".gz", ".pdf", "robots.txt", "favicon.ico"
    )

    CDN_DOMAINS = (
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
        "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com"
    )

    STATIC_DIRECTORIES = (
        "/static/", "/assets/", "/scripts/", "/js/", "/css/", "/images/",
        "/fonts/", "/vendor/", "/dist/", "/node_modules/", "/theme/", "/styles/"
    )

    NON_THREAD_URL_PATTERNS = (
        "/u/", "/user/", "/users/", "/members/", "/faq", "/rules", "/guidelines",
        "/search", "/about", "/badges", "/announcement", "/categories", "/c/",
        "/login", "/register", "/auth", "/settings", "community-rules", "terms"
    )

    @classmethod
    def classify_url(cls, url: str) -> Dict[str, Any]:
        """
        Classifies candidate URL before claiming or fetching.
        Returns dict with resource_type, page_type, is_valid_thread, action, reason.
        """
        if not url:
            return {
                "resource_type": "UNKNOWN",
                "page_type": "INVALID_URL",
                "is_valid_thread": False,
                "action": "SKIP",
                "reason": "EMPTY_URL"
            }

        url_clean = url.strip()
        url_lower = url_clean.lower().split("?")[0].split("#")[0]

        # Check static extensions
        for ext in cls.STATIC_EXTENSIONS:
            if url_lower.endswith(ext):
                res_type = "JAVASCRIPT" if ext == ".js" else ("STYLESHEET" if ext == ".css" else ("IMAGE" if ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico") else "STATIC_ASSET"))
                return {
                    "resource_type": res_type,
                    "page_type": "STATIC_RESOURCE",
                    "is_valid_thread": False,
                    "action": "SKIP",
                    "reason": "STATIC_RESOURCE"
                }

        # Check CDN domains
        for domain in cls.CDN_DOMAINS:
            if domain in url_lower:
                return {
                    "resource_type": "CDN_ASSET",
                    "page_type": "STATIC_RESOURCE",
                    "is_valid_thread": False,
                    "action": "SKIP",
                    "reason": "CDN_ASSET"
                }

        # Check static directories
        for s_dir in cls.STATIC_DIRECTORIES:
            if s_dir in url_lower:
                return {
                    "resource_type": "STATIC_DIRECTORY",
                    "page_type": "STATIC_RESOURCE",
                    "is_valid_thread": False,
                    "action": "SKIP",
                    "reason": "STATIC_DIRECTORY"
                }

        # Check API endpoints
        if "/api/" in url_lower and not any(kw in url_lower for kw in ["/api/v1/thread", "/api/v1/post", "/api/posts"]):
            return {
                "resource_type": "API_ENDPOINT",
                "page_type": "API_ENDPOINT",
                "is_valid_thread": False,
                "action": "SKIP",
                "reason": "API_RESOURCE"
            }

        # Check non-thread navigation / profile / login URL patterns
        for n_pat in cls.NON_THREAD_URL_PATTERNS:
            if n_pat in url_lower:
                p_type = "PROFILE" if any(p in n_pat for p in ["/u/", "/user/", "/members/"]) else ("NAVIGATION" if any(n in n_pat for n in ["/faq", "/rules", "/about", "/search"]) else "NON_THREAD_PAGE")
                return {
                    "resource_type": "HTML",
                    "page_type": p_type,
                    "is_valid_thread": False,
                    "action": "SKIP",
                    "reason": f"NON_THREAD_URL_{p_type}"
                }

        return {
            "resource_type": "HTML",
            "page_type": "HTML_THREAD_CANDIDATE",
            "is_valid_thread": True,
            "action": "PROCESS",
            "reason": "POTENTIAL_THREAD"
        }

    @classmethod
    def validate_extracted_thread(cls, url: str, raw_html: str, thread_info: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validates fetched candidate content and parsed thread_info before Threat Session creation.
        Returns (is_valid_bool, classification_dict).
        """
        if not raw_html or len(raw_html.strip()) < 20:
            return False, {
                "resource_type": "EMPTY_RESPONSE",
                "page_type": "EMPTY_RESPONSE",
                "is_valid_thread": False,
                "action": "SKIP",
                "reason": "EMPTY_RESPONSE"
            }

        clean_html = raw_html.strip()
        first_100 = clean_html[:100].lower()

        # Check if payload is raw JS / CSS / JSON code
        if first_100.startswith("!function") or first_100.startswith("var ") or first_100.startswith("const ") or \
           first_100.startswith("import ") or first_100.startswith("/*") or first_100.startswith("function(") or \
           first_100.startswith("{\"") or first_100.startswith("[{\"") or "(self.webpack" in first_100:
            return False, {
                "resource_type": "JAVASCRIPT" if ("function" in first_100 or "var " in first_100 or "const " in first_100) else "RAW_CODE",
                "page_type": "STATIC_RESOURCE",
                "is_valid_thread": False,
                "action": "SKIP",
                "reason": "STATIC_RESOURCE_JS_CODE"
            }

        title = (thread_info.get("title") or "").strip()
        content = (thread_info.get("content") or "").strip()
        author = thread_info.get("author")

        # Invalid content placeholders
        invalid_content_markers = ["content unavailable", "post content unavailable", "null", "undefined"]
        if content.lower() in invalid_content_markers and not title:
            return False, {
                "resource_type": "HTML",
                "page_type": "INVALID_THREAD",
                "is_valid_thread": False,
                "action": "SKIP",
                "reason": "NO_THREAD_CONTENT"
            }

        if len(content) < 5 and len(title) < 5:
            return False, {
                "resource_type": "HTML",
                "page_type": "INVALID_THREAD",
                "is_valid_thread": False,
                "action": "SKIP",
                "reason": "INSUFFICIENT_THREAD_TEXT"
            }

        # Check if content looks like JS source code
        if any(js_sig in content[:200] for js_sig in ["var ", "const ", "function(", "return ", "module.exports", "document.getelementbyid"]):
            return False, {
                "resource_type": "JAVASCRIPT",
                "page_type": "STATIC_RESOURCE",
                "is_valid_thread": False,
                "action": "SKIP",
                "reason": "JAVASCRIPT_BODY_TEXT"
            }

        # Genuine Thread Validation: URL format or explicit post container present
        url_lower = url.lower()
        has_thread_url = any(p in url_lower for p in ["/t/", "/post/", "/threads/", "/discussion/", "/topic/"])
        has_post_container = any(c in clean_html for c in ["post-root", "post-detail", "topic-body", "topic-post", "comment-tree", "message--post", "nested-comment", "tgme_widget_message"])

        if not has_thread_url and not has_post_container:
            return False, {
                "resource_type": "HTML",
                "page_type": "NON_THREAD_PAGE",
                "is_valid_thread": False,
                "action": "SKIP",
                "reason": "MISSING_POST_CONTAINER"
            }

        return True, {
            "resource_type": "HTML",
            "page_type": "GENUINE_THREAD",
            "is_valid_thread": True,
            "action": "OBSERVE",
            "reason": "VALIDATED_GENUINE_THREAD"
        }
