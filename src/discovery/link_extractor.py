"""
Link Extraction & URL Canonicalization Module for Stage 1 Discovery.
Extracts public HTTP/HTTPS URLs, Tor .onion URLs (v2/v3), and Telegram public preview URLs from text.
Performs clean canonicalization without contacting external servers.
"""

import re
from typing import List, Set


class LinkExtractor:
    """
    Regex-based parser for extracting and canonicalizing URLs from text.
    """

    # Regex patterns
    ONION_V3_PATTERN = re.compile(r'\b(?:https?://)?[a-z2-7]{56}\.onion(?::\d+)?(?:/[^\s"\'>]*)?', re.IGNORECASE)
    ONION_V2_PATTERN = re.compile(r'\b(?:https?://)?[a-z2-7]{16}\.onion(?::\d+)?(?:/[^\s"\'>]*)?', re.IGNORECASE)
    TELEGRAM_URL_PATTERN = re.compile(r'\b(?:https?://)?t\.me/(?:s/|joinchat/|[\w_]+)(?:/\d+)?', re.IGNORECASE)
    PASTE_SITE_PATTERN = re.compile(r'\b(?:https?://)?(?:pastebin\.com|ghostbin\.\w+|rentry\.co|justpaste\.it)/[a-zA-Z0-9_-]+', re.IGNORECASE)
    GENERIC_HTTP_PATTERN = re.compile(r'\bhttps?://[^\s"\'>]+', re.IGNORECASE)

    @classmethod
    def canonicalize_url(cls, url: str) -> str:
        """
        Canonicalizes URL:
        - Ensures scheme (default http:// for .onion if missing, https:// for standard URLs)
        - Strips query parameters and fragments where appropriate
        - Lowercases host
        - Strips trailing slash
        """
        if not url:
            return ""

        cleaned = url.strip()

        # Remove trailing punctuation often captured by regex
        cleaned = cleaned.rstrip(".,;:!)]}>")

        # Strip fragment anchor
        if "#" in cleaned:
            cleaned = cleaned.split("#", 1)[0]

        # Ensure scheme
        if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
            if ".onion" in cleaned.lower():
                cleaned = "http://" + cleaned
            else:
                cleaned = "https://" + cleaned

        # Parse scheme and rest
        parts = cleaned.split("://", 1)
        scheme = parts[0].lower()
        rest = parts[1]

        # Separate host and path
        path_parts = rest.split("/", 1)
        host = path_parts[0].lower()
        path = "/" + path_parts[1] if len(path_parts) > 1 else ""

        # Remove trailing slash from path
        if path == "/":
            path = ""
        elif path.endswith("/"):
            path = path[:-1]

        canonical = f"{scheme}://{host}{path}"
        return canonical

    @classmethod
    def is_static_resource(cls, url: str) -> bool:
        """Determines if a URL points to a static asset, script, style, image, font, or CDN file."""
        if not url:
            return True
        url_lower = url.lower().split("?")[0].split("#")[0]
        static_exts = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".xml", ".rss",
            ".atom", ".json", ".zip", ".tar", ".gz", ".pdf", "robots.txt", "favicon.ico"
        )
        cdn_domains = (
            "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
            "fonts.googleapis.com", "fonts.gstatic.com"
        )
        static_dirs = (
            "/static/", "/assets/", "/scripts/", "/js/", "/css/", "/images/",
            "/fonts/", "/vendor/", "/dist/", "/node_modules/", "/theme/", "/styles/"
        )
        if any(url_lower.endswith(ext) for ext in static_exts) or \
           any(domain in url_lower for domain in cdn_domains) or \
           any(s_dir in url_lower for s_dir in static_dirs) or \
           url_lower.endswith("robots.txt") or url_lower.endswith("favicon.ico"):
            return True
        return False

    def extract_links(self, text: str) -> List[str]:
        """
        Extracts all canonicalized URLs (.onion, Telegram, HTTP/HTTPS) from a text payload.
        """
        if not text or not isinstance(text, str):
            return []

        extracted: Set[str] = set()

        # 1. Onion links
        for m in self.ONION_V3_PATTERN.finditer(text):
            canonical = self.canonicalize_url(m.group(0))
            if canonical and not self.is_static_resource(canonical):
                extracted.add(canonical)

        for m in self.ONION_V2_PATTERN.finditer(text):
            canonical = self.canonicalize_url(m.group(0))
            if canonical and not self.is_static_resource(canonical):
                extracted.add(canonical)

        # 2. Telegram links
        for m in self.TELEGRAM_URL_PATTERN.finditer(text):
            canonical = self.canonicalize_url(m.group(0))
            if canonical and not self.is_static_resource(canonical):
                extracted.add(canonical)

        # 3. Generic HTTP/HTTPS links
        for m in self.GENERIC_HTTP_PATTERN.finditer(text):
            canonical = self.canonicalize_url(m.group(0))
            if canonical and not self.is_static_resource(canonical):
                extracted.add(canonical)

        return sorted(list(extracted))

    def extract_post_links(self, html_text: str, base_url: str) -> List[str]:
        """
        Discovers post/thread URLs from HTML or text relative to base_url.
        Uses SourceAdapterRegistry to extract source-specific candidate URLs.
        """
        if not html_text:
            return []

        from src.observer.adapters.adapter_registry import get_adapter_for_url
        adapter = get_adapter_for_url(base_url, html_text)
        adapter_links = adapter.extract_candidate_links(base_url, html_text)

        if adapter_links:
            return [self.canonicalize_url(l) for l in adapter_links if l != base_url and not self.is_static_resource(l)]

        post_urls: Set[str] = set()

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_text, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if any(kw in href for kw in ["/post/", "/threads/", "/t/", "/discussion/"]):
                    if href.startswith("http://") or href.startswith("https://"):
                        full_url = self.canonicalize_url(href)
                    else:
                        base_clean = base_url.rstrip("/")
                        if not href.startswith("/"):
                            href = "/" + href
                        full_url = self.canonicalize_url(base_clean + href)
                    if full_url and full_url != base_url and not self.is_static_resource(full_url):
                        post_urls.add(full_url)
        except Exception:
            pass

        # Regex fallback
        matches = re.findall(r'/(?:post|threads|t)/([a-zA-Z0-9_.-]+)', html_text)
        base_clean = base_url.rstrip("/")
        for m in matches:
            full_url = self.canonicalize_url(f"{base_clean}/post/{m}")
            if full_url and full_url != base_url and not self.is_static_resource(full_url):
                post_urls.add(full_url)

        return sorted(list(post_urls))
