"""
Content Sanitizer for DarkWatch Collector.
Enforces the trust boundary between untrusted Dark Web HTML and internal DarkWatch AI.
Extracts readable plain text, strips active/binary content, and computes SHA-256 hashes.
"""

import re
import hashlib
from typing import Dict, Any, Tuple

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import trafilatura
    HAS_TRAFILATURA = True
except ImportError:
    HAS_TRAFILATURA = False


class ContentSanitizer:
    """
    Sanitizes HTML content retrieved from Dark Web sources.
    Strips JavaScript, CSS, embedded active objects, forms, and binary payloads.
    Returns clean plain text, text character length, and SHA-256 hash.
    """

    # Unwanted tags to strip completely along with their text content
    UNWANTED_TAGS = [
        "script", "style", "noscript", "iframe", "embed", "object",
        "applet", "canvas", "svg", "form", "input", "button", "select",
        "option", "textarea", "head", "link", "meta"
    ]

    # Regex patterns for cleaning
    CONTROL_CHAR_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')
    MULTIPLE_SPACES_PATTERN = re.compile(r'[ \t]+')
    MULTIPLE_NEWLINES_PATTERN = re.compile(r'\n\s*\n+')

    def __init__(self, min_text_length: int = 20):
        self.min_text_length = min_text_length

    def sanitize_html(self, html_content: str) -> Tuple[str, int, str]:
        """
        Sanitizes HTML string and extracts plain readable text.

        Returns:
            Tuple[str, int, str]: (sanitized_text, text_length, sha256_hash)
        """
        if not html_content or not isinstance(html_content, str):
            clean_text = ""
            return clean_text, 0, self.compute_sha256(clean_text)

        clean_text = ""

        # Try trafilatura first if available
        if HAS_TRAFILATURA:
            try:
                extracted = trafilatura.extract(
                    html_content,
                    include_links=False,
                    include_images=False,
                    include_formatting=False
                )
                if extracted and isinstance(extracted, str):
                    clean_text = extracted
            except Exception:
                clean_text = ""

        # Fallback / primary extraction with BeautifulSoup if text is empty
        if not clean_text and HAS_BS4:
            clean_text = self._extract_with_bs4(html_content)

        # Fallback to regex stripping if neither library succeeded
        if not clean_text:
            clean_text = self._extract_with_regex(html_content)

        # Post-processing normalization
        clean_text = self._normalize_text(clean_text)
        text_length = len(clean_text)
        sha256_hash = self.compute_sha256(clean_text)

        return clean_text, text_length, sha256_hash

    def _extract_with_bs4(self, html_content: str) -> str:
        """Extract text using BeautifulSoup4."""
        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Remove unwanted tags completely
            for tag in soup.find_all(self.UNWANTED_TAGS):
                tag.decompose()

            # Remove HTML comments
            for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.startswith("<!--")):
                comment.extract()

            # Extract text separated by newlines
            text = soup.get_text(separator="\n")
            return text
        except Exception:
            return ""

    def _extract_with_regex(self, html_content: str) -> str:
        """Regex fallback to strip tags and active content."""
        # Strip script and style blocks
        text = re.sub(r'<(script|style|noscript|iframe|object|embed)[^>]*>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        # Strip all HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        return text

    def _normalize_text(self, text: str) -> str:
        """Strips control characters, normalizes spacing and line breaks."""
        if not text:
            return ""

        # Remove control characters
        text = self.CONTROL_CHAR_PATTERN.sub('', text)

        # Collapse whitespace per line
        lines = []
        for line in text.splitlines():
            cleaned_line = self.MULTIPLE_SPACES_PATTERN.sub(' ', line).strip()
            if cleaned_line:
                lines.append(cleaned_line)

        normalized = "\n".join(lines)
        return normalized

    @staticmethod
    def compute_sha256(text: str) -> str:
        """Calculates SHA-256 hex digest for a text string."""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
