"""
Ahmia Discovery Engine for GHOST Observation Agent.
Performs public onion discovery queries via Ahmia, extracts candidate URLs,
selects permitted test targets, and verifies search results.
"""

import urllib.request
import urllib.parse
import re
import time
import datetime
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup


class AhmiaDiscoveryEngine:
    """
    Ahmia search and candidate URL verification engine for GHOST agent.
    """

    def __init__(self, proxy_url: str = "socks5://127.0.0.1:9050", mock_fallback: bool = True):
        self.proxy_url = proxy_url
        self.mock_fallback = mock_fallback

    def search(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        """
        Executes search query against Ahmia and parses search results into candidate URLs.
        """
        search_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        encoded_query = urllib.parse.quote(query)
        ahmia_url = f"https://ahmia.fi/search/?q={encoded_query}"
        
        candidates = []
        raw_html = ""
        search_status = "SUCCESS"

        try:
            # Attempt live Ahmia fetch
            req = urllib.request.Request(
                ahmia_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"}
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                raw_html = resp.read().decode('utf-8', errors='replace')
        except Exception as e:
            if self.mock_fallback:
                # Controlled lab fallback search results for offline Docker test environment
                search_status = "LAB_CONTROLLED_FALLBACK"
                raw_html = f"""
                <html><head><title>Ahmia Search Results: {query}</title></head>
                <body>
                <ol class="search-results">
                    <li><a href="http://127.0.0.1:8080/forum">Result 1: Underground Threat Forum (CVE-2023-4966 PoC)</a></li>
                    <li><a href="http://127.0.0.1:8080/session_gated">Result 2: 2-Step Verification VIP Lounge (CVE-2024-1234 0day)</a></li>
                    <li><a href="http://127.0.0.1:8080/leak">Result 3: Ransomware Exfiltration Portal (SHA256 Leaks)</a></li>
                </ol>
                </body></html>
                """
            else:
                return {
                    "search_query": query,
                    "search_timestamp": search_timestamp,
                    "result_count": 0,
                    "candidate_urls": [],
                    "search_status": "FAILED",
                    "error": str(e)
                }

        # Parse Ahmia HTML search results
        if raw_html:
            soup = BeautifulSoup(raw_html, 'html.parser')
            # Extract links from search results
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                title = a_tag.get_text(strip=True) or href
                
                # Unwrap redirect URLs if Ahmia uses /redirect?redirect_url=
                if '/redirect/' in href and 'redirect_url=' in href:
                    parsed_url = urllib.parse.parse_qs(urllib.parse.urlparse(href).query).get('redirect_url', [''])[0]
                    if parsed_url:
                        href = parsed_url

                # Extract valid http/https or onion URLs
                if href.startswith(('http://', 'https://')) and not 'ahmia.fi' in href:
                    candidates.append({
                        "title": title,
                        "url": href
                    })

        # Deduplicate candidates
        seen = set()
        unique_candidates = []
        for c in candidates:
            if c["url"] not in seen:
                seen.add(c["url"])
                unique_candidates.append(c)

        selected_candidates = unique_candidates[:max_results]

        return {
            "search_query": query,
            "search_timestamp": search_timestamp,
            "result_count": len(selected_candidates),
            "candidate_urls": [c["url"] for c in selected_candidates],
            "candidates": selected_candidates,
            "search_status": search_status
        }

    def select_candidate(self, search_results: Dict[str, Any], target_preference: Optional[str] = None) -> Dict[str, Any]:
        """
        Selects a target candidate URL from search results based on selection criteria.
        """
        candidates = search_results.get("candidates", [])
        if not candidates:
            return {
                "selected_url": None,
                "reason_selected": "No candidates available in search results."
            }

        # If explicit preference provided (e.g. 2-step verification site / session_gated)
        if target_preference:
            for c in candidates:
                if target_preference in c["url"]:
                    return {
                        "selected_url": c["url"],
                        "selected_title": c["title"],
                        "reason_selected": f"Matches preferred target keyword '{target_preference}'"
                    }

        # Default: select 2nd candidate if multiple exist to demonstrate selection logic, or 1st
        sel = candidates[1] if len(candidates) > 1 else candidates[0]
        return {
            "selected_url": sel["url"],
            "selected_title": sel["title"],
            "reason_selected": "Selected rank #2 search result for active threat verification test."
        }
