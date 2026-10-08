"""
DarkWatch Verifier Orchestrator (Phase 1).
Executes controlled HTTP reachability requests over SOCKS5 proxy (or Whonix gateway),
sanitizes HTML content, determines deterministic source state, and records evidence in SQLite.
"""

import os
import time
import json
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import requests

from .sanitizer import ContentSanitizer
from .state_engine import StateEngine, SourceState
from .evidence_store import EvidenceStore


class DarkWatchVerifier:
    """
    Main DarkWatch verifier for Dark Web onion sources.
    Operates at the network collection boundary before internal AI processing.
    Configured for Whonix-Workstation / Whonix-Gateway SOCKS5 proxy routing.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        socks_proxy: Optional[str] = None,
        db_path: Optional[str] = None,
        use_whonix: bool = False
    ):
        # Load config file if available
        self.config = self._load_config(config_path)

        # SOCKS5 proxy selection logic
        env_proxy = os.environ.get("SOCKS_PROXY")
        whonix_env = os.environ.get("USE_WHONIX") or os.environ.get("WHONIX_MODE")
        whonix_gw_ip = os.environ.get("WHONIX_GATEWAY_IP", "10.152.152.10")
        whonix_socks_port = os.environ.get("WHONIX_SOCKS_PORT", "9050")

        if socks_proxy:
            proxy_val = socks_proxy
        elif env_proxy:
            proxy_val = env_proxy
        elif use_whonix or whonix_env:
            proxy_val = f"socks5h://{whonix_gw_ip}:{whonix_socks_port}"
        else:
            proxy_val = self.config.get("socks_proxy", f"socks5h://{whonix_gw_ip}:{whonix_socks_port}")

        if proxy_val and not str(proxy_val).startswith("socks"):
            proxy_val = f"socks5h://{proxy_val}"

        self.socks_proxy = proxy_val

        # Database path
        db_val = db_path or self.config.get("sqlite_db_path", "data/collector_evidence.db")
        self.evidence_store = EvidenceStore(db_path=db_val)

        # Content sanitizer and state engine
        min_length = self.config.get("min_text_length", 20)
        self.sanitizer = ContentSanitizer(min_text_length=min_length)
        self.state_engine = StateEngine(min_text_length=min_length)

        # General settings
        self.timeout = self.config.get("request_timeout", 10)
        self.max_bytes = self.config.get("max_content_bytes", 2097152) # 2 MB
        self.user_agent = self.config.get("user_agent", "DarkWatch-Collector/1.0 (Research/Isolated)")
        self.allowed_content_types = self.config.get("allowed_content_types", ["text/html", "application/xhtml+xml"])
        self.tor_check_url = self.config.get("tor_check_url", "https://check.torproject.org/api/ip")

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Loads collector configuration from JSON file."""
        paths_to_try = []
        if config_path:
            paths_to_try.append(config_path)

        # Default paths to check
        paths_to_try.extend([
            os.path.join(os.getcwd(), "config", "collector_config.json"),
            os.path.join(os.getcwd(), "src", "config", "collector_config.json"),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "collector_config.json")
        ])

        for path in paths_to_try:
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass

        # Fallback default dict
        return {
            "socks_proxy": "127.0.0.1:9050",
            "whonix_gateway_proxy": "socks5h://10.152.152.10:9050",
            "tor_check_url": "https://check.torproject.org/api/ip",
            "request_timeout": 10,
            "max_content_bytes": 2097152,
            "user_agent": "DarkWatch-Collector/1.0 (Research/Isolated)",
            "sqlite_db_path": "data/collector_evidence.db",
            "min_text_length": 20
        }

    def derive_source_id(self, onion_url: str) -> str:
        """Derives a consistent source ID from an onion URL (domain hostname)."""
        parsed = urllib.parse.urlparse(onion_url)
        netloc = parsed.netloc or parsed.path.split('/')[0]
        # Remove port if present
        host = netloc.split(':')[0]
        return host if host else onion_url

    def _get_proxies(self) -> Optional[Dict[str, str]]:
        """Formats SOCKS5 proxy dict for requests library."""
        if not self.socks_proxy:
            return None

        proxy_str = str(self.socks_proxy).strip()
        if not proxy_str.startswith("socks"):
            proxy_str = f"socks5h://{proxy_str}"

        return {
            "http": proxy_str,
            "https": proxy_str
        }

    def check_whonix_tor_connection(
        self,
        custom_session: Optional[requests.Session] = None
    ) -> Dict[str, Any]:
        """
        Safety connectivity test to verify if the collector HTTP client reaches Tor
        through the Whonix Gateway or configured SOCKS5 proxy.
        Queries https://check.torproject.org/api/ip.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        headers = {"User-Agent": self.user_agent}
        proxies = self._get_proxies()
        session = custom_session or requests.Session()

        try:
            resp = session.get(
                self.tor_check_url,
                headers=headers,
                proxies=proxies if not custom_session else None,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                is_tor = bool(data.get("IsTor", False))
                ip_addr = data.get("IP", "Unknown")
                return {
                    "connected_to_tor": is_tor,
                    "ip": ip_addr,
                    "socks_proxy": self.socks_proxy,
                    "timestamp": timestamp,
                    "error": None if is_tor else "Connected to API but IsTor reported false"
                }
            else:
                return {
                    "connected_to_tor": False,
                    "ip": None,
                    "socks_proxy": self.socks_proxy,
                    "timestamp": timestamp,
                    "error": f"Tor check API returned HTTP status {resp.status_code}"
                }
        except Exception as e:
            return {
                "connected_to_tor": False,
                "ip": None,
                "socks_proxy": self.socks_proxy,
                "timestamp": timestamp,
                "error": f"Tor check connection failed: {str(e)}"
            }

    def verify_onion_source(
        self,
        onion_url: str,
        custom_session: Optional[requests.Session] = None
    ) -> Dict[str, Any]:
        """
        Performs a controlled reachability request and verification attempt on an onion URL.

        Args:
            onion_url (str): The onion URL to verify
            custom_session (Optional[requests.Session]): Optional custom/mock requests Session for testing

        Returns:
            Dict[str, Any]: Structured verification result
        """
        source_id = self.derive_source_id(onion_url)
        timestamp = datetime.now(timezone.utc).isoformat()

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml"
        }

        proxies = self._get_proxies()
        session = custom_session or requests.Session()

        start_time = time.time()
        http_status = None
        content_type = None
        raw_html = ""
        error_msg = None
        connection_failed = False

        try:
            # Stream request to check headers before consuming response body
            resp = session.get(
                onion_url,
                headers=headers,
                proxies=proxies if not custom_session else None,
                timeout=self.timeout,
                stream=True,
                allow_redirects=True
            )

            response_time_ms = int((time.time() - start_time) * 1000)
            http_status = resp.status_code
            content_type = resp.headers.get("Content-Type", "")

            # Check if content type is allowed HTML
            is_allowed_html = any(ct in content_type.lower() for ct in self.allowed_content_types)

            if is_allowed_html or not content_type:
                # Controlled body read with size cap
                content_bytes = bytearray()
                for chunk in resp.iter_content(chunk_size=8192):
                    content_bytes.extend(chunk)
                    if len(content_bytes) >= self.max_bytes:
                        break

                raw_html = content_bytes.decode("utf-8", errors="replace")

        except requests.exceptions.Timeout as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Connection timeout: {str(e)}"
            connection_failed = True

        except requests.exceptions.ConnectionError as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Connection error: {str(e)}"
            connection_failed = True

        except Exception as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Request failure: {str(e)}"
            connection_failed = True

        # Process HTML sanitization if HTML content was obtained
        if raw_html:
            sanitized_text, text_length, sha256_hash = self.sanitizer.sanitize_html(raw_html)
        else:
            sanitized_text, text_length, sha256_hash = "", 0, self.sanitizer.compute_sha256("")

        # Evaluate state via deterministic State Engine
        state = self.state_engine.determine_state(
            http_status=http_status,
            content_type=content_type,
            text_length=text_length,
            raw_html=raw_html,
            error=error_msg,
            connection_failed=connection_failed
        )

        attempt_data = {
            "source_id": source_id,
            "onion_address": onion_url,
            "timestamp": timestamp,
            "http_status": http_status,
            "response_time_ms": response_time_ms,
            "state": state.value if isinstance(state, SourceState) else str(state),
            "text_length": text_length,
            "sha256": sha256_hash if text_length > 0 else None,
            "error": error_msg,
            "sanitized_text": sanitized_text if text_length > 0 else None
        }

        # Store record in evidence store
        final_result = self.evidence_store.save_attempt(attempt_data)
        return final_result
