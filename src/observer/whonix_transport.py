"""
Whonix Transport Layer Abstraction for DarkWatch Stage 1.
Provides proxy connectivity verification, fail-closed isolation enforcement,
and deterministic HTTP status classification.
"""

import socket
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple, Optional


class WhonixIsolationError(Exception):
    """Raised when mandatory Whonix SOCKS5 gateway is unreachable."""
    pass


class WhonixTransport:
    """
    SOCKS5 network transport layer wrapper enforcing fail-closed Whonix isolation.
    """

    STATUS_CONTENT_ACCESSIBLE = "CONTENT_ACCESSIBLE"
    STATUS_VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    STATUS_AUTOMATED_ACCESS_BLOCKED = "AUTOMATED_ACCESS_BLOCKED"
    STATUS_OFFLINE = "OFFLINE"

    def __init__(
        self,
        proxy_host: str = "10.152.152.10",
        proxy_port: int = 9050,
        enforce_fail_closed: bool = True
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.enforce_fail_closed = enforce_fail_closed
        self.proxy_url = f"socks5h://{proxy_host}:{proxy_port}"

    def verify_gateway(self, timeout: float = 3.0) -> bool:
        """
        Pre-flight socket check to verify proxy availability.
        Fails closed if unreachable.
        """
        try:
            with socket.create_connection((self.proxy_host, self.proxy_port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if self.enforce_fail_closed:
                raise WhonixIsolationError(
                    f"CRITICAL: Whonix SOCKS5 Proxy ({self.proxy_host}:{self.proxy_port}) is unreachable ({e}). "
                    "Aborting execution to enforce fail-closed isolation."
                )
            return False

    @classmethod
    def classify_http_status(cls, http_status: int) -> str:
        """
        Maps HTTP status codes to deterministic Stage 1 status classifications.
        """
        if http_status == 200:
            return cls.STATUS_CONTENT_ACCESSIBLE
        elif http_status in (401, 403):
            return cls.STATUS_VERIFICATION_REQUIRED
        elif http_status in (429, 503):
            return cls.STATUS_AUTOMATED_ACCESS_BLOCKED
        else:
            return cls.STATUS_OFFLINE


def verify_whonix_gateway(proxy_host: str = "10.152.152.10", proxy_port: int = 9050, enforce_fail_closed: bool = True, timeout: float = 3.0) -> bool:
    """Convenience function enforcing Whonix SOCKS5 gateway check."""
    transport = WhonixTransport(proxy_host=proxy_host, proxy_port=proxy_port, enforce_fail_closed=enforce_fail_closed)
    return transport.verify_gateway(timeout=timeout)

