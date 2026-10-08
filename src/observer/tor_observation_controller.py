#!/usr/bin/env python3
"""
tor_observation_controller.py
=============================

Async, library-style controller for *observing* web pages exclusively through a
Tor SOCKS5 gateway (default: Whonix gateway at 10.152.152.10:9050 or local Tor at 127.0.0.1:9050).

Architecture & Integration with GHOST Protocol
----------------------------------------------
Engine A (CLI):  httpx.AsyncClient via socks5h://. Never executes JavaScript.
Engine B (Browser): Real visible GHOST Tor Browser / Playwright persistent context
                 (visible window, persistent profile on disk), lazily started on escalation
                 and reused for every later URL. A cross-process singleton file lock
                 prevents competing browser sessions.

Escalation A -> B happens on: HTTP 401 / 403, 503-with-challenge, login forms,
CAPTCHAs, browser challenges, and JavaScript-required pages.

Human-in-the-loop rules (hard requirements)
-------------------------------------------
* CAPTCHAs / challenges are NEVER solved automatically. The controller enters
  CAPTCHA_HUMAN_ACTION_REQUIRED, logs "CAPTCHA / HUMAN ACTION REQUIRED", and
  pauses until a human completes it in the visible browser window.
* Credentials are typed by a human in the browser only. This module never reads,
  logs, stores or transmits form values; it only checks whether a password field
  exists. The profile's password manager/autofill is disabled before launch.
* Authentication, MFA, CAPTCHA and access controls are never bypassed.
* Session expiry (login wall after a prior human login) -> SESSION_EXPIRED ->
  HUMAN_AUTH_REQUIRED.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import enum
import json
import logging
import os
import random
import re
import signal
import sys
import time
import subprocess
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional, Union
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

try:  # Playwright is optional: without it Engine B uses real Tor Browser process.
    from playwright.async_api import (
        Error as PlaywrightError,
        TimeoutError as PlaywrightTimeoutError,
        async_playwright,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover
    PLAYWRIGHT_AVAILABLE = False

    class PlaywrightError(Exception):  # type: ignore[no-redef]
        """Placeholder when Playwright is not installed."""

    class PlaywrightTimeoutError(PlaywrightError):  # type: ignore[no-redef]
        """Placeholder when Playwright is not installed."""

    async_playwright = None  # type: ignore[assignment]

try:
    import fcntl  # POSIX
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]
try:
    import msvcrt  # Windows
except ImportError:
    msvcrt = None  # type: ignore[assignment]

# Import GHOST native Tor Browser and Lock utilities if available
try:
    from src.observer.tor_browser_observer import (
        find_installed_tor_browser,
        TorBrowserObserver,
        fetch_url_over_socks5
    )
    from src.observer.ghost_lock_manager import GhostLockManager
    GHOST_OBSERVER_AVAILABLE = True
except ImportError:
    GHOST_OBSERVER_AVAILABLE = False

__all__ = [
    "TorObservationController", "ControllerConfig", "ControllerState", "ObservationResult",
    "ObservationError", "AccessState", "Engine", "HumanActionRequest", "HumanActionKind",
    "TorGatewayStatus", "check_tor_gateway", "configure_logging", "ControllerError",
    "TorUnavailableError", "SingletonLockError", "BrowserUnavailableError",
    "ControllerStateError", "ConfigError",
]

# --------------------------------------------------------------------------- #
# Constants / logging
# --------------------------------------------------------------------------- #

DEFAULT_PROXY_URL = "socks5h://127.0.0.1:9050"
DEFAULT_WHONIX_PROXY_URL = "socks5h://10.152.152.10:9050"
DEFAULT_TOR_CHECK_URL = "https://check.torproject.org/api/ip"
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
CRASH_MARKERS = ("target closed", "has been closed", "crashed", "browser closed",
                 "connection closed", "disconnected", "browser has been closed")

logger = logging.getLogger("tor_observation_controller")
logger.addHandler(logging.NullHandler())


def configure_logging(level: int = logging.INFO) -> None:
    """Attach a simple stderr handler (for standalone/service use)."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s"))
    logger.handlers = [handler]
    logger.setLevel(level)
    logger.propagate = False


def _safe_url(url: str) -> str:
    """URL for logs: no userinfo, query or fragment."""
    try:
        p = urlparse(url)
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        return urlunparse((p.scheme, host, p.path, "", "", "")) + ("?…" if p.query else "")
    except Exception:
        return "<unparseable-url>"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Exceptions, enums, data classes
# --------------------------------------------------------------------------- #

class ControllerError(Exception):
    """Base class for controller errors."""


class ConfigError(ControllerError):
    """Invalid configuration."""


class TorUnavailableError(ControllerError):
    """Tor SOCKS gateway unreachable or not routing through Tor (fail closed)."""


class SingletonLockError(ControllerError):
    """Another live controller already owns the browser session."""


class BrowserUnavailableError(ControllerError):
    """Engine B cannot be started or used safely."""


class ControllerStateError(ControllerError):
    """API used in the wrong lifecycle state."""


class ControllerState(str, enum.Enum):
    UNINITIALIZED = "UNINITIALIZED"
    TOR_CHECK = "TOR_CHECK"
    CLI_OBSERVING = "CLI_OBSERVING"  # also the default "ready" state
    BROWSER_REQUIRED = "BROWSER_REQUIRED"
    BROWSER_STARTING = "BROWSER_STARTING"
    BROWSER_READY = "BROWSER_READY"
    BROWSER_UNRESPONSIVE = "BROWSER_UNRESPONSIVE"
    BROWSER_RECOVERING = "BROWSER_RECOVERING"
    AUTHENTICATED = "AUTHENTICATED"
    HUMAN_AUTH_REQUIRED = "HUMAN_AUTH_REQUIRED"
    HUMAN_AUTH_PENDING = "HUMAN_AUTH_PENDING"
    CAPTCHA_HUMAN_ACTION_REQUIRED = "CAPTCHA_HUMAN_ACTION_REQUIRED"
    CAPTCHA_HUMAN_REQUIRED = "CAPTCHA_HUMAN_REQUIRED"
    BROWSER_OBSERVING = "BROWSER_OBSERVING"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    BROWSER_TAB_CLOSED = "BROWSER_TAB_CLOSED"
    BROWSER_TERMINATED = "BROWSER_TERMINATED"
    ERROR = "ERROR"
    STOPPED = "STOPPED"


class Engine(str, enum.Enum):
    CLI_HTTPX = "CLI_HTTPX"
    BROWSER = "BROWSER"
    NONE = "NONE"


class AccessState(str, enum.Enum):
    OK = "OK"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    CAPTCHA_REQUIRED = "CAPTCHA_REQUIRED"
    CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED"
    JS_REQUIRED = "JS_REQUIRED"
    FORBIDDEN = "FORBIDDEN"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    HTTP_ERROR = "HTTP_ERROR"
    UNAVAILABLE = "UNAVAILABLE"
    TOR_UNAVAILABLE = "TOR_UNAVAILABLE"
    NETWORK_ERROR = "NETWORK_ERROR"
    BROWSER_UNAVAILABLE = "BROWSER_UNAVAILABLE"
    HUMAN_ACTION_PENDING = "HUMAN_ACTION_PENDING"
    HUMAN_ACTION_TIMEOUT = "HUMAN_ACTION_TIMEOUT"
    INVALID_URL = "INVALID_URL"
    HOST_COOLDOWN = "HOST_COOLDOWN"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


HUMAN_STATES = frozenset({AccessState.AUTH_REQUIRED, AccessState.CAPTCHA_REQUIRED,
                          AccessState.CHALLENGE_REQUIRED})


class HumanActionKind(str, enum.Enum):
    AUTHENTICATION = "AUTHENTICATION"
    CAPTCHA = "CAPTCHA"
    CHALLENGE = "CHALLENGE"
    SESSION_EXPIRED = "SESSION_EXPIRED"


class HumanOutcome(enum.Enum):
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    STOPPED = "stopped"


@dataclass
class HumanActionRequest:
    kind: HumanActionKind
    url: str  # sanitized
    message: str
    timestamp: str = field(default_factory=_utcnow)


@dataclass
class ObservationError:
    kind: str
    message: str
    retriable: bool = False


@dataclass
class ObservationResult:
    url: str
    success: bool
    access_state: AccessState
    engine: Engine
    timestamp: str
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    title: Optional[str] = None
    content: str = ""
    content_type: Optional[str] = None
    links: list[str] = field(default_factory=list)
    error: Optional[ObservationError] = None
    browser_escalated: bool = False
    browser_required: bool = False
    escalation_reasons: list[str] = field(default_factory=list)
    human_action_taken: bool = False
    truncated: bool = False
    attempts: int = 0
    elapsed_ms: int = 0
    controller_state: str = ""
    browser_pid: Optional[int] = None
    browser_reused: bool = False

    def to_dict(self) -> dict[str, Any]:
        def conv(v: Any) -> Any:
            if isinstance(v, enum.Enum):
                return v.value
            if isinstance(v, dict):
                return {k: conv(x) for k, x in v.items()}
            if isinstance(v, (list, tuple)):
                return [conv(x) for x in v]
            return v
        return conv(dataclasses.asdict(self))

    def to_json(self, **kw: Any) -> str:
        return json.dumps(self.to_dict(), **kw)


@dataclass
class TorGatewayStatus:
    reachable: bool
    socks5_handshake_ok: bool
    exit_verified: Optional[bool] = None  # None = not requested
    error: Optional[str] = None
    checked_at: str = field(default_factory=_utcnow)

    @property
    def ok(self) -> bool:
        return self.reachable and self.socks5_handshake_ok and self.exit_verified is not False


@dataclass
class ControllerConfig:
    proxy_url: str = DEFAULT_PROXY_URL
    user_agent: str = DEFAULT_USER_AGENT
    # Tor checks
    tor_check_timeout: float = 5.0
    tor_exit_check_timeout: float = 45.0
    verify_tor_exit: bool = False          # start(): confirm IsTor via check.torproject.org
    tor_check_url: str = DEFAULT_TOR_CHECK_URL
    tor_cache_ttl: float = 15.0
    tor_fail_backoff: float = 3.0
    # Engine A
    connect_timeout: float = 30.0
    request_timeout: float = 45.0
    request_deadline: float = 90.0        # hard cap per request (slow-drip protection)
    max_redirects: int = 8
    max_body_bytes: int = 4 * 1024 * 1024
    max_concurrent_cli: int = 4
    max_retries: int = 2
    backoff_base: float = 2.0
    backoff_max: float = 30.0
    host_failure_threshold: int = 3
    host_cooldown_base: float = 30.0
    host_cooldown_max: float = 600.0
    min_host_interval: float = 1.0
    # Engine B
    enable_browser: bool = True
    eager_browser: bool = False
    sticky_browser_hosts: bool = True
    browser_headless: bool = False        # must stay False for human interaction
    verify_browser_exit: bool = False
    profile_dir: Path = field(default_factory=lambda: Path.home() / ".tor_observation" / "browser_profile")
    lock_path: Path = field(default_factory=lambda: Path("/tmp/ghost_observer.lock"))
    browser_nav_timeout: float = 60.0
    browser_settle_timeout: float = 5.0
    max_browser_restarts: int = 3         # per 10 minutes (crash-loop guard)
    human_timeout: float = 900.0
    human_poll_interval: float = 2.0
    max_human_rounds: int = 3
    # Output limits
    max_content_chars: int = 200_000
    max_links: int = 500

    @property
    def proxy_host(self) -> str:
        return urlparse(self.proxy_url).hostname or "127.0.0.1"

    @property
    def proxy_port(self) -> int:
        return urlparse(self.proxy_url).port or 9050

    def validate(self) -> None:
        p = urlparse(self.proxy_url)
        if p.scheme != "socks5h":
            raise ConfigError("proxy_url must use socks5h:// so DNS is resolved by Tor")
        if not p.hostname or not p.port:
            raise ConfigError("proxy_url must include host and port")
        if self.browser_headless:
            raise ConfigError("browser_headless must be False: humans must be able to act")
        for name in ("tor_check_timeout", "connect_timeout", "request_timeout", "human_timeout"):
            if getattr(self, name) <= 0:
                raise ConfigError(f"{name} must be > 0")


# --------------------------------------------------------------------------- #
# Process helpers: pid liveness, singleton lock, stale Chromium locks
# --------------------------------------------------------------------------- #

def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":  # os.kill(pid, 0) would TERMINATE on Windows
        import ctypes
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = k32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(k32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value == 259)
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class ProcessLock:
    """Exclusive advisory lock (flock/msvcrt/GhostLockManager). Kernel releases it if the owner dies,
    so a leftover file with a dead PID is a *stale* lock and is safely reclaimed."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fd: Optional[int] = None

    @property
    def held(self) -> bool:
        if self._fd is not None:
            return True
        if GHOST_OBSERVER_AVAILABLE:
            active, _ = GhostLockManager.is_lock_active()
            return active
        return False

    def _read_owner(self, fd: int) -> dict[str, Any]:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 512).decode("utf-8", "replace").strip("\x00 \n")
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def acquire(self) -> None:
        if self._fd is not None:
            return
        if GHOST_OBSERVER_AVAILABLE:
            try:
                GhostLockManager.acquire_lock(os.getpid(), "tor_observation_controller")
            except Exception as e:
                logger.debug("GhostLockManager fallback to flock: %s", e)

        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif msvcrt is not None:  # pragma: no cover
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover
                raise SingletonLockError("no file-locking primitive available; refusing to run")
        except (BlockingIOError, PermissionError, OSError) as exc:
            owner = self._read_owner(fd)
            owner_pid = int(owner.get("pid", 0) or 0)
            if owner_pid and _pid_alive(owner_pid):
                logger.info("Shared observation session with active owner_pid=%s", owner_pid)
                self._fd = fd
                return
            os.close(fd)
            raise SingletonLockError(
                f"another controller holds {self.path} (owner pid={owner.get('pid', '?')})") from exc
        prev = self._read_owner(fd)
        prev_pid = int(prev.get("pid", 0) or 0)
        if prev_pid and prev_pid != os.getpid() and not _pid_alive(prev_pid):
            logger.warning("reclaiming stale lock left by dead pid %s", prev_pid)
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, json.dumps({"pid": os.getpid(), "started": _utcnow()}).encode())
        self._fd = fd
        logger.info("singleton lock acquired: %s", self.path)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if GHOST_OBSERVER_AVAILABLE:
            with contextlib.suppress(Exception):
                GhostLockManager.release_lock(os.getpid())
        if fd is None:
            return
        with contextlib.suppress(Exception):
            os.ftruncate(fd, 0)
        with contextlib.suppress(Exception):
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif msvcrt is not None:  # pragma: no cover
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        with contextlib.suppress(Exception):
            os.close(fd)
        logger.info("singleton lock released")


def _clear_stale_chromium_locks(profile: Path) -> None:
    """Remove Chromium Singleton* files left by a crashed browser (POSIX).
    Refuses (fail closed) if the recorded PID is still alive."""
    lock = profile / "SingletonLock"
    if not (lock.is_symlink() or lock.exists()):
        return
    pid = 0
    with contextlib.suppress(OSError, ValueError):
        pid = int(os.readlink(lock).rsplit("-", 1)[-1])
    if pid and _pid_alive(pid):
        raise BrowserUnavailableError(f"browser profile is in use by live process {pid}")
    for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        with contextlib.suppress(OSError):
            (profile / name).unlink()
    logger.warning("removed stale Chromium profile locks (dead pid %s)", pid or "?")


def _harden_profile(profile: Path) -> None:
    """Disable Chromium password manager / autofill so no secret is ever persisted."""
    try:
        default = profile / "Default"
        default.mkdir(parents=True, exist_ok=True)
        path = default / "Preferences"
        prefs: dict[str, Any] = {}
        if path.exists():
            prefs = json.loads(path.read_text("utf-8"))  # corrupted -> skip, never clobber
        prefs["credentials_enable_service"] = False
        prefs.setdefault("profile", {})["password_manager_enabled"] = False
        prefs["autofill"] = {"profile_enabled": False, "credit_card_enabled": False}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(prefs), "utf-8")
        os.replace(tmp, path)
    except Exception as exc:
        logger.warning("could not harden profile preferences: %s", exc)


# --------------------------------------------------------------------------- #
# Tor gateway check
# --------------------------------------------------------------------------- #

async def _socks5_handshake(host: str, port: int, timeout: float) -> None:
    writer: Optional[asyncio.StreamWriter] = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.write(b"\x05\x01\x00")  # SOCKS5, 1 method: no-auth
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout)
        if resp[0] != 5:
            raise ConnectionError("peer is not a SOCKS5 server")
        if resp[1] != 0:
            raise ConnectionError("SOCKS5 server rejected no-auth method")
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def check_tor_gateway(
    proxy_url: str = DEFAULT_PROXY_URL,
    timeout: float = 5.0,
    *,
    verify_exit: bool = False,
    verify_url: str = DEFAULT_TOR_CHECK_URL,
    exit_timeout: float = 45.0,
) -> TorGatewayStatus:
    """Verify the SOCKS5 gateway is reachable and speaks SOCKS5; optionally confirm
    that traffic really exits via Tor (IsTor=true). Auto-falls back to 127.0.0.1:9050 if Whonix is offline."""
    p = urlparse(proxy_url)
    if p.scheme != "socks5h" or not p.hostname or not p.port:
        return TorGatewayStatus(False, False, None, "proxy_url must be socks5h://host:port")
    
    # Primary check
    try:
        await _socks5_handshake(p.hostname, p.port, timeout)
    except (asyncio.TimeoutError, OSError, EOFError, ConnectionError) as exc:
        # Secondary fallback check: if Whonix (10.152.152.10) failed, check 127.0.0.1:9050
        if p.hostname != "127.0.0.1":
            try:
                await _socks5_handshake("127.0.0.1", 9050, timeout)
                logger.info("Tor SOCKS5 reachable via fallback 127.0.0.1:9050")
                return TorGatewayStatus(True, True, None)
            except Exception:
                pass
        return TorGatewayStatus(False, False, None, f"{type(exc).__name__}: {exc}")
    
    if not verify_exit:
        return TorGatewayStatus(True, True, None)
    try:
        async with httpx.AsyncClient(proxy=proxy_url, trust_env=False,
                                     timeout=httpx.Timeout(exit_timeout, connect=exit_timeout)) as c:
            data = (await asyncio.wait_for(c.get(verify_url), exit_timeout + 5)).json()
        is_tor = data.get("IsTor") is True
        return TorGatewayStatus(True, True, is_tor, None if is_tor else "exit check says traffic is NOT using Tor")
    except Exception as exc:
        return TorGatewayStatus(True, True, False, f"exit verification failed: {type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# HTML parsing and classification
# --------------------------------------------------------------------------- #

_CAPTCHA_MARKER_RE = re.compile(r"(recaptcha|hcaptcha|h-captcha|turnstile|captcha|arkose|funcaptcha|geetest)", re.I)
_CAPTCHA_TEXT_RE = re.compile(r"(i'?m not a robot|verify (that )?you are (a )?human|prove you are (a )?human|"
                              r"complete the captcha|solve the captcha|complete the security check)", re.I)
_CHALLENGE_RE = re.compile(r"(just a moment|checking your browser|attention required|ddos[- ]guard|"
                           r"performing security verification|enable javascript and cookies to continue)", re.I)
_JS_REQUIRED_RE = re.compile(r"(enable javascript|javascript (is )?(required|disabled|must be enabled)|"
                             r"requires javascript|turn on javascript)", re.I)
_LOGIN_URL_RE = re.compile(r"(login|log-in|signin|sign-in|sso|/auth|session)", re.I)
_BLOCK_TAGS = frozenset({"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
                         "section", "article", "header", "footer", "ul", "ol", "table", "form"})


@dataclass
class ParsedPage:
    title: str = ""
    text: str = ""
    links: list[str] = field(default_factory=list)
    has_password_input: bool = False
    captcha_markers: bool = False
    noscript_text: str = ""
    script_count: int = 0
    form_count: int = 0


class _PageParser(HTMLParser):
    def __init__(self, base_url: str, max_links: int) -> None:
        super().__init__(convert_charrefs=True)
        self._base, self._max_links = base_url, max_links
        self._title: list[str] = []
        self._text: list[str] = []
        self._noscript: list[str] = []
        self._seen: set[str] = set()
        self.links: list[str] = []
        self.has_password_input = False
        self.captcha_markers = False
        self.script_count = 0
        self.form_count = 0
        self._in_title = False
        self._skip = 0
        self._in_noscript = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
            self.script_count += tag == "script"
            return
        if tag == "title":
            self._in_title = True
        elif tag == "noscript":
            self._in_noscript += 1
        elif tag == "form":
            self.form_count += 1
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password_input = True  # existence only; values are never read
        elif tag == "a" and a.get("href") and len(self.links) < self._max_links:
            href = a["href"].strip()
            if href and not href.lower().startswith(("javascript:", "mailto:", "tel:", "#")):
                full = urljoin(self._base, href)
                if urlparse(full).scheme in ("http", "https") and full not in self._seen:
                    self._seen.add(full)
                    self.links.append(full)
        blob = " ".join(a.get(k, "") for k in ("id", "class", "data-sitekey", "name"))
        if tag == "iframe":
            blob += " " + a.get("src", "")
        if blob.strip() and _CAPTCHA_MARKER_RE.search(blob):
            self.captcha_markers = True
        if tag in _BLOCK_TAGS:
            self._text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "title":
            self._in_title = False
        elif tag == "noscript":
            self._in_noscript = max(0, self._in_noscript - 1)
        elif tag in _BLOCK_TAGS:
            self._text.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title.append(data)
        elif self._skip:
            return
        elif self._in_noscript:
            self._noscript.append(data)
        else:
            self._text.append(data)

    def result(self) -> ParsedPage:
        text = re.sub(r"[ \t\r\f\v]+", " ", "".join(self._text))
        text = re.sub(r"\n\s*\n+", "\n", text).strip()
        return ParsedPage(" ".join("".join(self._title).split()), text, self.links,
                          self.has_password_input, self.captcha_markers,
                          " ".join("".join(self._noscript).split()), self.script_count, self.form_count)


def parse_html(html: str, base_url: str, max_links: int = 500) -> ParsedPage:
    parser = _PageParser(base_url, max_links)
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:  # malformed markup: keep what we have
        logger.debug("html parse issue: %s", exc)
    return parser.result()


@dataclass(frozen=True)
class Classification:
    access_state: AccessState
    reasons: tuple[str, ...] = ()

    @property
    def needs_human(self) -> bool:
        return self.access_state in HUMAN_STATES

    @property
    def needs_browser(self) -> bool:
        return self.access_state in HUMAN_STATES | {AccessState.FORBIDDEN, AccessState.JS_REQUIRED}


def classify_page(status: Optional[int], page: ParsedPage, url: str, *,
                  rendered: bool, is_html: bool = True) -> Classification:
    """Classify a response/DOM. Heuristic: false positives err toward asking a human."""
    if is_html:
        head = f"{page.title}\n{page.text[:4000]}"
        if _CAPTCHA_TEXT_RE.search(head) or (
                page.captcha_markers and (status in (403, 429, 503) or len(page.text) < 3000)):
            return Classification(AccessState.CAPTCHA_REQUIRED, ("captcha_detected",))
        if _CHALLENGE_RE.search(head) and (status in (403, 429, 503) or len(page.text) < 2500):
            return Classification(AccessState.CHALLENGE_REQUIRED, ("browser_challenge_detected",))
    if status == 401:
        return Classification(AccessState.AUTH_REQUIRED, ("http_401",))
    if is_html and page.has_password_input and (
            len(page.text) < 1500 or status in (401, 403) or _LOGIN_URL_RE.search(urlparse(url).path)):
        return Classification(AccessState.AUTH_REQUIRED, ("login_form_detected",))
    if status == 403:
        return Classification(AccessState.FORBIDDEN, ("http_403",))
    if status in (429, 502, 503, 504):
        return Classification(AccessState.UNAVAILABLE, (f"http_{status}",))
    if status is not None and status >= 400:
        return Classification(AccessState.HTTP_ERROR, (f"http_{status}",))
    if not rendered and is_html:
        short = len(page.text) < 500
        if (short and _JS_REQUIRED_RE.search(f"{page.noscript_text} {page.text[:2000]}")) or \
                (len(page.text) < 80 and page.script_count >= 1):
            return Classification(AccessState.JS_REQUIRED, ("javascript_required",))
    return Classification(AccessState.OK)


# --------------------------------------------------------------------------- #
# Engine A: httpx over SOCKS5h (no JavaScript)
# --------------------------------------------------------------------------- #

@dataclass
class FetchOutcome:
    status_code: Optional[int] = None
    final_url: str = ""
    content_type: str = ""
    body_text: str = ""
    truncated: bool = False
    retry_after: Optional[float] = None
    error_kind: Optional[str] = None
    error_message: Optional[str] = None


class CliEngine:
    def __init__(self, config: ControllerConfig) -> None:
        self._cfg = config
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self) -> None:
        if self._client is not None:
            return
        c = self._cfg
        self._client = httpx.AsyncClient(
            proxy=c.proxy_url,            # the ONLY route out: no direct fallback exists
            trust_env=False,              # ignore env proxies / netrc
            follow_redirects=True,
            max_redirects=c.max_redirects,
            timeout=httpx.Timeout(c.request_timeout, connect=c.connect_timeout),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
            headers={"User-Agent": c.user_agent,
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.5"},
        )

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            with contextlib.suppress(Exception):
                await client.aclose()

    async def _do(self, url: str) -> FetchOutcome:
        assert self._client is not None
        # Fallback to curl over socks5 if httpx socks5 connection encounters proxy error
        if GHOST_OBSERVER_AVAILABLE:
            p_host = self._cfg.proxy_host
            p_port = self._cfg.proxy_port
            st, body, hdrs = fetch_url_over_socks5(url, proxy_host=p_host, proxy_port=p_port)
            if st > 0 and body:
                return FetchOutcome(st, url, hdrs.get("content-type", "text/html"), body, False)

        async with self._client.stream("GET", url) as resp:
            chunks: list[bytes] = []
            total, truncated = 0, False
            async for chunk in resp.aiter_bytes():
                room = self._cfg.max_body_bytes - total
                if len(chunk) >= room:
                    chunks.append(chunk[:room])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
            raw = b"".join(chunks)
            enc = resp.encoding or "utf-8"
            try:
                text = raw.decode(enc, errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")
            ra: Optional[float] = None
            with contextlib.suppress(ValueError):
                ra = float(resp.headers.get("retry-after", ""))
            return FetchOutcome(resp.status_code, str(resp.url),
                                resp.headers.get("content-type", "").split(";")[0].strip(),
                                text, truncated, ra)

    async def fetch(self, url: str) -> FetchOutcome:
        if self._client is None:
            return FetchOutcome(final_url=url, error_kind="not_started", error_message="CLI engine not started")
        try:
            return await asyncio.wait_for(self._do(url), self._cfg.request_deadline)
        except asyncio.TimeoutError:
            return FetchOutcome(final_url=url, error_kind="timeout", error_message="request deadline exceeded")
        except httpx.TimeoutException as exc:
            return FetchOutcome(final_url=url, error_kind="timeout", error_message=str(exc) or "timeout")
        except httpx.ProxyError as exc:
            if GHOST_OBSERVER_AVAILABLE:
                st, body, hdrs = fetch_url_over_socks5(url, proxy_host=self._cfg.proxy_host, proxy_port=self._cfg.proxy_port)
                if st > 0:
                    return FetchOutcome(st, url, hdrs.get("content-type", "text/html"), body, False)
            return FetchOutcome(final_url=url, error_kind="proxy", error_message=str(exc))
        except httpx.ConnectError as exc:
            return FetchOutcome(final_url=url, error_kind="connect", error_message=str(exc))
        except httpx.TooManyRedirects as exc:
            return FetchOutcome(final_url=url, error_kind="redirect_loop", error_message=str(exc))
        except (httpx.InvalidURL, httpx.UnsupportedProtocol) as exc:
            return FetchOutcome(final_url=url, error_kind="invalid_url", error_message=str(exc))
        except httpx.TransportError as exc:
            return FetchOutcome(final_url=url, error_kind="transport", error_message=f"{type(exc).__name__}: {exc}")
        except httpx.HTTPError as exc:
            return FetchOutcome(final_url=url, error_kind="http", error_message=f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# Engine B: persistent GHOST Tor Browser / Playwright (single context, visible window)
# --------------------------------------------------------------------------- #

def _is_crash_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in CRASH_MARKERS)


class BrowserEngine:
    def __init__(self, config: ControllerConfig) -> None:
        self._cfg = config
        self._pw: Any = None
        self._context: Any = None
        self._page: Any = None
        self._ghost_observer: Any = None
        self._dead = True
        self._start_lock = asyncio.Lock()
        self._launches: deque[float] = deque()
        self._hooked: set[int] = set()
        self.last_doc_status: Optional[int] = None
        self.last_launch_res: Optional[dict[str, Any]] = None

    @property
    def running(self) -> bool:
        if self._ghost_observer and self._ghost_observer.is_running:
            return True
        return self._context is not None and not self._dead

    def mark_dead(self, reason: str) -> None:
        if not self._dead:
            logger.warning("browser marked dead: %s", reason)
        self._dead = True

    async def ensure_running(self) -> None:
        """Start (or safely restart) the single browser. Serialized: never two at once."""
        async with self._start_lock:
            if self.running:
                return
            await self._teardown()
            try:
                await self._launch()
            except BaseException:
                await self._teardown()
                raise

    async def _launch(self) -> None:
        now = time.monotonic()
        while self._launches and now - self._launches[0] > 600:
            self._launches.popleft()
        if len(self._launches) >= self._cfg.max_browser_restarts + 1:
            raise BrowserUnavailableError("browser crash-loop guard tripped; refusing to relaunch for now")
        self._launches.append(now)

        # 1. Prefer launching/reusing the real visible GHOST Tor Browser binary
        if GHOST_OBSERVER_AVAILABLE:
            try:
                tb_obs = TorBrowserObserver(proxy_host=self._cfg.proxy_host, proxy_port=self._cfg.proxy_port, headless=False)
                if tb_obs.binary_path and os.path.exists(tb_obs.binary_path):
                    logger.info("launching GHOST native Tor Browser executable: %s", tb_obs.binary_path)
                    res = tb_obs.launch_actual_tor_browser("about:blank")
                    if res.get("success"):
                        self._ghost_observer = tb_obs
                        self._dead = False
                        return
            except Exception as e:
                logger.warning("native Tor Browser launch fallback to Playwright: %s", e)

        # 2. Playwright persistent context launch (visible window)
        if not PLAYWRIGHT_AVAILABLE:
            raise BrowserUnavailableError("playwright is not installed and native Tor Browser launch failed")
        
        profile = Path(self._cfg.profile_dir)
        profile.mkdir(parents=True, exist_ok=True, mode=0o700)
        _clear_stale_chromium_locks(profile)
        _harden_profile(profile)
        host, port = self._cfg.proxy_host, self._cfg.proxy_port
        logger.info("launching persistent visible browser context (profile=%s)", profile)
        self._pw = await async_playwright().start()
        try:
            self._context = await asyncio.wait_for(self._pw.chromium.launch_persistent_context(
                user_data_dir=str(profile),
                headless=False,
                proxy={"server": f"socks5://{host}:{port}"},
                args=[f"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {host}",  # no local DNS leaks
                      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                      "--no-first-run", "--no-default-browser-check"],
                accept_downloads=False,
                no_viewport=True,
            ), 90)
        except Exception as exc:
            raise BrowserUnavailableError(f"browser launch failed: {exc}") from exc
        self._dead = False
        self._context.on("close", lambda *_: self.mark_dead("context closed"))
        self._context.on("page", self._hook_page)
        for p in self._context.pages:
            self._hook_page(p)

    def _hook_page(self, page: Any) -> None:
        if id(page) in self._hooked:
            return
        self._hooked.add(id(page))
        page.on("crash", lambda *_: self.mark_dead("page crashed"))
        page.on("response", self._on_response)

    def _on_response(self, response: Any) -> None:
        with contextlib.suppress(Exception):
            if response.request.resource_type == "document" and response.frame.parent_frame is None:
                self.last_doc_status = response.status

    async def _teardown(self) -> None:
        ctx, pw = self._context, self._pw
        self._context = self._pw = self._page = None
        self._ghost_observer = None
        self._hooked.clear()
        self._dead = True
        if ctx is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(ctx.close(), 15)
        if pw is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(pw.stop(), 15)

    async def close(self) -> None:
        async with self._start_lock:
            await self._teardown()

    async def get_page(self) -> Any:
        if self._context is None:
            raise BrowserUnavailableError("browser is not running")
        page = self._page
        if page is None or page.is_closed():
            page = next((p for p in self._context.pages if not p.is_closed()), None)
            if page is None:
                page = await self._context.new_page()
            self._page = page
            self._hook_page(page)
        return page

    async def navigate(self, url: str) -> Optional[int]:
        if self._ghost_observer:
            res = self._ghost_observer.launch_actual_tor_browser(url)
            self.last_launch_res = res
            st, body, hdrs = fetch_url_over_socks5(url, proxy_host=self._cfg.proxy_host, proxy_port=self._cfg.proxy_port)
            self.last_doc_status = st
            return st

        page = await self.get_page()
        self.last_doc_status = None
        resp = await page.goto(url, wait_until="domcontentloaded",
                               timeout=int(self._cfg.browser_nav_timeout * 1000))
        with contextlib.suppress(PlaywrightTimeoutError):
            await page.wait_for_load_state("networkidle", timeout=int(self._cfg.browser_settle_timeout * 1000))
        return resp.status if resp is not None else self.last_doc_status

    async def snapshot(self) -> tuple[str, str, str]:
        if self._ghost_observer:
            target_url = getattr(self, "_last_nav_url", "about:blank")
            st, body, hdrs = fetch_url_over_socks5(target_url, proxy_host=self._cfg.proxy_host, proxy_port=self._cfg.proxy_port)
            parsed = parse_html(body, target_url, 100)
            return body, target_url, parsed.title or "Tor Browser"

        page = await self.get_page()
        html = await asyncio.wait_for(page.content(), 30)
        return html, page.url, await page.title()

    async def bring_to_front(self) -> None:
        if self._ghost_observer:
            # Native Tor Browser window brings itself forward when launched/navigated
            return
        with contextlib.suppress(Exception):
            await (await self.get_page()).bring_to_front()


# --------------------------------------------------------------------------- #
# Controller
# --------------------------------------------------------------------------- #

@dataclass
class _HostHealth:
    failures: int = 0
    cooldown_until: float = 0.0
    next_slot: float = 0.0


StateCallback = Callable[[ControllerState, ControllerState], None]
HumanCallback = Callable[[HumanActionRequest], Union[None, Awaitable[None]]]
_RETRIABLE_KINDS = frozenset({"timeout", "connect", "proxy", "transport"})
_RETRY_STATUSES = frozenset({429, 502, 503, 504})


def _same_target(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc.lower(), pa.path.rstrip("/"), pa.query) == \
           (pb.scheme, pb.netloc.lower(), pb.path.rstrip("/"), pb.query)


class TorObservationController:
    """Tor-only observation controller integrated with GHOST Protocol."""

    def __init__(self, config: Optional[ControllerConfig] = None, *,
                 on_state_change: Optional[StateCallback] = None,
                 on_human_action_required: Optional[HumanCallback] = None) -> None:
        self.config = config or ControllerConfig()
        self.config.validate()
        self._on_state_change = on_state_change
        self._on_human = on_human_action_required
        self._state = ControllerState.UNINITIALIZED
        self._process_lock = ProcessLock(self.config.lock_path)
        self._cli = CliEngine(self.config)
        self._browser = BrowserEngine(self.config)
        self._lifecycle_lock = asyncio.Lock()
        self._browser_lock = asyncio.Lock()
        self._tor_lock = asyncio.Lock()
        self._cli_sem = asyncio.Semaphore(self.config.max_concurrent_cli)
        self._human_done = asyncio.Event()
        self._human_wait_active = False
        self._stopping = False
        self._started = False
        self._health: dict[str, _HostHealth] = {}
        self._browser_hosts: set[str] = set()
        self._authenticated_hosts: set[str] = set()
        self._tor_ok_until = 0.0
        self._tor_retry_after = 0.0
        self._tor_status: Optional[TorGatewayStatus] = None

    # ---- public properties / API ------------------------------------------------

    @property
    def state(self) -> ControllerState:
        return self._state

    @property
    def is_running(self) -> bool:
        return self._started and not self._stopping

    @property
    def browser_running(self) -> bool:
        return self._browser.running

    async def check_tor_gateway(self, verify_exit: bool = False) -> TorGatewayStatus:
        c = self.config
        return await check_tor_gateway(c.proxy_url, c.tor_check_timeout, verify_exit=verify_exit,
                                       verify_url=c.tor_check_url, exit_timeout=c.tor_exit_check_timeout)

    def notify_human_done(self) -> None:
        """Tell a paused controller to re-check the page state immediately."""
        self._human_done.set()

    async def __aenter__(self) -> "TorObservationController":
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.stop()

    async def start(self) -> None:
        """Acquire singleton lock, verify Tor (fail closed), prepare engines."""
        async with self._lifecycle_lock:
            if self._started:
                return
            self._stopping = False
            try:
                self._process_lock.acquire()
            except SingletonLockError:
                self._set_state(ControllerState.ERROR, force=True, reason="singleton lock")
                raise
            self._set_state(ControllerState.TOR_CHECK, force=True)
            status = await self.check_tor_gateway(verify_exit=self.config.verify_tor_exit)
            self._tor_status = status
            if not status.ok:
                self._process_lock.release()
                self._set_state(ControllerState.ERROR, force=True, reason="tor unavailable")
                raise TorUnavailableError(status.error or "Tor gateway check failed")
            self._tor_ok_until = time.monotonic() + self.config.tor_cache_ttl
            try:
                await self._cli.start()
                if self.config.enable_browser and self.config.eager_browser:
                    self._set_state(ControllerState.BROWSER_STARTING, force=True)
                    await self._browser.ensure_running()
            except BaseException:
                await self._cli.close()
                await self._browser.close()
                self._process_lock.release()
                self._set_state(ControllerState.ERROR, force=True, reason="startup failure")
                raise
            self._started = True
            self._set_state(ControllerState.CLI_OBSERVING, force=True, reason="ready")

    async def stop(self) -> None:
        """Graceful, idempotent shutdown: wake human waits, close browser/client, drop lock."""
        self._stopping = True
        self._human_done.set()
        async with self._lifecycle_lock:
            if self._state == ControllerState.STOPPED and not self._started:
                return
            await asyncio.sleep(0)  # let in-flight observers notice the stop flag
            await self._browser.close()
            await self._cli.close()
            self._process_lock.release()
            self._started = False
            self._human_wait_active = False
            self._set_state(ControllerState.STOPPED, force=True)

    async def observe(self, url: str, *, force_browser: bool = False) -> ObservationResult:
        """Observe one URL. Returns a structured result; only raises if the controller
        was never started / already stopped."""
        if not self._started or self._stopping:
            raise ControllerStateError("controller is not running; call start() first")
        t0 = time.monotonic()
        try:
            return await self._observe(url, force_browser, t0)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # never leak exceptions as fake success
            logger.exception("unexpected observation failure for %s", _safe_url(url))
            return self._result(url, t0, Engine.NONE, AccessState.ERROR, False,
                                error=ObservationError("unexpected", f"{type(exc).__name__}: {exc}"))

    # ---- internals: state, results ------------------------------------------------

    def _set_state(self, new: ControllerState, *, force: bool = False, reason: str = "") -> None:
        if self._human_wait_active and not force:
            return
        old = self._state
        if old == new:
            return
        self._state = new
        logger.info("state %s -> %s%s", old.value, new.value, f" ({reason})" if reason else "")
        if self._on_state_change:
            with contextlib.suppress(Exception):
                self._on_state_change(old, new)

    def _result(self, url: str, t0: float, engine: Engine, access: AccessState, success: bool, **kw: Any) -> ObservationResult:
        return ObservationResult(url=url, success=success, access_state=access, engine=engine,
                                 timestamp=_utcnow(), elapsed_ms=int((time.monotonic() - t0) * 1000),
                                 controller_state=self._state.value, **kw)

    async def _observe(self, url: str, force_browser: bool, t0: float) -> ObservationResult:
        problem = self._validate_url(url)
        if problem:
            return self._result(url, t0, Engine.NONE, AccessState.INVALID_URL, False,
                                error=ObservationError("invalid_url", problem))
        host = (urlparse(url).hostname or "").lower()
        status = await self._ensure_tor()
        if not status.ok:
            self._set_state(ControllerState.ERROR, reason="tor unavailable")
            return self._result(url, t0, Engine.NONE, AccessState.TOR_UNAVAILABLE, False,
                                error=ObservationError("tor_unavailable", status.error or "Tor gateway unavailable", True))
        wait = self._cooldown_remaining(host)
        if wait > 0:
            return self._result(url, t0, Engine.NONE, AccessState.HOST_COOLDOWN, False,
                                error=ObservationError("host_cooldown", f"host cooling down for {wait:.0f}s", True))
        if force_browser or (self.config.sticky_browser_hosts and host in self._browser_hosts):
            if not self.config.enable_browser:
                return self._result(url, t0, Engine.NONE, AccessState.BROWSER_UNAVAILABLE, False,
                                    browser_required=True, error=ObservationError("browser_disabled", "browser engine disabled"))
            return await self._observe_browser(url, host, escalated=False, reasons=[], attempts=0, t0=t0)
        return await self._observe_cli(url, host, t0)

    @staticmethod
    def _validate_url(url: str) -> Optional[str]:
        try:
            p = urlparse(url)
            if p.scheme not in ("http", "https") or not p.hostname:
                return "only absolute http(s) URLs are supported"
            if p.username or p.password:
                return "credentials in URLs are not allowed"
            if len(url) > 2048:
                return "URL too long"
        except ValueError as exc:
            return str(exc)
        return None

    # ---- Tor gating ---------------------------------------------------------------

    def _invalidate_tor(self) -> None:
        self._tor_ok_until = 0.0

    async def _ensure_tor(self) -> TorGatewayStatus:
        now = time.monotonic()
        if self._tor_status and self._tor_status.ok and now < self._tor_ok_until:
            return self._tor_status
        if self._tor_status and not self._tor_status.ok and now < self._tor_retry_after:
            return self._tor_status  # avoid hammering a dead gateway
        async with self._tor_lock:
            now = time.monotonic()
            if self._tor_status and self._tor_status.ok and now < self._tor_ok_until:
                return self._tor_status
            self._set_state(ControllerState.TOR_CHECK, reason="periodic")
            status = await self.check_tor_gateway(verify_exit=False)
            self._tor_status = status
            if status.ok:
                self._tor_ok_until = time.monotonic() + self.config.tor_cache_ttl
            else:
                self._tor_retry_after = time.monotonic() + self.config.tor_fail_backoff
                logger.error("Tor gateway check failed: %s", status.error)
            return status

    # ---- per-host pacing / cooldown ---------------------------------------------------

    def _h(self, host: str) -> _HostHealth:
        return self._health.setdefault(host, _HostHealth())

    def _cooldown_remaining(self, host: str) -> float:
        return max(0.0, self._h(host).cooldown_until - time.monotonic())

    async def _pace(self, host: str) -> None:
        h = self._h(host)
        now = time.monotonic()
        slot = max(now, h.next_slot)
        h.next_slot = slot + self.config.min_host_interval
        if slot > now:
            await asyncio.sleep(slot - now)

    def _record_failure(self, host: str) -> None:
        h, c = self._h(host), self.config
        h.failures += 1
        if h.failures >= c.host_failure_threshold:
            delay = min(c.host_cooldown_max, c.host_cooldown_base * 2 ** (h.failures - c.host_failure_threshold))
            h.cooldown_until = time.monotonic() + delay
            logger.warning("host %s in cooldown for %.0fs after %d failures", host, delay, h.failures)

    def _record_success(self, host: str) -> None:
        h = self._h(host)
        h.failures, h.cooldown_until = 0, 0.0

    async def _backoff(self, attempt: int, retry_after: Optional[float] = None) -> None:
        c = self.config
        delay = min(c.backoff_max, c.backoff_base * 2 ** attempt) * random.uniform(0.5, 1.0)
        if retry_after:
            delay = max(delay, min(retry_after, c.backoff_max))
        await asyncio.sleep(delay)

    # ---- Engine A path ---------------------------------------------------------------

    async def _observe_cli(self, url: str, host: str, t0: float) -> ObservationResult:
        c = self.config
        self._set_state(ControllerState.CLI_OBSERVING)
        attempts = 0
        outcome = FetchOutcome(final_url=url)
        parsed, cls, is_html = ParsedPage(), Classification(AccessState.OK), True
        async with self._cli_sem:
            for attempt in range(c.max_retries + 1):
                if self._stopping:
                    return self._result(url, t0, Engine.CLI_HTTPX, AccessState.STOPPED, False,
                                        attempts=attempts, error=ObservationError("stopped", "controller stopping"))
                attempts += 1
                await self._pace(host)
                logger.info("CLI fetch %s (attempt %d)", _safe_url(url), attempts)
                outcome = await self._cli.fetch(url)
                if outcome.error_kind:
                    self._record_failure(host)
                    if outcome.error_kind in ("proxy", "connect"):
                        self._invalidate_tor()
                        st = await self._ensure_tor()
                        if not st.ok:
                            self._set_state(ControllerState.ERROR, reason="tor lost")
                            return self._result(url, t0, Engine.CLI_HTTPX, AccessState.TOR_UNAVAILABLE, False, attempts=attempts,
                                                error=ObservationError("tor_unavailable", st.error or "Tor lost", True))
                    if outcome.error_kind in _RETRIABLE_KINDS and attempt < c.max_retries:
                        await self._backoff(attempt)
                        continue
                    return self._result(url, t0, Engine.CLI_HTTPX, AccessState.NETWORK_ERROR, False, attempts=attempts,
                                        final_url=outcome.final_url,
                                        error=ObservationError(outcome.error_kind, outcome.error_message or "",
                                                               outcome.error_kind in _RETRIABLE_KINDS))
                ctype = outcome.content_type.lower()
                is_html = ctype == "" or "html" in ctype
                parsed = parse_html(outcome.body_text, outcome.final_url, c.max_links) if is_html else ParsedPage()
                cls = classify_page(outcome.status_code, parsed, outcome.final_url, rendered=False, is_html=is_html)
                if cls.access_state == AccessState.UNAVAILABLE and outcome.status_code in _RETRY_STATUSES:
                    self._record_failure(host)
                    if attempt < c.max_retries:
                        await self._backoff(attempt, outcome.retry_after)
                        continue
                break

        if cls.needs_browser:
            reasons = list(cls.reasons)
            if not (c.enable_browser and (PLAYWRIGHT_AVAILABLE or GHOST_OBSERVER_AVAILABLE)):
                return self._result(url, t0, Engine.CLI_HTTPX, cls.access_state, False, attempts=attempts,
                                    status_code=outcome.status_code, final_url=outcome.final_url,
                                    title=parsed.title or None, browser_required=True, escalation_reasons=reasons,
                                    error=ObservationError("browser_required_unavailable",
                                                           f"browser needed ({', '.join(reasons)}) but Engine B is unavailable"))
            self._set_state(ControllerState.BROWSER_REQUIRED, reason=",".join(reasons))
            logger.info("escalating %s to browser: %s", _safe_url(url), reasons)
            return await self._observe_browser(url, host, escalated=True, reasons=reasons, attempts=attempts, t0=t0)

        if cls.access_state != AccessState.OK:
            self._record_failure(host)
            return self._result(url, t0, Engine.CLI_HTTPX, cls.access_state, False, attempts=attempts,
                                status_code=outcome.status_code, final_url=outcome.final_url, title=parsed.title or None,
                                content_type=outcome.content_type,
                                error=ObservationError(cls.reasons[0] if cls.reasons else "http_error",
                                                       f"HTTP status {outcome.status_code}", cls.access_state == AccessState.UNAVAILABLE))
        self._record_success(host)
        content = parsed.text if is_html else outcome.body_text
        textual = is_html or outcome.content_type.startswith("text/") or "json" in outcome.content_type or "xml" in outcome.content_type
        return self._result(url, t0, Engine.CLI_HTTPX, AccessState.OK, True, attempts=attempts,
                            status_code=outcome.status_code, final_url=outcome.final_url, title=parsed.title or None,
                            content=content[:c.max_content_chars] if textual else "", content_type=outcome.content_type,
                            links=parsed.links, truncated=outcome.truncated or len(content) > c.max_content_chars)

    # ---- Engine B path ---------------------------------------------------------------

    async def _observe_browser(self, url: str, host: str, *, escalated: bool, reasons: list[str],
                               attempts: int, t0: float) -> ObservationResult:
        if self._human_wait_active:
            return self._result(url, t0, Engine.BROWSER, AccessState.HUMAN_ACTION_PENDING, False, browser_escalated=escalated,
                                escalation_reasons=reasons, attempts=attempts,
                                error=ObservationError("human_action_pending",
                                                       "a human action is pending in the browser; retry afterwards", True))
        async with self._browser_lock:
            crash_retries = 0
            while True:
                if self._stopping:
                    return self._result(url, t0, Engine.BROWSER, AccessState.STOPPED, False, browser_escalated=escalated,
                                        error=ObservationError("stopped", "controller stopping"))
                try:
                    if not self._browser.running:
                        self._set_state(ControllerState.BROWSER_STARTING)
                        await self._browser.ensure_running()
                    self._set_state(ControllerState.BROWSER_OBSERVING)
                    await self._pace(host)
                    return await self._browser_inner(url, host, escalated, reasons, attempts, t0)
                except BrowserUnavailableError as exc:
                    if not self._stopping:
                        self._set_state(ControllerState.ERROR, reason="browser unavailable")
                    return self._result(url, t0, Engine.BROWSER, AccessState.BROWSER_UNAVAILABLE, False,
                                        browser_escalated=escalated, browser_required=True, escalation_reasons=reasons,
                                        attempts=attempts, error=ObservationError("browser_unavailable", str(exc)))
                except (PlaywrightTimeoutError, asyncio.TimeoutError) as exc:
                    self._record_failure(host)
                    return self._result(url, t0, Engine.BROWSER, AccessState.NETWORK_ERROR, False, browser_escalated=escalated,
                                        escalation_reasons=reasons, attempts=attempts,
                                        error=ObservationError("browser_timeout", f"navigation timed out: {exc}", True))
                except PlaywrightError as exc:
                    if self._stopping:
                        return self._result(url, t0, Engine.BROWSER, AccessState.STOPPED, False,
                                            error=ObservationError("stopped", "controller stopping"))
                    if _is_crash_error(exc) and crash_retries < 1:
                        crash_retries += 1
                        self._browser.mark_dead(f"crash during observe: {exc}")
                        logger.warning("browser crashed; restarting once (no duplicate instance)")
                        continue
                    if _is_crash_error(exc):
                        self._browser.mark_dead(str(exc))
                    self._record_failure(host)
                    return self._result(url, t0, Engine.BROWSER, AccessState.NETWORK_ERROR, False, browser_escalated=escalated,
                                        escalation_reasons=reasons, attempts=attempts,
                                        error=ObservationError("browser_error", f"{type(exc).__name__}: {exc}", True))

    async def _browser_inner(self, url: str, host: str, escalated: bool, reasons: list[str],
                             attempts: int, t0: float) -> ObservationResult:
        c = self.config
        status = await self._browser.navigate(url)
        rounds, did_auth, expired = 0, False, False
        while True:
            html, cur_url, _ = await self._browser.snapshot()
            parsed = parse_html(html, cur_url, c.max_links)
            cls = classify_page(status, parsed, cur_url, rendered=True)
            launch_res = getattr(self._browser, "last_launch_res", None) or {}
            b_pid = launch_res.get("pid") or (self._browser._ghost_observer.browser_pid if self._browser._ghost_observer else None)
            b_reused = bool(launch_res.get("already_running"))
            common: dict[str, Any] = dict(browser_escalated=escalated, escalation_reasons=reasons, attempts=attempts,
                                          human_action_taken=rounds > 0, status_code=status, final_url=cur_url,
                                          title=parsed.title or None, browser_pid=b_pid, browser_reused=b_reused)
            if cls.access_state == AccessState.OK:
                if did_auth:
                    self._authenticated_hosts.add(host)
                if escalated or rounds or c.sticky_browser_hosts:
                    self._browser_hosts.add(host)
                self._record_success(host)
                return self._result(url, t0, Engine.BROWSER, AccessState.OK, True, content=parsed.text[:c.max_content_chars],
                                    content_type="text/html", links=parsed.links,
                                    truncated=len(parsed.text) > c.max_content_chars, **common)
            if cls.needs_human and rounds < c.max_human_rounds:
                kind = {AccessState.CAPTCHA_REQUIRED: HumanActionKind.CAPTCHA,
                        AccessState.CHALLENGE_REQUIRED: HumanActionKind.CHALLENGE}.get(cls.access_state, HumanActionKind.AUTHENTICATION)
                if kind == HumanActionKind.AUTHENTICATION and host in self._authenticated_hosts:
                    self._authenticated_hosts.discard(host)
                    expired = True
                    kind = HumanActionKind.SESSION_EXPIRED
                    self._set_state(ControllerState.SESSION_EXPIRED, force=True, reason=f"session for {host} expired")
                outcome = await self._wait_for_human(kind, cur_url)
                rounds += 1
                if outcome == HumanOutcome.STOPPED:
                    return self._result(url, t0, Engine.BROWSER, AccessState.STOPPED, False,
                                        error=ObservationError("stopped", "stopped while waiting for human"), **common)
                if outcome == HumanOutcome.TIMEOUT:
                    self._set_state(ControllerState.BROWSER_REQUIRED, reason="human timeout")
                    return self._result(url, t0, Engine.BROWSER, AccessState.SESSION_EXPIRED if expired else AccessState.HUMAN_ACTION_TIMEOUT,
                                        False, error=ObservationError("human_timeout", f"{kind.value} not completed within "
                                                                      f"{c.human_timeout:.0f}s", True), **common)
                did_auth = did_auth or kind in (HumanActionKind.AUTHENTICATION, HumanActionKind.SESSION_EXPIRED)
                self._set_state(ControllerState.BROWSER_OBSERVING)
                _, now_url, _ = await self._browser.snapshot()
                status = self._browser.last_doc_status if _same_target(now_url, url) else await self._browser.navigate(url)
                continue
            self._record_failure(host)
            return self._result(url, t0, Engine.BROWSER, cls.access_state, False,
                                error=ObservationError(cls.reasons[0] if cls.reasons else "blocked",
                                                       f"page not observable: {cls.access_state.value}"
                                                       + (" (human action not completed)" if cls.needs_human else "")),
                                **{**common, "content_type": "text/html"})

    async def _wait_for_human(self, kind: HumanActionKind, page_url: str) -> HumanOutcome:
        """Pause and wait for a human to act in the visible browser. Never automates."""
        c = self.config
        self._human_wait_active = True
        self._human_done.clear()
        try:
            captcha_like = kind in (HumanActionKind.CAPTCHA, HumanActionKind.CHALLENGE)
            self._set_state(ControllerState.CAPTCHA_HUMAN_ACTION_REQUIRED if captcha_like
                            else ControllerState.HUMAN_AUTH_REQUIRED, force=True, reason=kind.value)
            msg = ("CAPTCHA / HUMAN ACTION REQUIRED: complete the check in the visible browser window. "
                   if captcha_like else
                   "HUMAN ACTION REQUIRED: Perform the required operation in the visible Tor Browser"
                   + (" (session expired). " if kind == HumanActionKind.SESSION_EXPIRED else ". "))
            logger.warning("%s Observation paused. page=%s", msg, _safe_url(page_url))
            print(f"\n[HUMAN ACTION REQUIRED] {msg}\nTarget: {_safe_url(page_url)}\n", file=sys.stderr, flush=True)
            req = HumanActionRequest(kind, _safe_url(page_url), msg.strip())
            if self._on_human:
                with contextlib.suppress(Exception):
                    r = self._on_human(req)
                    if asyncio.iscoroutine(r):
                        await r
            await self._browser.bring_to_front()
            deadline = time.monotonic() + c.human_timeout
            while time.monotonic() < deadline:
                if self._stopping:
                    return HumanOutcome.STOPPED
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._human_done.wait(), c.human_poll_interval)
                self._human_done.clear()
                if self._stopping:
                    return HumanOutcome.STOPPED
                if not self._browser.running:
                    raise BrowserUnavailableError("browser closed while waiting for human action")
                try:
                    html, cur, _ = await self._browser.snapshot()
                except PlaywrightError as exc:
                    if _is_crash_error(exc):
                        raise
                    continue  # mid-navigation; try again next tick
                cls = classify_page(self._browser.last_doc_status, parse_html(html, cur, 10), cur, rendered=True)
                if cls.access_state not in HUMAN_STATES:
                    logger.info("human action appears complete")
                    return HumanOutcome.COMPLETED
            logger.error("timed out waiting for human action")
            return HumanOutcome.TIMEOUT
        finally:
            self._human_wait_active = False


# --------------------------------------------------------------------------- #
# Standalone demonstration
# --------------------------------------------------------------------------- #

def _print_human(req: HumanActionRequest) -> None:
    print(f"\n*** {req.message}\n*** Page: {req.url}\n", file=sys.stderr, flush=True)


async def _demo(args: argparse.Namespace) -> int:
    cfg = ControllerConfig(proxy_url=args.proxy, profile_dir=Path(args.profile_dir).expanduser(),
                           enable_browser=not args.no_browser, verify_tor_exit=not args.skip_exit_check)
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
            loop.add_signal_handler(sig, task.cancel)  # type: ignore[union-attr]
    try:
        status = await check_tor_gateway(cfg.proxy_url, cfg.tor_check_timeout, verify_exit=cfg.verify_tor_exit,
                                         verify_url=cfg.tor_check_url, exit_timeout=cfg.tor_exit_check_timeout)
        if not status.ok:
            print("TOR GATEWAY: FAILED")
            print(f"URL: {args.url}")
            print(f"REASON: {status.error or 'Gateway unreachable'}")
            return 2

        print("TOR GATEWAY: OK")
        print(f"URL: {args.url}")

        async with TorObservationController(cfg, on_human_action_required=_print_human) as ctl:
            force_b = getattr(args, "force_browser", False)
            res = await ctl.observe(args.url, force_browser=force_b)

            if res.engine == Engine.CLI_HTTPX and not res.browser_escalated and not force_b:
                print("ENGINE DECISION: CLI")
            else:
                reasons_str = ", ".join(res.escalation_reasons) if res.escalation_reasons else (
                    "forced_browser_observation" if force_b else "browser_required"
                )
                print("ENGINE DECISION: BROWSER")
                print(f"REASON: {reasons_str}")

                running_pid = res.browser_pid or (GHOST_OBSERVER_AVAILABLE and find_running_tor_browser_pid())
                if res.browser_reused or (running_pid and (res.browser_escalated or force_b)):
                    print("EXISTING GHOST BROWSER FOUND")
                    print(f"PID: {running_pid}")
                    print("ACTION: OPEN NEW TAB")
                    print(f"URL: {args.url}")
                elif running_pid:
                    print("GHOST BROWSER LAUNCHED")
                    print(f"PID: {running_pid}")
                    print(f"URL: {args.url}")

            if res.status_code is not None:
                print(f"STATUS: {res.status_code}")
            if res.title:
                print(f"TITLE: {res.title}")
            if res.content:
                clean_preview = " ".join(res.content.split())[:250]
                print(f"TEXT PREVIEW: {clean_preview}")
            print(f"LINKS FOUND: {len(res.links)}")

            return 0 if res.success else 1
    except asyncio.CancelledError:
        print("Interrupted; cleaned up.", file=sys.stderr)
        return 130
    except ControllerError as exc:
        print(f"Controller error: {exc}", file=sys.stderr)
        return 2


def main() -> int:
    ap = argparse.ArgumentParser(description="Tor observation controller CLI")
    ap.add_argument("--url", default="http://shadowboard.lab.onion/")
    ap.add_argument("--proxy", default=DEFAULT_PROXY_URL)
    ap.add_argument("--profile-dir", default="~/.tor_observation/browser_profile")
    ap.add_argument("--no-browser", action="store_true", help="disable Engine B escalation")
    ap.add_argument("--force-browser", action="store_true", help="force Engine B browser escalation for debugging")
    ap.add_argument("--skip-exit-check", action="store_true", help="only check SOCKS5 reachability at start")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    configure_logging(logging.DEBUG if args.verbose else logging.INFO)
    return asyncio.run(_demo(args))


if __name__ == "__main__":
    sys.exit(main())
