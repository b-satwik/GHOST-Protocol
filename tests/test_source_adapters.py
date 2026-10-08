"""
Unit tests for GHOST Protocol Source Adapters and Adapter Registry.
Validates page classification, candidate extraction, and thread parsing across
Discourse, XenForo, Telegram, and ShadowBoard platforms.
"""

import pytest
from src.observer.adapters.adapter_registry import get_adapter_for_url
from src.observer.adapters.discourse_adapter import DiscourseAdapter
from src.observer.adapters.xenforo_adapter import XenForoAdapter
from src.observer.adapters.telegram_adapter import TelegramAdapter
from src.observer.adapters.shadowboard_adapter import ShadowBoardAdapter
from src.discovery.link_extractor import LinkExtractor


def test_discourse_adapter():
    url = "https://0x00sec.org/t/cve-2024-1234-rce-exploit/1234"
    html = """
    <html>
      <head><title>CVE-2024-1234 RCE Exploit - 0x00sec</title></head>
      <body>
        <h1 id="topic-title">
          <a href="/t/cve-2024-1234-rce-exploit/1234">CVE-2024-1234 RCE Exploit</a>
        </h1>
        <div class="topic-body">
          <span class="creator">poster1</span>
          <time datetime="2026-01-01T00:00:00Z"></time>
          <div class="post">Here is an RCE exploit for Linux kernel zero-day vulnerability CVE-2024-1234.</div>
        </div>
        <div class="reply">
          <span class="creator">user2</span>
          <div class="post">Great POC payload!</div>
        </div>
      </body>
    </html>
    """
    adapter = get_adapter_for_url(url, html)
    assert isinstance(adapter, DiscourseAdapter)
    assert adapter.source_type == "DISCOURSE_FORUM"

    page_type = adapter.classify_page_type(url, html, "CVE-2024-1234 RCE Exploit", {})
    assert page_type == "THREAD_PAGE"

    thread_info = adapter.extract_thread_info(url, html)
    assert "CVE-2024-1234" in thread_info["title"]
    assert thread_info["author"] == "poster1"
    assert len(thread_info["content"]) > 0


def test_xenforo_adapter():
    url = "https://www.blackhatworld.com/threads/stolen-database-leak-2026.56789/"
    html = """
    <html>
      <head><title>Stolen Database Leak 2026 | BlackHatWorld</title></head>
      <body>
        <div class="p-body-content">
          <article class="message">
            <span class="username">darkhacker</span>
            <time class="u-dt">2026-02-01</time>
            <div class="bbWrapper">Selling admin credentials and database dump for target network.</div>
          </article>
        </div>
      </body>
    </html>
    """
    adapter = get_adapter_for_url(url, html)
    assert isinstance(adapter, XenForoAdapter)
    assert adapter.source_type == "XENFORO_FORUM"

    page_type = adapter.classify_page_type(url, html, "Stolen Database Leak", {})
    assert page_type == "THREAD_PAGE"

    thread_info = adapter.extract_thread_info(url, html)
    assert thread_info["author"] == "darkhacker"
    assert "admin credentials" in thread_info["content"]


def test_telegram_adapter():
    url = "https://t.me/s/SliceForLifeee"
    html = """
    <html>
      <head><title>SliceForLifeee Telegram Preview</title></head>
      <body>
        <div class="tgme_channel_info_header_title">SliceForLifeee</div>
        <div class="tgme_widget_message" data-post="SliceForLifeee/100">
          <div class="tgme_widget_message_author"><a href="https://t.me/s/SliceForLifeee">SliceForLifeee</a></div>
          <div class="tgme_widget_message_text">New malware sample drop and zero-day payload analysis.</div>
          <time class="time">12:34</time>
        </div>
      </body>
    </html>
    """
    adapter = get_adapter_for_url(url, html)
    assert isinstance(adapter, TelegramAdapter)
    assert adapter.source_type == "TELEGRAM_PUBLIC_CHANNEL"

    candidates = adapter.extract_candidate_links(url, html)
    assert len(candidates) > 0
    assert "https://t.me/s/SliceForLifeee/100" in candidates[0]

    thread_info = adapter.extract_thread_info("https://t.me/s/SliceForLifeee/100", html)
    assert thread_info["author"] == "SliceForLifeee"
    assert "malware sample" in thread_info["content"]


def test_shadowboard_adapter():
    url = "http://shadowboard.lab.onion/post/f4c536497e5bb6a4a8da"
    html = """
    <html>
      <head><title>Dread Lab Post</title></head>
      <body>
        <div class="post-title">Zero-day RCE Exploit Documented</div>
        <div class="post-meta">Posted by <a class="author" href="/u/HugBunter">u/HugBunter</a></div>
        <div class="post-content">Exploit payload for CVE-2024-9999.</div>
      </body>
    </html>
    """
    adapter = get_adapter_for_url(url, html)
    assert isinstance(adapter, ShadowBoardAdapter)
    assert adapter.source_type == "SHADOWBOARD_LAB"

    thread_info = adapter.extract_thread_info(url, html)
    assert thread_info["author"] == "HugBunter"
    assert "CVE-2024-9999" in thread_info["content"]


def test_link_extractor_integration():
    extractor = LinkExtractor()
    discourse_html = """<a href="/t/some-topic-name/4321">Topic Link</a>"""
    links = extractor.extract_post_links(discourse_html, "https://0x00sec.org/")
    assert len(links) == 1
    assert links[0] == "https://0x00sec.org/t/some-topic-name/4321"

    xenforo_html = """<a href="/threads/another-thread.9999/">Thread Link</a>"""
    xen_links = extractor.extract_post_links(xenforo_html, "https://www.blackhatworld.com/forums/?x=-")
    assert len(xen_links) >= 1
    assert any("another-thread.9999" in link for link in xen_links)
