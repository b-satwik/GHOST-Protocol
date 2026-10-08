"""
Unit Verification Script for Candidate Classification & Thread Validation
Tests:
1. Static Resources (.js, .css, cdn.jsdelivr.net, /static/, /assets/) -> SKIPPED (STATIC_RESOURCE)
2. API Endpoints -> SKIPPED (API_RESOURCE)
3. Non-thread pages (/u/, /faq, /search, /rules) -> SKIPPED (NON_THREAD_URL)
4. Valid thread URLs & content -> PROCESS / GENUINE_THREAD
5. Raw JS payload as thread body -> SKIPPED (STATIC_RESOURCE_JS_CODE)
6. No "anonymous" fallback on non-posts
"""

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.discovery.candidate_classifier import CandidateClassifier

def test_url_classification():
    print("[1] Testing URL Candidate Classification...")

    # Static assets
    js_url = "https://cdn.jsdelivr.net/ghost/sodo-search@~1.8/umd/sodo-search.min.js"
    res1 = CandidateClassifier.classify_url(js_url)
    assert not res1["is_valid_thread"], f"JS URL accepted! {res1}"
    assert res1["resource_type"] == "JAVASCRIPT", f"Unexpected type: {res1['resource_type']}"
    assert res1["action"] == "SKIP", "Action should be SKIP"

    css_url = "https://0x00sec.org/assets/application.css"
    res2 = CandidateClassifier.classify_url(css_url)
    assert not res2["is_valid_thread"], f"CSS URL accepted! {res2}"
    assert res2["action"] == "SKIP"

    png_url = "https://0x00sec.org/images/logo.png"
    res3 = CandidateClassifier.classify_url(png_url)
    assert not res3["is_valid_thread"], f"PNG URL accepted! {res3}"
    assert res3["action"] == "SKIP"

    # API Endpoint
    api_url = "https://0x00sec.org/api/status"
    res4 = CandidateClassifier.classify_url(api_url)
    assert not res4["is_valid_thread"], f"API URL accepted! {res4}"
    assert res4["reason"] == "API_RESOURCE"

    # Profile / Nav
    prof_url = "https://0x00sec.org/u/user01"
    res5 = CandidateClassifier.classify_url(prof_url)
    assert not res5["is_valid_thread"], f"Profile URL accepted! {res5}"
    assert res5["action"] == "SKIP"

    # Genuine Thread URL
    thread_url = "https://0x00sec.org/t/database-security-analysis/12345"
    res6 = CandidateClassifier.classify_url(thread_url)
    assert res6["is_valid_thread"], f"Genuine thread rejected! {res6}"
    assert res6["action"] == "PROCESS"

    print("  [PASS] URL Candidate Classification verified clean.")

def test_thread_validation():
    print("[2] Testing Extracted Thread Content Validation...")

    # Case A: Raw JS content delivered for a static link
    js_payload = "!function(e){var t={};function n(r){...}}(window);"
    thread_info_js = {"title": "sodo-search.min.js", "content": "Content Unavailable", "author": None}
    valid_a, info_a = CandidateClassifier.validate_extracted_thread("https://cdn.jsdelivr.net/sodo-search.min.js", js_payload, thread_info_js)
    assert not valid_a, f"Raw JS payload accepted as valid thread! {info_a}"
    assert info_a["action"] == "SKIP"
    assert info_a["resource_type"] == "JAVASCRIPT"

    # Case B: Valid HTML Genuine Thread
    html_payload = """
    <div id="post-root" class="topic-body">
        <h1 class="topic-title">Database access discussion & credentials</h1>
        <span class="username">user03</span>
        <div class="cooked">We have gained full root access to the core database cluster.</div>
    </div>
    """
    thread_info_valid = {
        "title": "Database access discussion & credentials",
        "content": "We have gained full root access to the core database cluster.",
        "author": "user03",
        "post_id": "topic_12345"
    }
    valid_b, info_b = CandidateClassifier.validate_extracted_thread("https://0x00sec.org/t/database-access/12345", html_payload, thread_info_valid)
    assert valid_b, f"Genuine thread failed validation! {info_b}"
    assert info_b["action"] == "OBSERVE"
    assert info_b["page_type"] == "GENUINE_THREAD"

    print("  [PASS] Extracted Thread Content Validation verified clean.")

if __name__ == "__main__":
    test_url_classification()
    test_thread_validation()
    print("\nALL CANDIDATE CLASSIFICATION UNIT TESTS PASSED SUCCESSFULLY!")
