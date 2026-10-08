# GHOST Protocol Controlled Laboratory Source Registry

This document documents the approved sources for the controlled laboratory demonstration (`approved: true`, `collection_allowed: true`).

---

## 1. Controlled Laboratory Approved Sources

The following controlled laboratory services are explicitly approved for observation (`approved: true`, `collection_allowed: true`):

| Source ID | Source Type | Category | Target URL | Max Cap | Policy Rationale |
|---|---|---|---|---|---|
| `CISA_KEV` | `SURFACE_CTI_REFERENCE` | `vulnerability_cti` | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | 5 | Approved surface CTI vulnerability source. |
| `EXPLOIT_DB` | `SURFACE_CTI_REFERENCE` | `vulnerability_exploit` | `https://www.exploit-db.com` | 5 | Approved surface CTI exploit repository. |
| `0X00SEC_FORUM` | `SURFACE_CTI_REFERENCE` | `security_forum` | `https://0x00sec.org` | 5 | Approved surface security discussion forum. |
| `RANSOMWARE_LIVE` | `SURFACE_CTI_REFERENCE` | `ransomware_cti` | `https://www.ransomware.live` | 5 | Approved surface ransomware CTI feed. |
| `VX_UNDERGROUND` | `SURFACE_CTI_REFERENCE` | `malware_cti` | `https://vx-underground.org` | 5 | Approved surface malware CTI library. |
| `SHADOWBOARD_LAB_ONION` | `DARK_WEB_CORPUS` | `security_intelligence` | `http://shadowboard.lab.onion` | 5 | Approved controlled laboratory shadowboard onion service. |
| `DREAD_FORUM_ONION` | `DARK_WEB_CORPUS` | `hacker_forum` | `http://dreadlab.lab.onion` | 5 | Approved controlled laboratory dread discussion forum. |

---

## 2. Reference / Discovery Only Sources (DO NOT CRAWL)

The following sources remain marked `REFERENCE_ONLY` (`approved: false`, `collection_allowed: false`) and MUST NOT be crawled as corpus text:

| Source ID | Source Type | Category | Target URL | Policy Rationale |
|---|---|---|---|---|
| `AHMIA_SEARCH_ENGINE` | `SURFACE_CTI_REFERENCE` | `discovery_search_engine` | `https://ahmia.fi` | Search engine reference/discovery tool only. |
| `DEEPDARK_CTI_REPO` | `SURFACE_CTI_REFERENCE` | `github_curated_repository` | `https://github.com/joxean/deepdarkCTI` | GitHub CTI reference repository. |

---

## 3. Human Approval & Safety Mandate

- **Strict Approval Required**: Only authorized controlled laboratory sources have `approved: true` and `collection_allowed: true`.
- **No Automatic Crawling**: The observer will **NEVER** automatically add or crawl external targets found in links.
- **Safety Boundaries**: No CAPTCHA bypass, no credential submission, no active probing/exploitation.
