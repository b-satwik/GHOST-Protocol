# DarkWatch Real Text Corpus Expansion — Bazzell OSINT Collection Registry

## Executive Summary

This document evaluates candidate intelligence sources extracted from Michael Bazzell's *OSINT Techniques: Resources for Uncovering Online Information* (10th Edition, 2023) for expanding the **DarkWatch Real Text Corpus Collection Pipeline**.

The primary objective is to acquire high-quality, publicly accessible cyber-threat-related text (forum discussions, exploit descriptions, vulnerability analysis, ransomware announcements, malware research, threat reports, public pastes, FOIA disclosures) to build a robust NLP training dataset targeting 1,000+ clean unique documents and 200+ human-verified records.

---

## Data Role Separation Principles

To prevent contamination of the NLP text training corpus, sources are strictly partitioned into four distinct roles:

1. **CORPUS TEXT (`SURFACE_CORPUS` / `DARK_WEB_CORPUS`)**: Actual text content used to build NLP training examples and candidate GoldRecords.
2. **CTI REFERENCE (`CTI_REFERENCE` / `SURFACE_CTI_REFERENCE`)**: Infrastructure, domain, hash, and reputation lookup services used exclusively for enrichment and indicator correlation.
3. **DISCOVERY ONLY (`DISCOVERY_ONLY`)**: Search engines and link directories used to discover onion services and target pages; NOT crawled as raw corpus text.
4. **ARCHIVE REFERENCE (`ARCHIVE_REFERENCE`)**: Bulk historical repositories and snapshot tools used for background reference.

---

## Policy & Safety Invariants

- **Passive Public Collection Only:** Standard HTTP GET requests only.
- **Strict Content Limits:** Hard limit of 2 MB per response body. Per-source cap of **10 pages** across enabled corpus sources.
- **No Access Control Bypass:** NO CAPTCHA solving, NO login/authentication automation, NO paywall bypass, NO anti-bot circumvention.
- **Strict Data Exclusions:** NO stealer log file downloads, NO raw credential dumps/passwords, NO private victim data files, NO PII dumps.
- **Ransomware Policy:** Public threat actor announcements, public claims, and technical indicators ONLY; strictly NO victim database downloads.

---

## Source Inventory & Categorization Table

| Source ID | Source Name | Role | Corpus/CTI/Discovery | Approval Status | Max Pages Cap | Notes & Discovered From |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| `CISA_KEV` | CISA KEV Catalog | `SURFACE_CTI_REFERENCE` | Corpus / CTI | **APPROVED** | 10 | Core approved vulnerability catalog |
| `EXPLOIT_DB` | Exploit-DB | `SURFACE_CTI_REFERENCE` | Corpus / CTI | **APPROVED** | 10 | Core approved exploit archive |
| `0X00SEC_FORUM` | 0x00sec Forum | `SURFACE_CTI_REFERENCE` | Corpus / CTI | **APPROVED** | 10 | Core approved security forum |
| `RANSOMWARE_LIVE` | Ransomware.live | `SURFACE_CTI_REFERENCE` | Corpus / CTI | **APPROVED** | 10 | Core approved ransomware CTI feed |
| `VX_UNDERGROUND` | vx-underground | `SURFACE_CTI_REFERENCE` | Corpus / CTI | **APPROVED** | 10 | Core approved malware library |
| `PROPUBLICA_ONION` | ProPublica Onion | `DARK_WEB_CORPUS` | Corpus | **APPROVED** | 10 | Core approved dark web news & CTI |
| `DREAD_FORUM_ONION` | Dread Forum | `DARK_WEB_CORPUS` | Corpus | **APPROVED** | 10 | Core approved dark web hacker forum |
| `REDDIT_CYBERSECURITY` | Reddit Netsec | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 7 — Public netsec discussions |
| `FOURCHAN_TECH` | 4chan /g/ Tech | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 7 — Public tech & security board |
| `FOURPLEBS_ARCHIVE` | 4plebs Archive | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 7 — Searchable threat text archive |
| `HACKER_NEWS` | Hacker News | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 7 — Tech & vulnerability threads |
| `PASTEBIN_PUBLIC` | Pastebin Public | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 11 — Public security pastes |
| `PSBDMP_PASTE_DUMP` | PSBDMP Paste Dump | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 11 — Indexed security pastes |
| `OCCRP_ALEPH` | OCCRP Aleph | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 15 — Investigative report text |
| `CRYPTOME_ARCHIVE` | Cryptome Archive | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 15 — Security & intel archives |
| `MUCKROCK_PUBLIC_RECORDS` | MuckRock FOIA | `SURFACE_CORPUS` | Corpus | **APPROVED** | 10 | Bazzell Ch. 15 — FOIA security disclosures |
| `VIRUSTOTAL_REF` | VirusTotal API | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 13 — Malware reputation API |
| `HUDSON_ROCK_CAVALIER` | Hudson Rock Cavalier | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 12 — Infostealer exposure API |
| `HACK_NOTICE_REF` | Hack Notice | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 12 — Breach notification tracker |
| `DEHASHED_LOOKUP_REF` | DeHashed Lookup | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 12 — Metadata query; NO cred dumps |
| `HIBP_API_REF` | Have I Been Pwned | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 12 — Breach statistics API |
| `BREACH_DIRECTORY_REF` | Breach Directory | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 12 — Metadata lookup engine |
| `GRAY_HAT_WARFARE_REF` | Gray Hat Warfare | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 6 — S3 bucket search; NO file downloads |
| `THREAT_CROWD_REF` | Threat Crowd | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 13 — Open CTI graph engine |
| `UNFURL_URL_ANALYZER_REF` | UNFURL Analyzer | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 2 — URL parameter analysis |
| `OSINT_SH_TOOLKIT_REF` | OSINT.sh Toolkit | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 6 — Domain WHOIS & DNS intel |
| `BLACKLIGHT_PRIVACY_INSPECTOR_REF` | Blacklight Inspector | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 2 — Website tracker inspector |
| `CENSYS_SCANNER_REF` | Censys Scanner | `CTI_REFERENCE` | CTI Reference | **REFERENCE_ONLY** | 0 | Bazzell Ch. 6 — Infrastructure scanner |
| `AHMIA_SEARCH_ENGINE` | Ahmia Search | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | Bazzell Ch. 14 — Onion search engine |
| `TOR_LINK_INDEX` | Tor Link Index | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | Bazzell Ch. 14 — Onion link directory |
| `ONIONLAND_SEARCH` | Onionland Search | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | Bazzell Ch. 14 — Surface onion search |
| `TOR2WEB_PROXY` | Tor2Web Proxy | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | Bazzell Ch. 14 — Tor gateway proxy |
| `GOOGLE_SEARCH_ENGINE` | Google Search | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | Bazzell Ch. 1 — Surface search engine |
| `BING_SEARCH_ENGINE` | Bing Search | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | Bazzell Ch. 1 — Surface search engine |
| `YANDEX_SEARCH_ENGINE` | Yandex Search | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | Bazzell Ch. 1 — Surface search engine |
| `MILLION_SHORT_ENGINE` | Million Short | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | Bazzell Ch. 1 — Alternative search engine |
| `DEEPDARK_CTI_REPO` | deepdarkCTI Repo | `DISCOVERY_ONLY` | Discovery | **REFERENCE_ONLY** | 0 | GitHub CTI reference repository |
| `PUSHSHIFT_ARCHIVE` | Pushshift Reddit | `ARCHIVE_REFERENCE` | Archive | **REFERENCE_ONLY** | 0 | Bazzell Ch. 7 — Historical Reddit archive |
| `ANNAS_ARCHIVE_REF` | Anna's Archive | `ARCHIVE_REFERENCE` | Archive | **REFERENCE_ONLY** | 0 | Bazzell Ch. 15 — Literature search engine |
| `WAYBACK_MACHINE_REF` | Wayback Machine | `ARCHIVE_REFERENCE` | Archive | **REFERENCE_ONLY** | 0 | Bazzell Ch. 2 — Historical web snapshot |
| `MEMORY_LOL_REF` | Memory.lol | `ARCHIVE_REFERENCE` | Archive | **REFERENCE_ONLY** | 0 | Bazzell Ch. 2 — Social handle history |
| `TORCH_SEARCH_ONION` | Torch Search | `DARK_WEB_CORPUS` | Discovery / Corpus | **PENDING_REVIEW** | 10 | Bazzell Ch. 14 — Volatile onion search |
| `HAYSTAK_SEARCH_ONION` | Haystak Search | `DARK_WEB_CORPUS` | Discovery / Corpus | **PENDING_REVIEW** | 10 | Bazzell Ch. 14 — Volatile onion search |
| `TOR66_DIRECTORY_ONION` | Tor66 Directory | `DARK_WEB_CORPUS` | Discovery / Corpus | **PENDING_REVIEW** | 10 | Bazzell Ch. 14 — Volatile onion directory |
| `EVEREST_LEAK_SITE_ONION` | Everest Leak Site | `DARK_WEB_CORPUS` | Corpus | **PENDING_REVIEW** | 10 | Bazzell Ch. 14 — Public notices ONLY |
| `RANSOMWARE_GROUP_PORTALS_ONION` | Ransomware Blogs | `DARK_WEB_CORPUS` | Corpus | **PENDING_REVIEW** | 10 | Bazzell Ch. 14 — Extortion claims ONLY |
| `TELEGRAM_LEAK_CHANNELS_REF` | Telegram Channels | `DARK_WEB_CORPUS` | Corpus / CTI | **PENDING_REVIEW** | 10 | Bazzell Ch. 7 & 12 — Post text ONLY |

---

## Role Summary Breakdown

- **Total Enabled Corpus Sources:** **16** (7 Core Approved + 9 Bazzell Surface Corpus)
- **Total CTI / Enrichment Reference Sources:** **12**
- **Total Discovery-Only Sources:** **9** (including deepdarkCTI)
- **Total Archive Reference Sources:** **4**
- **Total Pending Review Sources:** **10** (including 6 Bazzell onion/Telegram targets + 4 placeholder entries)
- **Total Registered Sources:** **51**
