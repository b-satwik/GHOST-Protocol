# GHOST PROTOCOL — LIVE OPERATION CYCLE WALKTHROUGH

This document outlines the exact step-by-step operational sequence executed during one continuous observation cycle of **GHOST PROTOCOL**.

---

## 🔄 16-Step Observation Cycle Execution

```
STEP 1: WHONIX / TOR GATEWAY VERIFICATION
   │    Checks Whonix SOCKS5 gateway (socks5h://10.152.152.10:9050).
   │    If unreachable and fail-closed is active: FAIL CLOSED.
   ▼
STEP 2: SOURCE REACHABILITY & DNS CHECK
   │    Executes lightweight pre-flight probe over SOCKS5 proxy.
   ▼
STEP 3: ACCESS REQUIREMENT DETERMINATION
   │    Inspects HTTP status & body for LOGIN_REQUIRED, TWO_STEP_REQUIRED,
   │    or BROWSER_REQUIRED signals.
   ▼
STEP 4: COLLECTOR SELECTION
   │    Selects minimum required collector:
   │    - DIRECT_TOR_HTTP (public sources)
   │    - TOR_BROWSER (session-gated / 2FA)
   │    - TELEGRAM_PREVIEW (public Telegram preview)
   ▼
STEP 5: OBSERVATION EXECUTION
   │    Captures raw HTML, clean text, headers, and HTTP status code.
   ▼
STEP 6: CONTENT HASHING & CHANGE DETECTION
   │    Computes SHA-256 hash & 128-permutation MinHash LSH signature.
   │    Classifies change: UNCHANGED (Heartbeat), CHANGED_UNIQUE,
   │    or CHANGED_NEAR_DUPLICATE.
   ▼
STEP 7: ENTITY & LINK EXTRACTION
   │    Extracts CVEs, malware names, onion URLs, Telegram links, handles,
   │    and IP/domain indicators from clean text.
   ▼
STEP 8: CONTEXTUAL THREAT FILTERING
   │    Applies contextual proximity pattern matching.
   │    Classifies as ROUTINE_CONTENT vs THREAT_RELEVANT_CONTENT.
   ▼
STEP 9: DARKWATCH FROZEN ML PIPELINE
   │    - DistilBERT: Text threat category & confidence (if text exists).
   │    - XGBoost: Flow classification (if network telemetry exists).
   │    - Temporal AE v2: Anomaly score (if temporal session history exists).
   ▼
STEP 10: HM-TIF FUSION & RISK QUANTIFICATION
   │    Fuses available modalities, calculates fusion risk score ($R \in [0, 1]$),
   │    and assigns risk severity (LOW, ELEVATED, HIGH, CRITICAL).
   ▼
STEP 11: CTI, STIX & MITRE ENRICHMENT
   │    Generates STIX 2.1 Bundle JSON & maps MITRE ATT&CK technique IDs.
   ▼
STEP 12: COMPOSITE ENTITY RESOLUTION
   │    Runs composite resolver ($S_{comp} = 0.40 \cdot JW + 0.35 \cdot Cosine + 0.25 \cdot Jaccard$)
   │    to correlate synthetic actors (e.g. ViperSec ↔ Viper_X).
   ▼
STEP 13: HISTORICAL CORRELATION GRAPH UPDATE
   │    Queries observation history store, links timeline events,
   │    and updates REPLACED_BY infrastructure edges.
   ▼
STEP 14: PERSISTENCE & PROVENANCE RECORDING
   │    Writes complete observation record to SQLite database with full provenance.
   ▼
STEP 15: LIVE TELEMETRY EMISSION
   │    Streams event telemetry to GHOST Command Console & Analyst Workstation.
   ▼
STEP 16: WORKSTATION / ANALYST NOTIFICATION
        Updates live status counters, graphs, and alert logs.
```
