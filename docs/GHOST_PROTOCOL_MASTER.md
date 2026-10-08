# GHOST PROTOCOL — MASTER ARCHITECTURE & TECHNICAL SPECIFICATION

**Canonical Reference Document for Autonomous Cyber Threat Intelligence & DarkWatch AI System**  
**Version**: 2.4-STABLE  
**Classification**: Controlled Cyber Threat Intelligence Laboratory & Autonomous AI Agent  

---

## 1. Executive Summary & Core System Philosophy

**GHOST PROTOCOL** (Global Threat Observation & System Tracking Protocol) is an autonomous cyber threat intelligence workstation designed to continuously observe, sanitize, evaluate, correlate, and document dark web sources, onion portals, leak sites, and threat forums.

### Critical System Directives:
1. **ONE Official Dashboard**: The Stage 1 Analyst Operations Workstation (`src/stage1_dashboard.py` & `src/templates/stage1_dashboard.html`, launched via `python run_stage1_dashboard.py`) is the single canonical dashboard. There are no secondary or competing dashboards.
2. **Frozen DistilBERT Intelligence Model**: The HackerSignal DistilBERT model (`models/distilbert_hackersignal/final_model`) is **FROZEN**. It is the authoritative text exploit-classification model. It is never retrained, modified, replaced, or wrapped in fake classifiers.
3. **Controlled Docker Laboratory Isolation**: The local Docker lab (`127.0.0.1:8080`) is strictly an authorized synthetic testing laboratory. It is never confused with real-world passive Whonix/Tor observations.
4. **Threat Filter Gate**: Every observation passes through a first-stage `ThreatFilter` gate. Ordinary/routine posts bypass expensive exploit classification to prevent false alarmism, while threat-relevant text is evaluated by DistilBERT.
5. **Dynamic Multi-Modality (HM-TIF)**: Unavailable modalities (Network, Temporal) are handled through dynamic weight renormalization rather than fabricating fake telemetry.
6. **Tool-Executing GHOST AI Agent**: The GHOST AI console is an operational orchestration dispatcher (`GhostToolDispatcher`) that executes repository tools based on natural language commands.

---

## 2. End-to-End Master Architecture

```
                    ┌─────────────────────────────────────────┐
                    │          SOURCE DISCOVERY QUEUE         │
                    │   (Ahmia Search / deepdarkCTI Seeds)    │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │             SOURCE REGISTRY             │
                    │      (Canonical URL Deduplication)      │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │      TRANSPORT / OBSERVATION LAYER      │
                    │ ┌───────────────────┐ ┌───────────────┐ │
                    │ │ REAL-WORLD (Tor)  │ │  DOCKER LAB   │ │
                    │ │  SOCKS5 Isolation │ │ (127.0.0.1)   │ │
                    │ └───────────────────┘ └───────────────┘ │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │        TEXT SANITIZATION ENGINE         │
                    │   (HTML Strip / SHA-256 Hash Compute)   │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │            THREAT FILTER GATE           │
                    └───────────┬─────────────────┬───────────┘
                                │                 │
            ROUTINE / NORMAL    │                 │  THREAT-RELEVANT
            (Non-Security Post) │                 │  (Exploit Keywords)
                                ▼                 ▼
                     ┌────────────────────┐  ┌─────────────────────────────────┐
                     │ ROUTINE_CONTENT    │  │ FROZEN DISTILBERT MODEL         │
                     │ (Normal Discussion)│  │ (8 Exploit Classes / 66.9M)     │
                     └────────────────────┘  └────────────────┬────────────────┘
                                                              │
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │ XGBOOST NETWORK ENGINE (Opt)    │
                                             │ (45 Telemetry Features)         │
                                             └────────────────┬────────────────┘
                                                              │
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │ TEMPORAL AUTOENCODER (Opt)      │
                                             │ (14 Time-Series Features)       │
                                             └────────────────┬────────────────┘
                                                              │
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │ HM-TIF MULTI-MODAL FUSION      │
                                             │ (Dynamic Weight Renormalization)│
                                             └────────────────┬────────────────┘
                                                              │
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │ CTI / STIX 2.1 / MITRE MAPPING │
                                             └────────────────┬────────────────┘
                                                              │
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │ HISTORICAL CORRELATION ENGINE   │
                                             └────────────────┬────────────────┘
                                                              │
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │ TWO-TIER XAI EXPLANATION BRAIN  │
                                             └────────────────┬────────────────┘
                                                              │
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │ EVIDENCE PERSISTENCE STORE      │
                                             └────────────────┬────────────────┘
                                                              │
                                                              ▼
                                             ┌─────────────────────────────────┐
                                             │ ONE OFFICIAL ANALYST DASHBOARD  │
                                             │ (Stage 1 SOC Workstation)       │
                                             └────────────────┬────────────────┘
                                                              ▲
                                                              │ (Tool Dispatch)
                                             ┌────────────────┴────────────────┐
                                             │ GHOST AI COMMAND CONSOLE        │
                                             └─────────────────────────────────┘
```

---

## 3. Frozen HackerSignal DistilBERT AI Core

The text intelligence component of GHOST relies on the pre-trained, validated **HackerSignal DistilBERT model**.

### Technical Specifications:
- **Model Storage Path**: `models/distilbert_hackersignal/final_model`
- **Architecture**: `DistilBertForSequenceClassification`
- **Total Parameters**: 66,961,160 parameters
- **Maximum Sequence Length**: 512 tokens
- **Vocabulary / Tokenizer**: `distilbert-base-uncased` (stored with model weights)
- **Model Status**: **FROZEN** (Must not be retrained, altered, or replaced)

### Supported Exploit Classes (8 Categories):
1. `auth_access`: Authentication bypass, broken access control, default credentials, session takeover.
2. `dos`: Denial of Service, resource exhaustion, crash loop, memory leak DoS.
3. `file_inclusion`: Local File Inclusion (LFI), Remote File Inclusion (RFI), directory traversal (`../../etc/passwd`).
4. `info_disclosure`: Sensitive data exposure, unencrypted database backups, exposed credentials, API key leaks.
5. `injection`: SQL injection, Command injection, LDAP/XML injection, parameter pollution.
6. `memory_corruption`: Heap/stack buffer overflow, use-after-free, pointer dereference, memory corruption exploits.
7. `rce`: Remote Code Execution, arbitrary code execution, webshell upload, command execution zero-days.
8. `xss`: Cross-Site Scripting (Reflected, Stored, DOM-based), script injection.

---

## 4. Real Model Inference Diagnostic & Validation Matrix

The frozen model's performance has been verified against synthetic cyber-security descriptions in `tests/test_distilbert_real_inference.py` and `tests/test_distilbert_validation_matrix.py`.

### Real Inference Benchmark Results:
| Exploit Category | Sample Text Input | Predicted Class | Confidence | Top-3 Predictions |
| :--- | :--- | :--- | :--- | :--- |
| **RCE** | Zero-day RCE payload targeting web application server... | `rce` | **99.69%** | `rce: 0.997`, `injection: 0.001`, `memory_corruption: 0.000` |
| **XSS** | Reflected XSS flaw in query parameter allows arbitrary JS... | `xss` | **99.88%** | `xss: 0.999`, `injection: 0.001`, `rce: 0.000` |
| **INJECTION** | SQL injection in search parameter allows dumping DB... | `injection` | **99.78%** | `injection: 0.998`, `auth_access: 0.001`, `rce: 0.001` |
| **AUTH_ACCESS** | Default credentials and broken access control interface... | `auth_access` | **99.56%** | `auth_access: 0.996`, `injection: 0.002`, `info_disclosure: 0.001` |
| **FILE_INCLUSION** | LFI vulnerability via directory traversal parameter... | `file_inclusion` | **98.62%** | `file_inclusion: 0.986`, `info_disclosure: 0.008`, `injection: 0.002` |
| **INFO_DISCLOSURE** | Exposed backup directory containing unencrypted database dump... | `info_disclosure` | **99.24%** | `info_disclosure: 0.992`, `auth_access: 0.003`, `injection: 0.002` |
| **DOS** | Recursive parsing loop and high memory usage cause crash... | `dos` | **89.79%** | `dos: 0.898`, `memory_corruption: 0.067`, `injection: 0.014` |
| **MEMORY_CORRUPTION** | Heap buffer overflow in binary parser allows register overwrite... | `memory_corruption` | **79.64%** | `memory_corruption: 0.796`, `dos: 0.179`, `injection: 0.010` |

### Validation Matrix Test Suite (9/9 Scenarios Passed):
`test_distilbert_validation_matrix.py` validates controlled ground truth against real DistilBERT predictions:
- `LAB_SCENARIO_01_NORMAL` $\rightarrow$ Expected: `NORMAL` $\mid$ Actual: `NORMAL` (1.0000) **PASS**
- `LAB_SCENARIO_02_RCE` $\rightarrow$ Expected: `rce` $\mid$ Actual: `rce` (0.9979) **PASS**
- `LAB_SCENARIO_03_XSS` $\rightarrow$ Expected: `xss` $\mid$ Actual: `xss` (0.9988) **PASS**
- `LAB_SCENARIO_04_INJECTION` $\rightarrow$ Expected: `injection` $\mid$ Actual: `injection` (0.9978) **PASS**
- `LAB_SCENARIO_05_AUTH_ACCESS` $\rightarrow$ Expected: `auth_access` $\mid$ Actual: `auth_access` (0.9956) **PASS**
- `LAB_SCENARIO_06_FILE_INCLUSION` $\rightarrow$ Expected: `file_inclusion` $\mid$ Actual: `file_inclusion` (0.9862) **PASS**
- `LAB_SCENARIO_07_INFO_DISCLOSURE` $\rightarrow$ Expected: `info_disclosure` $\mid$ Actual: `info_disclosure` (0.9924) **PASS**
- `LAB_SCENARIO_08_DOS` $\rightarrow$ Expected: `dos` $\mid$ Actual: `dos` (0.8979) **PASS**
- `LAB_SCENARIO_09_MEMORY_CORRUPTION` $\rightarrow$ Expected: `memory_corruption` $\mid$ Actual: `memory_corruption` (0.7964) **PASS**

---

## 5. Controlled Docker Cyber Laboratory

The Docker Laboratory (`darkwatch_labs/services/app.py`) is an authorized synthetic environment running locally on `127.0.0.1:8080`.

### Service Endpoints & Synthetic Behaviors:
1. `http://127.0.0.1:8080/forum` — RCE & Command Injection exploit descriptions.
2. `http://127.0.0.1:8080/market` — Authentication & stolen access credential listings.
3. `http://127.0.0.1:8080/paste` — XSS payload samples and stealer logs.
4. `http://127.0.0.1:8080/leak` — Information disclosure and database breach dumps.
5. `http://127.0.0.1:8080/security` — DoS vectors and security advisories.
6. `http://127.0.0.1:8080/general` — **ROUTINE NORMAL DISCUSSION** (non-threat text).
7. `http://127.0.0.1:8080/dynamic_forum` — Changing content & near-duplicate testing.
8. `http://127.0.0.1:8080/session_gated` — Session-gated 2-step human authorization flow.
9. `http://127.0.0.1:8080/mirror` — Infrastructure migration mirror tracking.

---

## 6. Threat Filter Gate Architecture

To prevent every ordinary web post from triggering expensive machine learning classification, the pipeline includes a pre-inference `ThreatFilter` (`src/pipeline/threat_filter.py`).

### Routing Logic:
1. **Raw Text Input** $\rightarrow$ Cleaned & Sanitized by `TextSanitizer`.
2. **Threat Keyword & Pattern Matching**: Scans for security keywords (e.g. `exploit`, `vulnerability`, `cve`, `bypass`, `payload`, `injection`, `overflow`).
3. **Decision Branching**:
   - **`ROUTINE_CONTENT`**: Text contains normal non-security discussion (e.g. `/general` forum posts). Bypasses DistilBERT and returns `NORMAL` risk.
   - **`THREAT_RELEVANT`**: Text contains exploit or vulnerability discussion. Passed to DistilBERT for 8-class exploit classification.

---

## 7. Multi-Modality HM-TIF Dynamic Weight Renormalization

The **Hierarchical Multi-Modal Threat Intelligence Fusion (HM-TIF)** engine (`src/pipeline/inference_engine.py`) evaluates available telemetry without fabricating missing inputs.

### Renormalization Cases:
- **`TEXT ONLY`**: Weight = `1.00` (Text Score only).
- **`TEXT + NETWORK`**: Weights = `Text: 0.60 | Network: 0.40`.
- **`TEXT + TEMPORAL`**: Weights = `Text: 0.70 | Temporal: 0.30`.
- **`TEXT + NETWORK + TEMPORAL`**: Weights = `Text: 0.45 | Network: 0.35 | Temporal: 0.20`.

---

## 8. GHOST AI Agent & Natural Language Tool Dispatcher

The GHOST AI Command Console is driven by `GhostToolDispatcher` (`src/agent/ghost_tool_dispatcher.py`). It translates natural language text into project function calls.

### Implemented Tool Bindings:
| Natural Language Command | Executed Repository Function | Returned Result |
| :--- | :--- | :--- |
| `"capture this"` | `capture_current_source()` | Navigates & captures active target URL. |
| `"deep analyze this"` | `deep_analyze(observation_id)` | Returns 16-point pipeline trace. |
| `"what did we find?"` | `get_observation()` + `get_model_explanation()` | Summarizes latest observation & XAI. |
| `"show me previous observations"` | `search_history()` | Queries `ObservationHistoryStore`. |
| `"where did this appear before?"` | `find_entity()` + `get_entity_timeline()` | Runs `HistoricalCorrelator`. |
| `"explain model decision"` | `get_model_explanation()` | Returns two-tier XAI feature attribution. |

---

## 9. Deep Analysis View (`[ VIEW DEEP ANALYSIS ]`)

When clicked, GHOST executes a complete 16-step trace over the stored observation record:
1. **Original Observation**: ID, Canonical URL, Timestamp, Hash.
2. **Sanitized Text**: Plain text stripped of HTML tags.
3. **Threat-Filter Decision**: `ROUTINE_CONTENT` vs `THREAT_RELEVANT`.
4. **DistilBERT Prediction**: Top predicted class label.
5. **DistilBERT Confidence**: Probability score (`0.0 - 1.0`).
6. **Top Predictions**: Class probability breakdown.
7. **Token Evidence**: Highlighted n-gram tokens.
8. **Network Analysis**: XGBoost 45-feature output (if present).
9. **Temporal Analysis**: Temporal Autoencoder 14-feature MSE (if present).
10. **HM-TIF Fusion**: Multi-modal fusion score and risk severity.
11. **Risk Score & Severity**: `LOW`, `ELEVATED`, `HIGH`, `CRITICAL`.
12. **CTI Entities**: Extracted CVEs, malware handles, onion mirrors.
13. **STIX 2.1 Objects**: Generated STIX bundle ID & object JSON.
14. **MITRE Mapping**: Mapped ATT&CK technique codes (e.g. `T1190`, `T1486`).
15. **Historical Matches**: First seen / last seen entity correlations.
16. **XAI Explanation**: Natural language narrative explanation.

---

## 10. Real-World vs Docker Laboratory Distinction

| Dimension | Real-World Observation | Docker Cyber Laboratory |
| :--- | :--- | :--- |
| **Network Transport** | Passive SOCKS5 via Whonix Gateway (`127.0.0.1:9050`) | Direct Local Loopback (`127.0.0.1:8080`) |
| **Target URLs** | Approved `.onion` services & Tor cleartext mirrors | Synthetic test endpoints (`/forum`, `/market`, etc.) |
| **Data Character** | Real live dark web threat observations | Harmless controlled synthetic test content |
| **Dashboard Badge** | `🌐 REAL-WORLD OBSERVATION (Whonix / Tor)` | `⚠️ DOCKER LAB TEST (127.0.0.1 / SYNTHETIC)` |

---

## 11. ONE Official Dashboard Location & Operations

### Single Canonical Entry Point:
```bash
python run_stage1_dashboard.py
```
- **Port**: `http://127.0.0.1:5000`
- **Backend File**: `src/stage1_dashboard.py`
- **Frontend Template**: `src/templates/stage1_dashboard.html`
- **Layout**: 3-part layout (240px sidebar, flex center workspace, 320px right HUD).
- **Animation Directive**: Zero animation policy (`transition: none !important; animation: none !important;`).

---

## 12. Complete Automated Test Suite Verification

Run the verified test suite:
```bash
python -m unittest tests/test_distilbert_real_inference.py tests/test_distilbert_validation_matrix.py tests/test_missing_modalities.py tests/test_onion_link_observation.py tests/test_stage1_dashboard.py
```
- **Test Results**: **18/18 PASSED** (0 failures, 0 errors in `8.8s`).
- **.Onion Observation Coverage**: `tests/test_onion_link_observation.py` verifies `.onion` v2 & v3 link extraction, `TOR_BROWSER` collector assignment, `ThreatFilter` gating, frozen DistilBERT inference (`rce` prediction with `99.7%` confidence), STIX 2.1 bundle generation, and `GhostToolDispatcher` execution.
