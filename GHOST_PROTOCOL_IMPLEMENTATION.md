# GHOST PROTOCOL — AUTONOMOUS LIVE INTELLIGENCE SYSTEM ARCHITECTURE & IMPLEMENTATION GUIDE

## 1. Architectural Overview & Core Principles

**GHOST PROTOCOL** is an autonomous cyber-threat observation, search, correlation, historical-memory, and explanation system built around the **frozen DarkWatch ML pipeline**.

### Core Intelligence Loop

```
DISCOVER → REGISTER → VALIDATE → OBSERVE CONTINUOUSLY → CAPTURE LIVE CHANGES →
SANITIZE + DEDUPLICATE → THREAT CONTEXT FILTER → DARKWATCH FROZEN ML → HM-TIF FUSION →
CTI / STIX / MITRE → ENTITY RESOLUTION → HISTORICAL CORRELATION → XAI → PERSIST → GHOST COMMAND CONSOLE
```

### Safety & Network Boundary
1. **Real-World Passive Observation**:
   - Strictly passive, read-only public information gathering.
   - All real-world network traffic routes over the **Whonix SOCKS5 gateway** (`socks5h://10.152.152.10:9050`).
   - **Fail-Closed Isolation**: If the Whonix gateway is configured but unreachable, execution immediately aborts (`WhonixIsolationError`). No clearnet fallback, no host network bypass.
   - Zero active exploitation, zero vulnerability scanning, zero credential guessing, zero CAPTCHA bypass, zero unauthorized logins.

2. **Controlled Docker Laboratory**:
   - `127.0.0.1` isolated lab environment configured via Docker Compose (`darkwatch-tor-router`, `darkwatch-services`).
   - Serves persistent, real generated 56-character Tor v3 `.onion` addresses for synthetic testing and missing-modality evaluation.

---

## 2. Frozen ML Brain Integration

The system consumes predictions and features from the existing frozen ML models without retraining:
- **HackerSignal DistilBERT**: Text threat classification across 8 classes (`auth_access`, `dos`, `file_inclusion`, `info_disclosure`, `injection`, `memory_corruption`, `rce`, `xss`).
- **XGBoost**: Network flow telemetry classifier (evaluated only when network telemetry exists).
- **Temporal Autoencoder v2**: Session/action temporal anomaly detector (evaluated only when temporal telemetry exists).
- **HM-TIF**: Hierarchical Multi-Modality Threat Information Fusion combining available modalities with explicit availability tracking:
  - `TEXT: AVAILABLE / UNAVAILABLE`
  - `NETWORK: AVAILABLE / UNAVAILABLE`
  - `TEMPORAL: AVAILABLE / UNAVAILABLE`
  - `FUSION: AVAILABLE / PARTIAL / UNAVAILABLE`

---

## 3. Local Command Interpreter & Cyber Dictionary

Human natural language commands are interpreted using a lightweight local parser and cyber dictionary (`src/config/ghost_dictionary.json`), avoiding heavy external LLM dependencies.

### Command Aliases & Intent Mapping
- `/help`: Lists available console commands.
- `/status`: Displays system, source, observation, and alert counts.
- `/sources`: Lists active registered sources and validation states.
- `/add-source <url>`: Registers target URL into `source_registry.db` (`real_world` or `docker_lab`).
- `/sherlock <username>`: Performs OSINT handle discovery across synthetic lab services.
- `/observe <url>`: Triggers observation over specified source URL.
- `/capture`: Captures current targeted source.
- `/search <query>`: Searches discovery queue, Ahmia, or observation history.
- `/history <entity>`: Queries historical entity records.
- `/timeline <entity>`: Generates longitudinal entity activity timeline.
- `/correlate <entity>`: Executes entity correlation.
- `/deep-analyze`: Runs deep ML, CTI, STIX, MITRE, and XAI pipeline over observation.
- `/explain`: Returns model decision explanation.

---

## 4. Persistent Source Lifecycle & Discovery Engine

### Source Lifecycle States
Every target source maintains a persistent record in SQLite (`data/source_registry.db`):
- `DISCOVERED`: Discovered URL placed in validation queue.
- `PENDING_VALIDATION`: Awaiting initial network/safety check.
- `ONLINE`: Accessible over Tor/HTTP.
- `OFFLINE`: Unreachable source (retained in history; never deleted).
- `REAPPEARED`: Previously offline source returning online.
- `CONTENT_CHANGED`: Observed content SHA-256 differs from prior pass.
- `UNCHANGED`: Content SHA-256 matches prior pass.
- `LOGIN_REQUIRED`: Requires login credentials.
- `TWO_STEP_REQUIRED`: Requires 2-step verification.
- `BROWSER_REQUIRED`: Requires JavaScript browser environment.
- `BLOCKED`: Access blocked by anti-bot/CAPTCHA.
- `RETIRED`: Explicitly deactivated source.

### Discovery Engines
1. **Ahmia**: Discovery/search layer for `.onion` URLs (`src/discovery/ahmia_discovery.py`). Discovered URLs enter `PENDING_VALIDATION` queue.
2. **deepdarkCTI**: Seed threat intelligence repository.
3. **Daunt.link**: Discovery and resolution source (kept strictly **separate** from Dread observation target).
4. **Recursive Link Discovery**: Scans observed public pages for outbound `.onion` and `t.me` links (`src/discovery/link_extractor.py`).

---

## 5. Real-World Target Workflows

### Dread Flow (Session-Gated Target)
1. Discovered/resolved via Daunt.link.
2. Initial Tor CLI HTTP check returns `HTTP 401` / `TWO_STEP_REQUIRED`.
3. GHOST launches real Tor Browser process with JS disabled.
4. Console emits prompt: `USER ACTION REQUIRED: Complete the authorized 2-step verification.`
5. User manually completes verification; GHOST resumes continuous observation over the authenticated session.

### Telegram Public Preview Flow
1. Target URL: `https://t.me/s/SliceForLifeee`.
2. Uses public HTML preview (`t.me/s/`) without requiring login, API keys, or Telegram client accounts.
3. Extracts incremental post IDs, message text, timestamps, handles, and outbound links (`src/observer/telegram_public_observer.py`).

---

## 6. Entity Memory, Resolver & Infrastructure Tracking

### Entity Memory Types
Tracks `ACTOR`, `USERNAME`, `ALIAS`, `ORGANIZATION`, `TARGET`, `DOMAIN`, `ONION`, `URL`, `IP`, `HASH`, `WALLET`, `MALWARE`, `RANSOMWARE`, `CAMPAIGN`, `SOURCE`, `TELEGRAM_CHANNEL`, `INFRASTRUCTURE`.

### Composite Entity Resolver
Resolves handle aliases (e.g. `ViperSec` ↔ `Viper_X`) using composite scoring:
\[ S_{comp} = 0.40 \cdot \text{JaroWinkler} + 0.35 \cdot \text{DistilBERT\_Cosine} + 0.25 \cdot \text{Graph\_Jaccard} \]

### Infrastructure Evolution Tracking
Tracks `FIRST_SEEN`, `LAST_SEEN`, `STATUS_HISTORY`, and `OLD_INFRASTRUCTURE` `REPLACED_BY` `NEW_INFRASTRUCTURE` graph edges.

---

## 7. Command Center & Autonomous AI Workstation

Served via `src/stage1_dashboard.py` (`python run_stage1_dashboard.py`):
- **Visual Design**: Deep Slate / Black (`#0b0f19`) theme, Green (`#10b981`) primary text, Sky Blue (`#38bdf8`) metrics, Amber (`#f59e0b`) warnings, Rose (`#ef4444`) critical errors.
- **Design Constraints**: NO emojis, NO glowing/cyber effects, NO fake gauges or artificial metrics.
- **Primary Interface**:
  - `GHOST>` interactive command console with structured operational output formatting.
  - Interactive Investigation Workstation modal opening on clicking any actor, source, onion, domain, or node.
  - 8 Interactive Data-Driven SVG Graphs (Entity Rel, Source Rel, Infra Evolution, Actor Activity, Source Uptime, Threat Trend, Change Timeline, STIX Rel).
  - Environment separation for Real-World Passive Sources vs Controlled Docker Lab.
  - Live Telemetry Stream sidebar displaying real-time system events.

---

## 8. Running GHOST Protocol

### Execute GHOST Command Agent (CLI Mode)
```bash
.venv/bin/python run_ghost_agent.py
```

### Launch GHOST Command Center Workstation (Web Dashboard)
```bash
.venv/bin/python run_stage1_dashboard.py
```
Open browser at: `http://127.0.0.1:8050/`

---

## 9. Verification & Test Commands

### Run Master Controlled Lab Test Suite
```bash
.venv/bin/python -m unittest tests/test_controlled_ghost_protocol_lab.py
```

### Run Master GHOST Integration Test Suite
```bash
.venv/bin/python -m unittest tests/test_ghost_agent_integration.py
```

### Run Stage 1 Dashboard Tests
```bash
.venv/bin/python -m unittest tests/test_stage1_dashboard.py
```
