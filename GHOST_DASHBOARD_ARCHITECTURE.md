# GHOST PROTOCOL — ANALYTICAL WORKSTATION DASHBOARD ARCHITECTURE

## 1. Overview & Visual Design System

The **GHOST PROTOCOL Command Center** (`src/templates/stage1_dashboard.html` & `src/stage1_dashboard.py`) is an **Analytical Workstation** with a clean white primary dashboard interface and a **Black Terminal-Style Live Telemetry Board**.

### Key Visual & Semantic Specifications:
- **Primary Workstation Theme**: Pure white card containers (`#ffffff`), neutral light gray page background (`#f8fafc`), dark slate typography (`#0f172a`), thin gray borders (`#cbd5e1`, `#e2e8f0`).
- **Live Telemetry Stream**: Styled as a **Black Terminal Board** (`#000000` background, green/light gray monospace text) streaming real operational events (Tor Check, HTTP Check, Threat Filter, DistilBERT, XGBoost, Temporal AE, HM-TIF, CTI, STIX, MITRE, Entity Resolution).
- **Score Semantics Isolation**:
  - $S_{comp}$ ($0.40 JW + 0.35 Cosine + 0.25 Jaccard$) is strictly reserved for Username / Entity correlation views and NEVER displayed inside ML model panels.
  - ML model panels display their true model outputs ($S_{text}$ for DistilBERT, $S_{net}$ for XGBoost, $E_{recon}$ and $S_{temp}$ for Temporal Autoencoder, $R_{fusion}$ for HM-TIF).
- **Strict Visual Rules**: ZERO blue/black cyber themes for the main dashboard, ZERO glowing cards, ZERO neon text, ZERO gradients, ZERO decorative animations, ZERO emojis, ZERO fake gauges.

---

## 2. Top Navigation Bar & 10 Workspaces

The top navigation bar provides instant access to **10 dedicated investigation workspaces**:

1. **COMMAND**: Interactive console (`GHOST>`) receiving analyst directives and slash commands, displaying structured human-readable operational outputs.
2. **SOURCES**: Source directory & Live Docker Test Controls (`OPEN`, `OBSERVE`, `REFRESH`, `PAUSE`, `RESUME`) with clean separation between **REAL-WORLD SOURCES** (monitored over Whonix SOCKS5 gateway) vs **CONTROLLED DOCKER LAB** (local synthetic test onion services on `127.0.0.1`).
3. **DISCOVERY**: Ahmia onion search and candidate queue ranking.
4. **USER ACTIVITY & ENTITIES**: First-class Username Investigation Workspace. Features handle search (`ViperSec`), cross-source comparison cards (ShadowForum `ViperSec` ↔ DreadLab `Viper_X`), multi-day activity timeline (Days 1–4), and composite score resolver evidence ($S_{comp} = 0.865$).
5. **ATTACKS**: Dynamic threat categories (Keylogger, Ransomware, Auth Access Bypass, RCE, Data Exfiltration) with multi-modal evidence breakdowns.
6. **AI MODELS**: Human-language explanations and real configuration metrics for DistilBERT, XGBoost, Temporal Autoencoder v2, and HM-TIF. Explicitly displays `UNAVAILABLE` when network flow or temporal data is missing.
7. **DATASETS**: Specifications and statistics for project datasets (HackerSignal, Darknet.CSV, Temporal dataset).
8. **GRAPHS**: 8 clean white SVG visualizers with explicit legends and node click handlers.
9. **MITRE ATT&CK**: Offline STIX 2.1 MITRE ATT&CK Enterprise workspace & ATT&CK Matrix Grid view. Search by technique ID (e.g. `T1486`), name, or tactic.
10. **DEEP ANALYSIS**: Deep observation inspection workspace.

---

## 3. Selection Context Isolation & Drawer Navigation

Clicking any item in the workstation (Source URL, Actor Handle, Attack Category, Model Component, Dataset, Observation ID, or MITRE Technique) opens an inline **Mini Investigation Window** drawer.
- **Selection Context Isolation**: Selection context never leaks across investigation types (e.g. clicking `DISTILBERT` displays DistilBERT specs; clicking `ViperSec` displays Username/Entity specs).
- **Duplicate & Recurring Evidence Fingerprinting**: SHA-256 and MinHash LSH fingerprinting labels recurring passes as `RECURRING EVIDENCE (DUPLICATE / NEAR-DUPLICATE)` with prior/current timestamps, avoiding expensive AI re-inference.

---

## 4. REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/ghost_tool` | `POST` | Command & natural language query dispatcher. Accepts query and active UI `context`. |
| `/api/user_activity` | `GET` | Returns first-class username report, cross-source appearances, multi-day timeline, and $S_{comp}$ score. |
| `/api/mitre/search` | `GET` | Searches offline STIX 2.1 MITRE knowledge base by technique ID, name, or tactic. |
| `/api/mitre/matrix` | `GET` | Returns Enterprise ATT&CK matrix grid structure highlighting observed techniques. |
| `/api/docker_controls` | `POST` | Handles live test control actions (`OPEN`, `OBSERVE`, `REFRESH`, `PAUSE`, `RESUME`) for Docker lab sources. |
| `/api/ai_models` | `GET` | Returns human-language explanations, input modalities, parameters, and decision contributions for ML components. |
| `/api/attacks` | `GET` | Returns aggregated list of observed threat categories and confidence percentages. |
| `/api/datasets` | `GET` | Returns dataset specifications, sample counts, class distributions, and provenance for project datasets. |
| `/api/real_vs_lab_sources` | `GET` | Returns sources grouped into `real_world_sources` vs `controlled_lab_sources`. |
