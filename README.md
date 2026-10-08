# GHOST PROTOCOL

### Autonomous Cyber Threat Intelligence & Multi-Tier Explainable AI Observation System

---

## 1. Overview

**GHOST PROTOCOL** is a cybersecurity research system for autonomous cyber threat intelligence (CTI), multi-modal threat classification, hierarchical threat intelligence fusion, and explainable AI (XAI). GHOST provides end-to-end, passive observation of synthetic threat actors, automated threat session reconstruction, STIX 2.1 entity extraction, MITRE ATT&CK mapping, and transparent two-tier explainability (SHAP & LIME) for security analysts.

To ensure strict ethical compliance and safety, GHOST is developed, benchmarked, and validated within **controlled Docker-based virtual laboratories** simulating realistic underground forum, paste, market, and ransomware-leak scenarios.

---

## 2. Problem

Modern cyber-threat intelligence processing faces several critical challenges:
- **Unstructured Multimodal Discourse**: Threat discussions across underground platforms exhibit unstructured text, code snippets, metadata, user reputation networks, and dynamic temporal activity.
- **Data Heterogeneity & Missing Modalities**: In real-world CTI collection, complete aligned data across text, network, and temporal modalities is rarely available for every observed artifact.
- **Black-Box AI Decisions**: High-stakes threat attribution and risk scoring require transparent, actionable explanations for human security analysts before taking defensive actions.
- **Adversarial & Dynamic Environments**: Observation platforms must operate passively, securely, and reproducibly without compromising analyst infrastructure or exposing non-public networks.

---

## 3. Controlled Research Environment

GHOST is validated exclusively within **isolated Docker-based cybersecurity virtual laboratories**. These environments simulate high-fidelity synthetic threat actor discourse, paste submissions, ransomware leak announcements, and authentication-gated forums.

```
+-------------------------------------------------------+
|        Controlled Docker Virtual Laboratory           |
|  (ShadowBoard, ShadowForum, DreadLab, PasteVault)     |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|             Synthetic Threat Scenarios                |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|                 GHOST Observation                     |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|                   Threat Session                      |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|                 ML / CTI / XAI                        |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
|               Analyst Dashboard                       |
+-------------------------------------------------------+
```

---

## 4. GHOST Architecture

The GHOST system architecture follows a 14-stage modular processing pipeline:

1. **Source Discovery**: Controlled target discovery and canonical URL normalization.
2. **Source Validation**: Health checks and endpoint availability verification.
3. **Passive / Authorized Observation**: SOCKS5 transport and browser-based observation.
4. **Threat Filtering**: NLU-based noise reduction to isolate high-confidence security discourse.
5. **Multi-Modal Feature Extraction**: DistilBERT embeddings, tabular indicators, and temporal sequence features.
6. **Multi-Modal AI Classification**: DistilBERT text classification, XGBoost tabular risk estimation, and Temporal Autoencoder anomaly detection.
7. **Hierarchical Multi-Modal Threat Intelligence Fusion (HM-TIF)**: Dynamic modality weighting handling missing inputs.
8. **CTI Entity Extraction**: Automated parsing of IOCs, CVEs, attack vectors, and target assets.
9. **STIX 2.1 Generation**: Standardization into STIX 2.1 domain objects (Indicator, Vulnerability, Attack Pattern).
10. **MITRE ATT&CK Mapping**: Automated mapping to Tactics, Techniques, and Procedures (TTPs).
11. **Two-Tier XAI**: Local feature attribution (SHAP) and surrogate model explanations (LIME).
12. **Threat Sessions & Correlation**: Temporal graph grouping of related thread discourse and actor handles.
13. **Analyst Review Queue**: Human-in-the-Loop (HITL) triage interface.
14. **Analyst Dashboard**: Real-time interactive UI for threat visualization and intelligence export.

---

## 5. Observation Pipeline

The GHOST observation pipeline handles content retrieval passively:
- **Tor / SOCKS5 Transport**: Configurable isolation routing for network separation.
- **Fail-Closed Isolation**: Automatic execution termination if transport guarantees are breached.
- **JavaScript-Disabled Observation**: Minimal attack surface for passive text rendering.
- **Persistent Session Manager**: Handles synthetic authentication flows in controlled lab scenarios.

---

## 6. Multi-Modal AI

GHOST leverages a three-component Machine Learning architecture:
- **DistilBERT NLU Model**: Fine-tuned transformer for cybersecurity activity and event classification (`vulnerability_exploit`, `ransomware_leak`, `malware_distribution`, `credential_dump`, `benign_discussion`).
- **XGBoost Classifier**: Multi-class tabular risk scorer evaluating structural and metadata signals.
- **Temporal Autoencoder**: Anomaly detection model for identifying sudden bursts in threat volume or unusual actor activity profiles.

---

## 7. Hierarchical Multi-Modal Threat Intelligence Fusion (HM-TIF)

GHOST implements **HM-TIF**, a fusion mechanism designed to handle partial or unaligned data modalities:
- Evaluates confidence scores across available modalities (Text, Tabular, Temporal).
- Dynamically adjusts modality weights when one or more inputs are missing (e.g., text-only observation).
- Produces a normalized composite Risk Score ($[0.0, 1.0]$) and Threat Severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

---

## 8. CTI / STIX 2.1

GHOST converts raw observations into standardized **STIX 2.1** JSON bundles containing:
- **Identity & Threat Actor**: Synthetic profile entities.
- **Indicator**: IP addresses, onion endpoints, cryptographic hashes, CVE references.
- **Vulnerability**: Mapped CVE identifiers and severity classifications.
- **Attack Pattern**: Standardized technique definitions.
- **Relationship Objects**: Mapped connections (`indicates`, `targets`, `uses`).

---

## 9. MITRE ATT&CK

Observed threat discourse is mapped to the MITRE ATT&CK matrix:
- **Tactics**: Initial Access (TA0001), Execution (TA0002), Persistence (TA0003), Privilege Escalation (TA0004), Defense Evasion (TA0005), Credential Access (TA0006), Discovery (TA0007), Lateral Movement (TA0008), Impact (TA0040).
- **Techniques**: Exploitation for Privilege Escalation (T1068), OS Credential Dumping (T1003), Data Destruction (T1485), Service Stop (T1489), Ingress Tool Transfer (T1105).

---

## 10. Two-Tier XAI

GHOST implements transparent Two-Tier Explainable AI to justify model predictions:
- **Tier 1 (Global & Local Feature Attribution)**: SHAP (SHapley Additive exPlanations) values highlighting key input tokens and metadata features driving the risk score.
- **Tier 2 (Model Explanations & Surrogate Trees)**: LIME (Local Interpretable Model-agnostic Explanations) text feature highlights highlighting specific keywords that influenced classification.

---

## 11. Threat Sessions

Related observations are automatically grouped into **Threat Sessions**:
- Clusters sequential forum threads, user interactions, and cross-posted pastes over configurable time windows.
- Tracks handle persistence, thread reply trees, and evolving risk trajectories.

---

## 12. Analyst Dashboard

The GHOST Analyst Dashboard is a Flask-based Web UI providing:
- **Real-Time Threat Feed**: Live updates of incoming laboratory observations.
- **Session Inspector**: Graph visualization of user nodes, reply edges, and timeline activity.
- **XAI Explanation Panel**: Interactive SHAP and LIME visual feature attribution summaries.
- **STIX 2.1 Bundle Exporter**: One-click download of JSON STIX bundles for SIEM/SOAR integration.

---

## 13. Docker Virtual Laboratory

The primary demonstration environment is an isolated, multi-service Docker laboratory containing synthetic services:
- **ShadowBoard**: Synthetic underground forum with topic threads, user handles, and authentication.
- **ShadowForum**: Multi-category threat discussion service.
- **DreadLab**: Synthetic darknet discussion board.
- **PasteVault**: Synthetic public paste dump service.
- **LeakLocker**: Synthetic ransomware extortion leak portal.

The laboratory dynamically configures its endpoints upon deployment using `docker compose up -d`.

---

## 14. Installation

### Prerequisites
- Python 3.10+
- Docker & Docker Compose
- Virtualenv (`python3 -m venv .venv`)

### Setup Instructions

```bash
# Clone the repository
git clone https://github.com/your-org/ghost-protocol.git
cd ghost-protocol

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 15. Running the Controlled Lab

To launch the isolated Docker laboratory environment:

```bash
cd darkwatch_labs
docker compose up -d
```

Verify service status:

```bash
docker compose ps
```

---

## 16. Running GHOST

### Start the Analyst Dashboard

```bash
python3 run_stage1_dashboard.py
```

Access the dashboard in your browser at `http://127.0.0.1:5000`.

### Run Pipeline Demonstration

```bash
python3 run_full_demonstration.py
```

### Run Synthetic Agent Verification

```bash
python3 run_ghost_agent.py
```

---

## 17. Security / Ethics

- **Strict Controlled Scope**: GHOST is designed and authorized exclusively for controlled virtual laboratories and synthetic threat data.
- **No Unauthorized Probing**: The pipeline operates passively. It does not perform active vulnerability scanning, exploit delivery, CAPTCHA solving, or unauthorized access attempts.
- **No Private Data Dumps**: The repository contains no real-world victim data, stealer logs, credential dumps, or PII.

---

## 18. Dataset Policy

The current repository contains **NO raw scraped datasets, private research collections, or victim data dumps**. All demonstration data is synthetically generated within the Docker laboratory.

Research datasets may be released separately in future work following formal data sanitization, ethical review, and appropriate academic licensing.

---

## 19. Future Work

- **Site-Specific LLM Adaptability**: Future iterations will explore LLM-assisted DOM adapters capable of dynamically interpreting novel underground forum structures, nested thread layouts, and custom markup formats. *(Note: This feature is planned for future research and is not currently implemented in this release.)*
- **Expanded STIX 2.1 Graph Analytics**: Integration of advanced graph neural networks for automated threat campaign link discovery.

---

## 20. Research Foundations

The design and methodology of GHOST build upon published foundations in cyber threat intelligence, underground forum analysis, multimodal fusion, and explainable AI:

- *DarkBERT: A Language Model for the Dark Side of the Internet*
- *CrimeBB: Enabling Cybercrime Research on Underground Forums at Scale*
- *Hierarchical Multi-Modal Threat Intelligence Fusion Without Aligned Data*
- *TIJERE: A Novel Threat Intelligence Joint Extraction Model Based on Analyst Expert Knowledge*
- *HackerSignal: A Large-Scale Multi-Source Dataset Linking Hacker Community Discourse to the CVE Vulnerability Lifecycle*
- *EventHunter: Dynamic Clustering and Ranking of Security Events from Hacker Forum Discussions*
- *A Structured Cyber Threat Intelligence Dataset Using STIX 2.1 Entities and MITRE ATT&CK Mappings*
- *A Tight Scrape: Methodological Approaches to Cybercrime Research Data Collection in Adversarial Environments*
- *VTT-LLM: Advancing Vulnerability-to-Tactic-and-Technique Mapping through Fine-Tuning of Large Language Model*
- *DICE-E: A Framework for Conducting Darknet Identification, Collection, Evaluation with Ethics*
- *Explainable AI for Multi-Stage Cyber Attack Detection Using SHAP Fingerprints*
- *URM4DMU: A User Representation Model for Darknet Markets Users*

---

## 21. License

This repository is governed by the **GHOST PROTOCOL RESTRICTED ACADEMIC RESEARCH LICENSE**. See [LICENSE](LICENSE) for full details. Commercial use, public redistribution, and unauthorized deployment are strictly prohibited.
