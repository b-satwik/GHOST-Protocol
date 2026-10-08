# DarkWatch Local 5-Service Test Lab Documentation (Revised Architecture)

## Overview & Architecture
The **Local DarkWatch Service Lab** provides five realistic, controlled community chat services. Users interact with ordinary chat applications while DarkWatch **silently observes and processes threat content in the background**.

```
                        ┌─────────────────────────────────────────┐
                        │              END USER                   │
                        │  (Interacts with realistic chat/forum)  │
                        └────────────────────┬────────────────────┘
                                             │ Sends Message
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │      CONTROLLED SERVICE (A, B, C, D, E) │
                        │  - Network verification (Tor/VPN/Direct)│
                        │  - Auth verification (Password / 2FA)   │
                        │  - Renders normal chat UI               │
                        └────────────────────┬────────────────────┘
                                             │ Automatic Background Event
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │    BACKGROUND OBSERVATION LAYER         │
                        │  - Extracts metadata (Exit IP, Hash,    │
                        │    Session, Tor/VPN verification, Auth) │
                        └────────────────────┬────────────────────┘
                                             │ Silent Pipeline Dispatch
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │    DARKWATCH INFERENCE ENGINE           │
                        │  - DistilBERT Text Model                │
                        │  - Regex CTI Extractor                  │
                        │  - MITRE ATT&CK STIX 2.1 Mapper         │
                        │  - Risk Scoring & XAI Engine            │
                        └────────────────────┬────────────────────┘
                                             │ Silent Storage
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │     SQLITE DB (`data/local_lab/`)       │
                        │  - `observations` table                 │
                        │  - `analysis_results` table             │
                        └─────────────────────────────────────────┘
```

---

## Controlled Service Matrix

| Service | Port | Service ID | Network Path | Auth Method | Gatekeeper Access Control |
|---|---|---|---|---|---|
| **Service A** | `8001` | `DIRECT_CHAT` | Direct | Username + Password (`PASSWORD_ONLY`) | Baseline control service for standard HTTP traffic. |
| **Service B** | `8002` | `TOR_CHAT` | Tor Only | Username + Password (`PASSWORD_ONLY`) | **Strict Tor Verification**: Direct access returns `ACCESS DENIED — TOR CONNECTION REQUIRED`. Only verified Tor proxy/header requests (`X-Tor-Verified: true` or `?tor=1`) are granted access. |
| **Service C** | `8003` | `VPN_CHAT` | VPN Only | Username + Password (`PASSWORD_ONLY`) | **Strict VPN Verification**: Direct access returns `ACCESS DENIED — VPN TUNNEL REQUIRED`. Only verified VPN tunnel requests (`X-VPN-Verified: true` or `?vpn=1`) are allowed. |
| **Service D** | `8004` | `TWOFA_CHAT` | Controlled Normal Path | Username + Password + Code (`PASSWORD_PLUS_2FA`) | **2-Step Verification**: Password check → 6-digit code entry page (`DEMO 2FA CODE: 123456`) → Authenticated chat. |
| **Service E** | `8005` | `NO2FA_CHAT` | Controlled Normal Path | Username + Password (`PASSWORD_ONLY`) | **No-2FA Baseline**: Baseline password service for comparing 2FA vs No-2FA observation metadata. |

---

## Key Design Principles

1. **Clean User Experience**:
   - The end user sees a standard, realistic community chat interface.
   - **No threat scores, No XAI cards, No MITRE panels, No DarkWatch branding** are displayed on the user's web pages.
2. **Automatic Background Observation**:
   - Submitting a message automatically computes a SHA256 content hash and creates a background observation object (`observations` table in `data/local_lab/local_lab.db`).
   - The observation contains: `observation_id`, `timestamp`, `service_id`, `network_path`, `username`, `session_id`, `thread_id`, `message_id`, `message_text`, `content_hash`, `tor_verified`, `vpn_verified`, `observed_exit_ip`.
3. **Silent DarkWatch Pipeline Processing**:
   - Background observations are dispatched to `InferenceEngine.predict(text)` to generate threat predictions, extract CTI indicators, map MITRE techniques, and compute risk scores.
   - Pipeline outputs are persisted in the `analysis_results` table in `local_lab.db` for research analysis.
4. **Tor Circuit Exit IP Tracking**:
   - Service B includes the `/tor-circuit-test` endpoint to observe Tor exit IP rotation (`initial_exit_ip` vs `new_exit_ip` / `EXIT_IP_UNCHANGED`).

---

## Management Commands

- **Start Lab Services**:
  ```bash
  ./scripts/start_local_lab.sh
  ```
- **Check Status**:
  ```bash
  ./scripts/status_local_lab.sh
  ```
- **Stop Lab Services**:
  ```bash
  ./scripts/stop_local_lab.sh
  ```

All logs are written to `logs/local_lab/local_lab_master.log`.

---

## Test Accounts

- **Analyst**: `analyst` / `analyst123`
- **Standard User**: `user1` / `password123`
