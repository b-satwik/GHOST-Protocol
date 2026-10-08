# ShadowBoard — GHOST Protocol Controlled Research Lab

**ShadowBoard** is a completely self-contained Dockerized research-lab website designed for testing GHOST PROTOCOL's continuous browser observation, authenticated session tracking, conversation analysis, threat-session correlation, entity/alias correlation, temporal behavior analysis, CTI extraction, XAI, and multi-user activity tracking.

> [!IMPORTANT]
> - **AUTHORIZED LOCAL TEST ENVIRONMENT**: Everything runs locally inside Docker.
> - **NO REAL DARKNET CONNECTION**: Does NOT connect to real darknet sites or include real criminal content.
> - **SYNTHETIC CONTENT ONLY**: All users, organizations (`ApexGlobal`, `Northstar Systems`, `BluePeak Labs`), and discussions are entirely synthetic.

---

## Architecture Overview

```
[ Tor Browser / GHOST Observer ]
              │
              ▼
    [ darkwatch-tor-router ] (Port 9050 SOCKS5 Proxy & Tor v3 Onion Service)
              │
              ▼
    [ darkwatch-services ] (Port 8080 Flask Web App & SQLite Database)
              │
              ├── Persistent Storage: /app/data/shadowboard.db
              └── Tor Onion Key Persistence: /var/lib/tor/shadowboard
```

---

## 1. Quick Start Guide

### Build Containers
```bash
cd darkwatch_labs
docker compose build
```

### Start Laboratory Stack
```bash
docker compose up -d
```
Or run the automated startup script from the repository root:
```bash
./scripts/start_darkwatch_lab.sh
```

### Stop Laboratory Stack
```bash
docker compose down
```

---

## 2. Accessing the Laboratory & Finding the Onion Address

Once the container stack is running, you can access ShadowBoard locally or over Tor:

- **Local Web URL:** `http://127.0.0.1:8080/`
- **Tor SOCKS5 Proxy:** `127.0.0.1:9050`

### Display Tor .onion Address
To retrieve the generated v3 `.onion` address:
```bash
docker exec darkwatch-tor-router cat /var/lib/tor/shadowboard/hostname
```
Or run the address display script:
```bash
./commands/lab/show_onion_addresses.sh
```

---

## 3. Pre-Provisioned Test Accounts

The laboratory includes 10 pre-configured test accounts with hashed passwords (`pbkdf2:sha256`):

| Username | Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `user01` | `ShadowPass123!` | User | Synthetic Analyst / Poster |
| `user02` | `ShadowPass123!` | User | Telemetry Specialist |
| `user03` | `ShadowPass123!` | User | Security Audit Lead |
| `user04` | `ShadowPass123!` | User | Synthetic Threat Reporter |
| `user05` | `ShadowPass123!` | User | Infrastructure Engineer |
| `user06` | `ShadowPass123!` | User | Threat Intelligence Analyst |
| `user07` | `ShadowPass123!` | User | Incident Responder |
| `user08` | `ShadowPass123!` | User | YARA Rule Reviewer |
| `user09` | `ShadowPass123!` | User | Forensic Investigator |
| `user10` | `ShadowPass123!` | Admin | Laboratory Administrator |

*Note: Unauthenticated users are redirected to `/login` with HTTP 401 status to test GHOST's `LOGIN_REQUIRED` browser observation workflow.*

---

## 4. Multi-User Discussion Experiment Walkthrough

To execute a multi-user threat conversation scenario for GHOST observation:

1. **User03 Initiates Discussion:**
   - Log in as `user03` / `ShadowPass123!`.
   - Navigate to `/` or `/forum` and click **+ Create Post**.
   - Create post: Title: *"ApexGlobal Gateway Vulnerability Audit"*, Content: *"Investigating gateway node 10.0.4.12 egress rules."*

2. **User07 Replies:**
   - Log in as `user07` / `ShadowPass123!`.
   - Open post `/post/<id>` and submit reply: *"Reviewed gateway logs. Rotating API credentials."*

3. **User03 Replies to User07 (Nested Reply):**
   - Log in as `user03`, view the post, and click **Reply** under `user07`'s comment.
   - Submit nested reply: *"Please verify node-03 patch status."*

4. **User05 Joins Nested Discussion:**
   - Log in as `user05`, submit nested reply under `user03`'s comment: *"Node-03 patch verification completed."*

5. **Editing Content (Content Change Observation):**
   - `user03` returns to their original post and clicks **Edit Post** to update the text. GHOST detects `CHANGED_UNIQUE` on continuous observation.

---

## 5. Laboratory Reset & Re-Seeding

To clear all experimental posts, replies, sessions, and activity logs back to default baseline:

### Option A: Web UI
1. Log in with any account.
2. Click **Lab Admin** in the header (`http://127.0.0.1:8080/admin`).
3. Click **Reset Forum Lab Data**.

### Option B: API / Command
```bash
curl -X POST http://127.0.0.1:8080/admin/reset -b "session_token=<valid_session>"
```

The database preserves predefined accounts `user01`-`user10` and reseeds initial harmless cybersecurity discussions featuring `ApexGlobal`, `Northstar Systems`, and `BluePeak Labs`.
