# DarkWatch Collector — Whonix Deployment Guide

This guide details how to configure and execute the DarkWatch Phase 1 Collector inside **Whonix-Workstation-LXQt** connected to **Whonix-Gateway-LXQt**.

---

## Architecture Overview

```
+-------------------------------------------------------------------------+
| UNTRUSTED DARK WEB (.onion websites)                                    |
+-------------------------------------------------------------------------+
                                     ^
                                     | (Tor Network Traffic)
                                     v
+-------------------------------------------------------------------------+
| WHONIX-GATEWAY VM (IP: 10.152.152.10)                                   |
| - Runs Tor Daemon                                                       |
| - Listens on SOCKS Port 9050                                            |
| - Resolves .onion DNS queries via Tor (socks5h://)                      |
+-------------------------------------------------------------------------+
                                     ^
                                     | Internal Isolated Virtual Network
                                     v
+-------------------------------------------------------------------------+
| WHONIX-WORKSTATION VM                                                   |
| - Runs DarkWatch Collector                                              |
| - Enforces SOCKS_PROXY=socks5h://10.152.152.10:9050                     |
| - Sanitizes HTML & records SQLite evidence                              |
+-------------------------------------------------------------------------+
```

---

## 1. Prerequisites Verification in Whonix-Workstation

Before running the collector inside Whonix-Workstation, verify Tor connectivity:

```bash
# 1. Verify system Tor status check
whonixcheck

# 2. Verify Tor API response
curl -x socks5h://10.152.152.10:9050 https://check.torproject.org/api/ip
```

Expected response:
```json
{"IsTor":true,"IP":"<Tor Exit Node IP>"}
```

---

## 2. Configuration Options

The DarkWatch Collector automatically selects the Whonix Gateway proxy (`socks5h://10.152.152.10:9050`). You can configure it using any of the following methods:

### Option A: Environment Variable (Recommended for CLI)
```bash
export SOCKS_PROXY="socks5h://10.152.152.10:9050"
```

### Option B: Whonix Mode Flag in Python
```python
from src.collector.verifier import DarkWatchVerifier

verifier = DarkWatchVerifier(use_whonix=True)
```

### Option C: Configuration File (`config/collector_config.json`)
```json
{
  "socks_proxy": "socks5h://10.152.152.10:9050",
  "whonix_gateway_proxy": "socks5h://10.152.152.10:9050",
  "request_timeout": 15,
  "max_content_bytes": 2097152,
  "sqlite_db_path": "data/collector_evidence.db"
}
```

---

## 3. Running the Collector

### Step 1: Run the Tor Connectivity Check
Verify that the Python collector client reaches Tor through the Gateway:

```python
from src.collector.verifier import DarkWatchVerifier

verifier = DarkWatchVerifier(use_whonix=True)
status = verifier.check_whonix_tor_connection()

print("Connected to Tor:", status["connected_to_tor"])
print("Tor Exit IP:", status["ip"])
print("Proxy Used:", status["socks_proxy"])
```

### Step 2: Verify an Onion Source
Pass a target `.onion` URL to the verifier:

```python
from src.collector.verifier import DarkWatchVerifier

verifier = DarkWatchVerifier(use_whonix=True)

# Example verification attempt
result = verifier.verify_onion_source("http://examplelab.lab.onion")

print("Source State:", result["state"])             # e.g., "CONTENT_ACCESSIBLE"
print("HTTP Status:", result["http_status"])          # e.g., 200
print("Clean Text Length:", result["text_length"])   # e.g., 1850
print("SHA-256 Hash:", result["sha256"])            # e.g., "a1b2c3..."
print("Content Changed:", result["content_changed"]) # e.g., False
```

---

## 4. Running the Automated Test Suite

Execute all mock unit tests to confirm collector correctness before real usage:

```bash
python3 -m unittest discover -s tests
```
