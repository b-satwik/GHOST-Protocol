# DarkWatch Minimal Collector Package for Whonix Workstation

This folder contains the minimal isolated DarkWatch Phase 1 Collector package designed for deployment inside **Whonix-Workstation**.

## Operational Constraints & Environment Details

- **Minimal Collector Package:** Contains only network reachability verification, HTML sanitization, deterministic state classification, and SQLite evidence persistence.
- **Whonix Mode:** Must be executed using `DarkWatchVerifier(use_whonix=True)`.
- **Expected Proxy:** Routes all SOCKS5 traffic through Whonix Gateway at `socks5h://10.152.152.10:9050`.
- **Authorized Research:** Intended solely for controlled, authorized security intelligence research collection.
- **No Machine Learning Models:** Machine learning models (DistilBERT, XGBoost, Autoencoders, Fusion Engine) are excluded from this deployment package and reside on the host.
- **Manual Control:** No real collection or crawling should be started automatically.

## Package Structure

```
whonix_collector_share/
├── README.md
├── config/
│   └── collector_config.json
├── requirements-collector.txt
└── src/
    ├── __init__.py
    └── collector/
        ├── __init__.py
        ├── verifier.py
        ├── sanitizer.py
        ├── state_engine.py
        └── evidence_store.py
```
