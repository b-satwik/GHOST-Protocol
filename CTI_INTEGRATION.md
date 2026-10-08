# DARKWATCH XAI — CTI & MITRE ATT&CK INTEGRATION GUIDE

This document explains the CTI extraction, MITRE ATT&CK correlation, and transparent policy risk assessment layers.

---

## 1. THREAT INFORMATION EXTRACTION LAYER

Extracted threat entities are separated from ML sequence classification:
- **CVEs & Vulnerabilities:** Pattern matching for `CVE-YYYY-NNNN`, Zero-Day, RCE, LPE, SQLi.
- **Malware & RATs:** Taxonomy dictionary matching RedLine, Loki, Venom RAT, Keylogger, Ransomware, Stealer, Botnet.
- **Credentials & Access:** Combo lists, RDP access, Fullz, Credit Card CVV, Bank drop.
- **IOCs:** IP addresses, Onion domains (`.onion`), MD5/SHA256 hashes, Email addresses.

Extracted entities output explicit status (`DETECTED` vs `NOT_DETECTED`) to eliminate hallucination.

---

## 2. MITRE ATT&CK KNOWLEDGE CORRELATION

Extracted threats are correlated against official MITRE ATT&CK Enterprise techniques defined in `src/config/mitre_knowledge_base.json`:

| Technique ID | Technique Name | Tactic | Keywords / Indicators |
| :--- | :--- | :--- | :--- |
| **T1078** | Valid Accounts | Initial Access / Persistence | account, rdp access, combo list, credentials |
| **T1110** | Brute Force | Credential Access | brute, cracked, checker, passlist |
| **T1059** | Command & Script Interpreter | Execution | powershell, python, bash, cmd |
| **T1486** | Data Encrypted for Impact | Impact | ransomware, encryptor, locker, ransom |
| **T1190** | Exploit Public-Facing App | Initial Access | exploit, cve-, zero-day, rce, sqli |
| **T1566** | Phishing | Initial Access | phishing, scam page, mailer, spoof |
| **T1071** | Application Layer Protocol | Command & Control | botnet, rat, c2, keylogger, trojan |

Every mapping output retains evidence text, mapping method (`KEYWORD_PATTERN_MATCH`), confidence score (`0.90`), and reference source.
