# DARKWATCH XAI — AUTOMATED TEST REPORT

**Test Suite File:** [tests/test_pipeline.py](file:///home/balasatwik/Downloads/darkwatch%20%282%29/darkwatch/tests/test_pipeline.py)  
**Execution Command:** `python3 -m unittest discover -s tests -p "test_*.py"`  
**Status:** **6 / 6 PASSED (100% Success)**

---

## 1. TEST CASE RESULTS

| Test Name | Target Component | Verifications Performed | Status |
| :--- | :--- | :--- | :---: |
| `test_threat_extractor` | ThreatExtractor | Malware terms, CVE format matching, credential keywords, IOC extraction | **PASSED** |
| `test_mitre_mapper` | MITREMapper | MITRE ATT&CK technique IDs (`T1078`, `T1071`), evidence strings, confidence scores | **PASSED** |
| `test_risk_engine` | RiskEngine | Dynamic policy calculation, severity mapping, contributing factors | **PASSED** |
| `test_conditional_xai` | ConditionalXAIEngine | `LIGHTWEIGHT` mode for LOW risk vs `DEEP_EXPLANATION` mode for HIGH risk | **PASSED** |
| `test_alert_generator` | AlertGenerator | Alert UUID format, ISO timestamp, model scores, XAI attachment, status | **PASSED** |
| `test_end_to_end_inference` | InferenceEngine | End-to-end execution returning dictionary containing prediction, extraction, CTI, risk, XAI, and alert | **PASSED** |

---

## 2. EMPIRICAL TEST OUTPUT (5 DISTINCT INPUTS)

```
Test 1: Benign Cybersecurity Discussion ➔ Predicted: OTHER_SEMANTIC | Risk: 0.037 (LOW) | MITRE: []
Test 2: Malware Discussion ➔ Predicted: botnets and malware | Risk: 0.209 (LOW) | MITRE: ['T1190', 'T1071']
Test 3: Credential / Access Sale ➔ Predicted: accounts & bank drops | Risk: 0.143 (LOW) | MITRE: ['T1078']
Test 4: Vulnerability / Exploit ➔ Predicted: exploits | Risk: 0.169 (LOW) | MITRE: ['T1190']
Test 5: Unrelated Normal Text ➔ Predicted: OTHER_SEMANTIC | Risk: 0.037 (LOW) | MITRE: []
```
