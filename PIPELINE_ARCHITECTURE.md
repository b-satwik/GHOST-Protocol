# DARKWATCH XAI — PIPELINE ARCHITECTURE

This document details the multi-modal pipeline architecture for **DarkWatch XAI**, demonstrating how text, behavioral, and temporal modalities flow from raw ingestion to the analyst dashboard.

---

## 1. END-TO-END PIPELINE DIAGRAM

```
                  DARK WEB / UNDERGROUND CONTENT
                                │
                                ▼
                       INGESTION & ETL LAYER
             (normalize_dwdata.py & extract_dwdata_features.py)
                                │
             ┌──────────────────┼──────────────────┐
             ▼                  ▼                  ▼
     TEXT MODALITY       BEHAVIORAL MODALITY   TEMPORAL MODALITY
   (Raw listing text)     (39 Tabular Features) (14 Vendor Dynamics)
             │                  │                  │
             ▼                  ▼                  ▼
   DistilBERT Classifier Tabular Autoencoder  Temporal Autoencoder
    (dwdata_text_model) (dwdata_tabular_model)(dwdata_temporal_model)
             │                  │                  │
   Logits ➔ Softmax      Reconstruction MSE    Reconstruction MSE
   (Predicted Class ID)   (Behavioral Anomaly)  (Temporal Anomaly)
             │                  │                  │
             └──────────────────┼──────────────────┘
                                │
                                ▼
                      TRI-MODAL RISK FUSION
                    (Dynamic Modality Weights)
                                │
                                ▼
                    THREAT ENTITY EXTRACTION
                    (Malware, CVEs, IOCs, Tools)
                                │
                                ▼
                      CTI & MITRE ATT&CK MAPPER
                     (mitre_knowledge_base.json)
                                │
                                ▼
                     TRANSPARENT RISK ENGINE
                       (risk_policy.json)
                                │
                                ▼
                   CONDITIONAL PERFORMANCE XAI
                   (Lightweight vs Deep LIME/SHAP)
                                │
                                ▼
                    SECURITY ANALYST ALERT OBJECT
                              (JSON)
                                │
                                ▼
                     STREAMLIT ANALYST DASHBOARD
```

---

## 2. MODALITY AVAILABILITY HANDLING

The pipeline explicitly handles multi-modal availability:

- **Mode 1: Historical Dataset Record (All 3 Modalities Available)**
  - `text_available = True`
  - `behavior_available = True`
  - `temporal_available = True`
  - *Fusion Formula:* $0.40 \cdot S_{\text{beh}} + 0.35 \cdot S_{\text{temp}} + 0.25 \cdot (1 - \text{Conf}_{\text{text}})$

- **Mode 2: Text-Only Input (Behavioral & Temporal Unavailable)**
  - `text_available = True`
  - `behavior_available = False`
  - `temporal_available = False`
  - *Fusion Formula (Renormalized):* $1.00 \cdot (1 - \text{Conf}_{\text{text}})$ (No synthetic zero vectors inserted).
