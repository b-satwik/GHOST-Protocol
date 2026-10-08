# DARKWATCH XAI — COMPONENT INTEGRATION MAP

This document maps all historical and new components in the repository, explaining how existing research scripts are integrated into the canonical end-to-end pipeline without throwing away team members' work.

---

## 1. INTEGRATION & CANONICAL COMPONENT MAP

| Domain | Original Research File | Canonical Integration Point | Purpose & Status | Integration Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Normalization** | `preprocessing/normalize_dwdata.py` | `preprocessing/normalize_dwdata.py` | Standardizes raw CSV dump schemas to 31 normalized columns | Ingests `data/raw/DWData-master/` $\to$ `dwdata_optimized.csv` |
| **Feature Extraction**| `preprocessing/extract_dwdata_features.py` | `src/pipeline/feature_extractor.py` & `extract_dwdata_features.py` | Engineers 73 features & 29 semantic category labels | Extracted features fed into tabular & temporal scaling |
| **Feature Selection** | `preprocessing/prepare_dwdata_model.py` | `preprocessing/prepare_dwdata_model.py` | Filters 10 constant & 6 redundant correlated features | Produces `tabular_features.json` & model feature lists |
| **Dataset Splitting** | `learning/training/prepare_training_data.py` | `learning/training/prepare_training_data.py` | 70/20/10 time-safe split based on snapshot dates | Produces `data/processed/training/*.csv` |
| **Text Model** | `learning/training/train_text_model.py` | `models/dwdata_text_model/` $\to$ `src/pipeline/inference_engine.py` | Fine-tuned DistilBERT 29-class sequence classifier | Loaded via HuggingFace `AutoModelForSequenceClassification` |
| **Behavioral Model**| `learning/training/train_tabular_model.py` | `models/dwdata_tabular_model/model.pt` $\to$ `src/pipeline/inference_engine.py` | PyTorch 39-dim MLP Autoencoder (`TabularAutoencoder`) | Scaled via `scaler.joblib`, computes reconstruction MSE |
| **Temporal Model** | `learning/training/train_temporal_model.py` | `models/dwdata_temporal_model/temporal_autoencoder.pt` $\to$ `src/pipeline/inference_engine.py` | PyTorch 14-dim MLP Autoencoder (`TemporalAutoencoder`) | Scaled via `temporal_scaler.npz`, computes MSE |
| **Risk Fusion** | `learning/training/build_model_fusion.py` | `src/pipeline/inference_engine.py` | Weighted decision risk fusion ($0.40 \cdot \text{Beh} + 0.35 \cdot \text{Temp} + 0.25 \cdot (1 - \text{TextConf})$) | Dynamically renormalizes weights based on available modalities |
| **Threat Extraction**| `learning/training/analyze_text_model.py` | `src/extraction/threat_extractor.py` | Regex & pattern extraction of CVEs, RATs, credentials, IOCs | Outputs structured JSON (`DETECTED` / `NOT_DETECTED`) |
| **CTI / MITRE Mapper**| Concept / Team CTI notes | `src/cti/mitre_mapper.py` & `src/config/mitre_knowledge_base.json` | Correlates extracted threat terms to MITRE ATT&CK techniques | Returns technique IDs (`T1078`, `T1190`, `T1486`, `T1071`) with evidence |
| **Risk Policy** | Concept / Team notes | `src/risk/risk_engine.py` & `src/config/risk_policy.json` | Transparent policy-driven severity calculation | Combines ML fusion + CTI score + Entity presence |
| **Text XAI** | `learning/training/explain_text_lime.py` | `src/xai/conditional_xai.py` | LIME text token perturbation explainer | Computes top positive and negative token weights |
| **Behavioral XAI** | `learning/training/explain_behavioral_shap.py` | `src/xai/conditional_xai.py` | SHAP tabular feature importance explainer | Computes KernelExplainer feature attributions |
| **Temporal XAI** | `learning/training/explain_temporal.py` | `src/xai/conditional_xai.py` | Temporal feature reconstruction error ranking | Computes per-feature MSE error contributions |
| **Unified XAI** | `learning/training/explain_fusion.py` | `src/xai/conditional_xai.py` | Multi-modal text report narrative generator | Generates human-readable analyst narrative |
| **Alert Schema** | Concept / Team notes | `src/alerts/alert_generator.py` | Standardized JSON security alert builder | Generates traceable `DW-ALERT-XXXX` JSON object |
| **CLI Prediction** | `predict.py` | `predict.py` | Command line prediction tool for historical records & text | Supports Mode 1 (Historical) & Mode 2 (Text-Only) |
| **Analyst Dashboard**| `dashboard/app.py` | `dashboard/app.py` | Interactive Streamlit web UI | Connected to real pipeline & dataset loading |

---

## 2. PRESERVATION PRINCIPLE

No legacy training or evaluation scripts were deleted. Original files in `learning/training/` and `preprocessing/` remain fully functional as historical research assets. All new operational modules wrap around these existing artifacts.
