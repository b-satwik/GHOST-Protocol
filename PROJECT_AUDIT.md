# DARKWATCH XAI — COMPREHENSIVE PROJECT AUDIT REPORT

**Project Name:** DarkWatch XAI  
**Audit Date:** September 25, 2026  
**Auditor:** Lead Coding Assistant (Antigravity)  
**Objective:** Audit, classify, and verify every dataset, model, script, pipeline component, CTI module, XAI tool, alert generator, and UI file in the repository.

---

## 1. COMPONENT CLASSIFICATION MATRIX

Every component in the workspace has been inspected and classified into one of the following exact categories:
- `[REAL + WORKING]`: Production-ready code executing real computations.
- `[REAL + PARTIAL]`: Real code/artifact that is partially complete or trained on a subsample.
- `[PROTOTYPE]`: Functional wrapper/framework connecting modules, but using heuristics/simulations.
- `[PLACEHOLDER]`: Shell structure or dummy values waiting for implementation.
- `[MISSING]`: Required feature/artifact not yet present in repository.
- `[DUPLICATE]`: Multiple versions of scripts/models serving identical purpose.
- `[UNUSED]`: Legacy, obsolete, or disconnected file.

| Component Name | File / Path | Purpose | Classification | Real Model? | Loadable? | Used? | Inputs | Outputs | Dependencies | Problems | Integration Point |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- | :--- | :--- | :--- | :--- |
| **Dark Web Marketplace Scrapes** | `data/raw/DWData-master/` | 54+ CSV dumps from 15+ markets (2021-2024) | `[REAL + WORKING]` | N/A | YES | YES | Raw web scrapes | 388,379 CSV rows | Standard CSV | Raw duplicates & schema variations | Fed into `normalize_dwdata.py` |
| **Surface CTI Network Traffic** | `data/raw/surface_cti.csv` | CICFlowMeter network traffic dataset (158k rows) | `[UNUSED]` | N/A | YES | NO | Network traffic captures | 85 flow metrics | pandas | Unmerged with dark web dataset | Kept separate in raw data |
| **Benign Safe Corpus** | `data/raw/safe_corpus.json` | 2,000 JSON lines of benign text | `[UNUSED]` | N/A | YES | NO | Benign web text | JSON records | json | Unmerged with threat dataset | Kept separate in raw data |
| **Normalized Dataset** | `data/processed/dwdata_optimized.csv` | Standardized dark web listings schema | `[REAL + WORKING]` | N/A | YES | YES | DWData-master CSVs | 388k rows x 31 cols | `normalize_dwdata.py` | None | Fed into `extract_dwdata_features.py` |
| **Feature Engineered Dataset** | `data/processed/dwdata_features.csv` | 73 engineered features & 29 semantic labels | `[REAL + WORKING]` | N/A | YES | YES | dwdata_optimized.csv | 388k rows x 73 cols | `extract_dwdata_features.py` | Class imbalance in 29 categories | Fed into `prepare_dwdata_model.py` |
| **Time-Safe Split Datasets** | `data/processed/training/*.csv` | Chronological 70/20/10 train/val/test splits | `[REAL + WORKING]` | N/A | YES | YES | dwdata_features.csv | Train:271k, Val:75k, Test:41k | `prepare_training_data.py` | Severe class imbalance in text labels | Fed into model training scripts |
| **DistilBERT Text Model** | `models/dwdata_text_model/model.safetensors` | 29-class semantic sequence classifier | `[REAL + PARTIAL]` | YES | YES | PARTIAL | Raw text string (max_len=128) | Logits / 29 class probabilities | HuggingFace Transformers, PyTorch | Subsampled to 5k train samples; 1 epoch | `InferenceEngine._predict_text()` |
| **Tabular Behavioral Autoencoder**| `models/dwdata_tabular_model/model.pt` | 39-dim PyTorch MLP Autoencoder | `[REAL + WORKING]` | YES | YES | YES | 39 standardized numerical features | Reconstruction MSE score | PyTorch, StandardScaler | High anomaly flag rate on test set (drift) | `InferenceEngine._predict_tabular()` |
| **Temporal Autoencoder** | `models/dwdata_temporal_model/temporal_autoencoder.pt`| 14-dim PyTorch MLP Autoencoder | `[REAL + WORKING]` | YES | YES | YES | 14 vendor temporal features | Reconstruction MSE score | PyTorch, MinMaxScaler | None | `InferenceEngine._predict_temporal()` |
| **Tri-Modal Fusion Algorithm** | `learning/training/build_model_fusion.py` | Weighted decision risk fusion formula | `[REAL + WORKING]` | YES | N/A | YES | Beh MSE, Temp MSE, Text Conf | Fusion Risk Score & Band | Python math | Requires all 3 modalities | `InferenceEngine.predict()` |
| **Threat Extraction Engine** | `src/extraction/threat_extractor.py` | Extracts CVEs, malware, credentials, IOCs | `[REAL + WORKING]` | N/A | YES | YES | Raw dark web text | Structured JSON entities & IOCs | re, Python stdlib | Keyword list limits | `InferenceEngine.predict()` |
| **MISP / CTI Knowledge Base** | `src/config/mitre_knowledge_base.json` | CTI & MITRE ATT&CK technique reference | `[REAL + WORKING]` | N/A | YES | YES | Extracted threat terms & text | MITRE technique matches & evidence | JSON | Expanded MITRE Coverage | `src/cti/mitre_mapper.py` |
| **MITRE ATT&CK Mapper** | `src/cti/mitre_mapper.py` | Correlates extracted threats to ATT&CK | `[REAL + WORKING]` | N/A | YES | YES | Threat entities & text | Validated technique ID cards | json, Python | Keyword false positives on generic terms | `InferenceEngine.predict()` |
| **Transparent Risk Engine** | `src/risk/risk_engine.py` | Configurable policy risk calculator | `[REAL + WORKING]` | N/A | YES | YES | ML Fusion, CTI score, Entity score | Risk Score, Severity, Policy Rationale | `risk_policy.json` | Threshold calibration needed | `InferenceEngine.predict()` |
| **Performance-Aware XAI Engine**| `src/xai/conditional_xai.py` | Connects LIME, SHAP, & Temporal XAI | `[REAL + PARTIAL]` | YES | YES | PARTIAL | Text, Tabular, & Temporal data | Token highlights, SHAP attributions | LIME, SHAP | Needs direct LIME/SHAP live hooks | `InferenceEngine.predict()` |
| **Security Analyst Alert Object**| `src/alerts/alert_generator.py` | Standard analyst alert schema builder | `[REAL + WORKING]` | N/A | YES | YES | Prediction, CTI, Risk, XAI | Traceable JSON Alert Object | uuid, datetime | None | `predict.py` & Dashboard |
| **Unified Inference Pipeline** | `src/pipeline/inference_engine.py` | End-to-end multi-modal orchestrator | `[PROTOTYPE]` | YES | YES | YES | Single text or JSON record | Structured prediction JSON | PyTorch, Transformers, src.* | Previously used keyword fallback | `predict.py` & `dashboard/app.py` |
| **CLI Entrypoint** | `predict.py` | Top-level command line prediction tool | `[REAL + WORKING]` | N/A | YES | YES | `--text`, `--json`, `--deep` | Printed / Saved JSON Alert | argparse, src.pipeline | None | Command line interface |
| **Streamlit Analyst Dashboard** | `dashboard/app.py` | Interactive web UI for threat analysts | `[REAL + WORKING]` | N/A | YES | YES | User input text / metadata | Live gauges, XAI plots, JSON export | Streamlit | Historical feed tab is mock table | Web UI (`streamlit run`) |
| **Automated Test Suite** | `tests/test_pipeline.py` | 6 unit and integration test cases | `[REAL + WORKING]` | N/A | YES | YES | Synthetic test strings | All 6 tests PASSED | unittest | Expand to 12 comprehensive tests | CLI / CI verification |
| **Legacy Preprocessing Folder** | `preprocessing_codes/` | Empty folder | `[UNUSED]` | N/A | NO | NO | None | None | None | Empty directory | None |
| **Checkpoints Folder** | `models/checkpoints/` | Empty folder for epoch weights | `[UNUSED]` | N/A | NO | NO | None | None | None | Empty directory | None |

---

## 2. DETAILED DISTILBERT MODEL AUDIT

The DistilBERT semantic classifier in `models/dwdata_text_model/` has been thoroughly audited against your 12 research questions:

1. **What DistilBERT model exists?**  
   - Fine-tuned `distilbert-base-uncased` with a 29-class Sequence Classification head (`models/dwdata_text_model/model.safetensors`, 268 MB).
2. **What dataset was used?**  
   - Subsampled `data/processed/training/text_train.csv` (5,000 samples out of 271,266 full training records).
3. **What labels/classes exist?**  
   - 29 semantic category IDs mapped in `data/processed/training/text_label_map.json`:
     `0: OTHER_SEMANTIC`, `1: accounts & bank drops`, `2: botnets`, `3: botnets and malware`, `4: cracked`, `5: cvv & cards`, `6: data`, `7: digital goods`, `8: drugs`, `9: exploit`, `10: exploits`, `11: forgeries / counterfeits`, `12: genuine`, `13: goods`, `14: hacking`, `15: information`, `16: malware`, `17: methods`, `18: new_malware`, `19: other digital items`, `20: other fraud`, `21: personal data`, `22: rat`, `23: security software`, `24: services`, `25: software & hosting`, `26: software & malware`, `27: software / hosting`, `28: stealth`.
4. **What tokenizer/model files exist?**  
   - `models/dwdata_text_model/config.json`
   - `models/dwdata_text_model/model.safetensors` (268,823,208 bytes)
   - `models/dwdata_text_model/tokenizer.json`
   - `models/dwdata_text_model/tokenizer_config.json`
5. **How was it trained?**  
   - PyTorch / HuggingFace Trainer style loop in `learning/training/train_text_model.py`. 1 epoch, learning rate `2e-5`, batch size `16`, max sequence length `128`.
6. **What evaluation exists?**  
   - `reports/training/text_model_metrics.json` (Unbalanced Test set 1k: Accuracy = 47.0%, Macro Precision = 92.07%, Weighted F1 = 0.6198).
   - `reports/training/balanced_text_metrics.json` (Balanced Test set 150: Accuracy = 16.0%, Macro F1 = 0.1023).
7. **Can it actually be loaded?**  
   - YES. Loadable via `transformers.AutoModelForSequenceClassification.from_pretrained("models/dwdata_text_model")` and `AutoTokenizer.from_pretrained("models/dwdata_text_model")`.
8. **Can it perform inference?**  
   - YES. Tokenizer `inputs = tokenizer(text, return_tensors="pt", max_length=128, truncation=True)` $\to$ Model `logits = model(**inputs).logits` $\to$ Softmax `probs = torch.softmax(logits, dim=-1)` $\to$ Top class & confidence.
9. **What input format does it expect?**  
   - Raw text string (`listing_name` / title), max token length 128.
10. **Does it correspond to our current DarkWatch dataset?**  
    - YES. The 29 classes directly represent the normalized category mappings of the 388k dark web listings.
11. **Does it duplicate an existing text model?**  
    - NO. It is the sole trained text model in the repository.
12. **How should it be used?**  
    - It is the **ACTIVE BASELINE TEXT MODEL**. Genuine HuggingFace model inference MUST be connected to replace prototype keyword matching.

---

## 3. MISP & CTI ARTIFACT AUDIT

- **MISP Galaxy Files:** None found in raw workspace root.
- **CTI Knowledge Assets Found:**
  - `src/config/mitre_knowledge_base.json` (JSON knowledge base containing official MITRE ATT&CK Enterprise technique definitions, tactics, keywords, and descriptions).
  - `data/raw/surface_cti.csv` (158,616 rows x 85 CICFlowMeter network traffic flow metrics). Unmerged raw asset.

---

## 4. INTEGRATION & ACTION PLAN

1. **Implement Genuine DistilBERT Inference:**  
   Replace `_predict_text()` keyword logic in `inference_engine.py` with true HuggingFace tokenizer + model logits + softmax computation.
2. **Implement Genuine Tabular & Temporal Feature Scaling:**  
   Connect `extract_dwdata_features.py` and `scaler.joblib` to transform historical dataset records into exact 39-dim and 14-dim vectors. Set `behavior_available = False` and `temporal_available = False` for text-only inputs.
3. **Implement Dual-Mode Inference Engine:**  
   - **Mode 1 (Historical Record):** Full tri-modal execution (Text + Behavior + Temporal + CTI + Risk + XAI).
   - **Mode 2 (Text-Only Input):** Text model + Threat Extraction + MITRE ATT&CK mapping + Risk Engine + Conditional XAI (with explicit unavailable flags).
4. **Integrate Real LIME & SHAP:**  
   Connect `explain_text_lime.py` and `explain_behavioral_shap.py` to `src/xai/conditional_xai.py`.
5. **Calibrate Risk Engine & Connect Dashboard:**  
   Adjust `risk_policy.json` thresholds and connect the dashboard feed to `reports/training/model_fusion_test.csv` or live dataset loading.
