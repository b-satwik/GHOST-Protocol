# DarkWatch XAI — Stage 2 Verification Report

**Date**: September 25, 2026  
**Status**: Empirical Verification Completed  
**Artifact**: `reports/verification/stage2_verification.md`

---

## 1. Executive Verification Summary

An empirical, code-level audit was conducted across the pre-trained weights, configuration files, feature scalers, training scripts (`learning/training/`), and inference code (`src/pipeline/`).

| Component | Training Script | Model Artifact Path | Saved Architecture | Feature Dimension | Verification Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Text Model** | `train_text_model.py` | `models/dwdata_text_model/` | HuggingFace `DistilBertForSequenceClassification` | 29 Output Classes (`id2label`) | **VERIFIED** |
| **Tabular Model** | `train_tabular_model.py` | `models/dwdata_tabular_model/model.pt` | PyTorch Autoencoder (`Linear(39,78) -> (78,39) -> (39,19) -> (19,39) -> (39,78) -> (78,39)`) | 39 Features (exact order verified) | **VERIFIED** |
| **Temporal Model** | `train_temporal_model.py` | `models/dwdata_temporal_model/temporal_autoencoder.pt` | PyTorch Autoencoder (`Linear(14,32) -> (32,16) -> (16,8) -> (8,16) -> (16,32) -> (32,14)`) | 14 Features (exact order verified) | **VERIFIED** |

---

## 2. Component-by-Component Audit Details

### A. Text Model Pipeline Status
- **Saved Model**: DistilBERT sequence classifier saved at `models/dwdata_text_model/model.safetensors` (268 MB).
- **Vocab & Labels**: `vocab_size = 30522`, `id2label` mapping contains 29 semantic classes.
- **Handover Discrepancy Verified**: The existing text model was trained on a 5,000-row subset for only 1 epoch, resulting in severe class imbalance and low balanced accuracy (~16%). It is loadable and functional in PyTorch/Transformers, but requires full retraining on the 388k dataset.

### B. Tabular Model Pipeline Status
- **Architecture**: PyTorch 6-layer MLP Autoencoder.
- **Scaler**: `scaler.joblib` (`StandardScaler` fitted on 39 features).
- **Feature Vector Order Verification**:
  - `scaler.feature_names_in_` and `model.pt['features']` match 100% in feature names and exact order (39 features).
  - Feature list: `['price_value', 'rating', 'vendor_rating', 'reputation', 'sold', 'in_stock', 'has_price', 'has_network_indicator', 'text_char_count', 'text_unique_word_count', 'text_avg_word_length', 'text_digit_count', 'text_digit_ratio', 'text_uppercase_count', 'text_uppercase_ratio', 'text_special_char_count', 'text_has_url', 'text_has_ip', 'text_has_crypto_term', 'text_has_malware_term', 'text_has_credential_term', 'text_has_exploit_term', 'category_frequency', 'vendor_listing_count', 'vendor_category_count', 'vendor_marketplace_count', 'vendor_activity_days', 'marketplace_listing_count', 'marketplace_vendor_count', 'price_log1p', 'price_text_length', 'currency_known', 'is_crypto_currency', 'price_is_zero', 'domain_count', 'ip_count', 'email_count', 'total_indicator_count', 'network_indicator_density']`.
  - **No Zero-Filled / Synthetic Vectors**: Mode 1 (historical records) extracts the exact 39 features. Mode 2 (text-only inputs) explicitly sets `behavior_available = False`.

### C. Temporal Model Pipeline Status
- **Architecture**: PyTorch 6-layer MLP Autoencoder (`Linear 14 -> 32 -> 16 -> 8 -> 16 -> 32 -> 14`).
- **Scaler**: `temporal_scaler.npz` (`mean` and `scale` vectors of dimension 14).
- **Feature Columns**: `['price_value', 'vendor_observation_number', 'vendor_previous_observation_gap', 'vendor_listing_count', 'vendor_category_count', 'vendor_marketplace_count', 'vendor_activity_days', 'marketplace_listing_count', 'marketplace_vendor_count', 'total_indicator_count', 'has_network_indicator', 'text_has_malware_term', 'text_has_credential_term', 'text_has_exploit_term']`.

### D. Fusion Mathematical Verification
- **Original Research Implementation (`learning/training/build_model_fusion.py`)**:
  $$\text{Fusion Score} = 0.40 \cdot \text{BehavioralSignal} + 0.35 \cdot \text{TemporalSignal} + 0.25 \cdot \text{SemanticConfidence}$$
  where:
  $$\text{BehavioralSignal} = \text{clip}\left(\frac{\text{MSE}_{\text{tab}} - p_{95}}{p_{99} - p_{95}}, 0, 1\right)$$
  $$\text{TemporalSignal} = \text{clip}\left(\frac{\text{MSE}_{\text{temp}} - p_{95}}{p_{99} - p_{95}}, 0, 1\right)$$
- **Current Inference Engine Implementation (`src/pipeline/inference_engine.py`)**:
  - Dynamically handles missing modalities: for text-only input, weight is renormalized to `1.0 * Text_Semantic_Risk`.
  - For historical multi-modal records, uses $0.40 \cdot \text{MSE}_{\text{beh}} + 0.35 \cdot \text{MSE}_{\text{temp}} + 0.25 \cdot \text{Text\_Semantic\_Risk}$.

### E. Anomaly Score Normalization Audit
- Anomaly thresholds were computed on training reconstruction errors:
  - Tabular: $p_{95} = 0.0365$, $p_{99} = 0.1339$
  - Temporal: $p_{95} = 0.0058$, $p_{99} = 0.0270$
- Raw MSE reconstruction errors below $p_{95}$ represent normal behavioral patterns; errors exceeding $p_{99}$ represent extreme anomalies.

### F. XAI Verification
- **Text XAI**: `explain_text_lime.py` uses `LimeTextExplainer` over DistilBERT.
- **Behavioral XAI**: `explain_behavioral_shap.py` computes feature importance over the Tabular Autoencoder.
- **Temporal XAI**: `explain_temporal.py` computes per-feature reconstruction error contribution.
- **Inference Integration**: `src/xai/conditional_xai.py` dynamically triggers deep LIME/SHAP attributions for high-risk inputs and reports explicit `xai_available: True` status.

### G. Test Suite Quality Audit
- `tests/test_pipeline.py` contains 12 unit and integration tests executing real model inference over PyTorch autoencoders, HuggingFace transformers, CTI extraction, MITRE mapping, risk calculation, and XAI availability (`12 tests in 0.397s: OK`).

---

## 3. Discovered Bugs / Inconsistencies & Fixes

1. **State Dict Key Mismatch in PyTorch Autoencoders**:
   - *Bug*: Old inference script used dummy `Linear(39, 24)` and `Linear(14, 10)` classes, causing `RuntimeError` when loading saved weight checkpoints.
   - *Fix*: Reconstructed exact PyTorch architectures matching the saved `model_state_dict` tensors.
2. **Missing Modality Crashing (`NoneType` in `round()`)**:
   - *Bug*: Passing text-only inputs resulted in `None` anomaly scores, causing `TypeError: type NoneType doesn't define __round__ method` in alert generation.
   - *Fix*: Added null safety in `AlertGenerator` to return `None` for unobserved modalities without throwing exceptions.
3. **MITRE Association Confidence Uniformity**:
   - *Bug*: All keyword matches previously received static `0.80` confidence.
   - *Fix*: Updated `MITREMapper` to distinguish `EXPLICIT_EVIDENCE` (confidence `0.90`) from `WEAK_KEYWORD_ASSOCIATION` (confidence `0.50`).

---

## 4. File Modification Register

### Files Modified
* `src/pipeline/inference_engine.py`
* `src/cti/mitre_mapper.py`
* `src/xai/conditional_xai.py`
* `src/alerts/alert_generator.py`
* `src/config/risk_policy.json`
* `tests/test_pipeline.py`

### Files Remaining Untouched
* `datasets/` (~388,379 Dark Web records)
* `models/dwdata_tabular_model/model.pt` & `scaler.joblib`
* `models/dwdata_temporal_model/temporal_autoencoder.pt` & `temporal_scaler.npz`
* `learning/training/train_tabular_model.py` & `train_temporal_model.py`
* `dashboard/app.py` (scrapped UI isolated)
