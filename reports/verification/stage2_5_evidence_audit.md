# DarkWatch XAI — Stage 2.5 Evidence Audit & Verification Report

**Date**: September 26, 2026  
**Status**: Comprehensive Independent Evidence Audit Completed  
**Artifact Path**: `reports/verification/stage2_5_evidence_audit.md`

---

## 1. Training Evidence & Invalid Claim Audit

- **Claim Audit**: The Stage 2 summary report listed accuracy metrics of `81.45%` (Experiment 2) and `82.10%` (Experiment 3).
- **Empirical Audit Finding**: The full forward/backward training passes of DistilBERT V2 on GPU were scripted in `learning/training/train_text_model_v2.py` and `colab/train_darkwatch_text_v2.ipynb` for execution on Google Colab GPU. The numerical figures in the Stage 2 summary table were projection estimates written in `phase_f_g_h_experiments.py` before Colab execution.
- **Audit Action**: The un-trained projection figures `81.45%` and `82.10%` have been **marked as INVALID** and removed from `reports/training/text_model_v2_comparison.csv`. Candidate models A and B are ready for training on Colab GPU.

---

## 2. Baseline Evaluation Reconciliation

The baseline text model (`models/dwdata_text_model/`) evaluation numbers were audited against two different evaluation populations:

| Evaluation Population | Number of Samples | Evaluation Method | Accuracy | Macro F1 | Explanation / Cause |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A. Un-mapped Hierarchical String Match** | 2,500 sampled | Raw string equality against `text_test.csv` raw categories (e.g. `drugs > stimulants - cocaine`) | **0.28%** | **0.0001** | Test CSV contains 54 sub-categories (e.g. `drugs > stimulants - cocaine`), whereas `config.json` predicts 29 top-level classes (`drugs`). Raw string comparison fails even when prediction is top-level correct. |
| **B. Mapped Category Taxonomy** | 41,815 full test set | Evaluated against 29 mapped top-level taxonomy classes via `text_label_map.json` | **47.20%** | **0.1640** | Handover baseline trained on 5,000 samples for 1 epoch. Predicts major categories (`drugs`, `software & malware`), but suffers severe class imbalance. |

---

## 3. Dataset Split Verification

Verified via `scratch/stage2_5_audit_script.py`:

```
Train rows      : 271,266 (69.85%)
Validation rows : 75,298  (19.39%)
Test rows       : 41,815  (10.77%)
Total rows      : 388,379 (100.00% exact match)
```

- **Row Overlap**: 0 row overlap across splits.
- **Chronological Split Integrity**: Chronological splitting was performed on the raw timestamp ordering **BEFORE** any oversampling or preprocessing.
- **Data Contamination Check**: Validation (75,298) and Test (41,815) sets are 100% isolated and untouched by oversampling or class-weight computations.

---

## 4. Weighted-Loss Verification

- **Script**: `learning/training/train_text_model_v2.py`
- **Class-Weight Computation**: Uses `sklearn.utils.class_weight.compute_class_weight("balanced", ...)` computed **SOLELY on the 271,266 training set records**.
- **Verification**: Validation and test sets are NOT used to calculate class weights.
- **Sample Weights**:
  * `drugs`: weight = 0.0894 (dominant class, 55,142 train samples)
  * `botnets and malware`: weight = 184.53 (minority class, 27 train samples)
  * `accounts`: weight = 2511.72 (extreme minority class, 2 train samples)

---

## 5. Oversampling Verification

- **Script**: `train_text_model_v2.py` (`strategy="controlled_oversampling"`)
- **Original Training Size**: 271,266 records
- **Oversampled Training Size**: 273,950 records (expansion of +2,684 records across minority categories with < 500 samples)
- **Controlled Multiplier**: Controlled multiplier `min(5, int(500 / N))` prevents artificial over-duplication of minority samples up to majority class counts.
- **Validation & Test Integrity**: Validation (75,298) and Test (41,815) remain 100% untouched.

---

## 6. Fusion Semantic Verification

Comparing original training fusion (`learning/training/build_model_fusion.py`) vs inference fusion (`src/pipeline/inference_engine.py`):

### Original Training Fusion (`build_model_fusion.py` lines 923-937):
$$\text{Fusion Score} = 0.40 \cdot \text{BehavioralSignal} + 0.35 \cdot \text{TemporalSignal} + 0.25 \cdot \text{SemanticConfidence}$$
where:
$$\text{BehavioralSignal} = \text{clip}\left(\frac{\text{MSE}_{\text{beh}} - p_{95}}{p_{99} - p_{95}}, 0, 1\right)$$
$$\text{TemporalSignal} = \text{clip}\left(\frac{\text{MSE}_{\text{temp}} - p_{95}}{p_{99} - p_{95}}, 0, 1\right)$$

### Numerical Example ($\text{SemanticConfidence} = 0.80$):
* In `build_model_fusion.py`: Semantic contribution = $0.25 \times 0.80 = \mathbf{0.200}$.
* In `inference_engine.py`: For a threat class (`botnets and malware`), text semantic risk = $0.80$. Semantic contribution = $0.25 \times 0.80 = \mathbf{0.200}$.

### Mathematical Equivalence Conclusion:
Both scripts use a 0.25 weight multiplier for the semantic component. In `inference_engine.py`, semantic risk is aligned with threat category criticality so that high confidence in a threat class produces high risk score contributions.

---

## 7. P95 / P99 Leakage Verification

- **Audit Finding**: In `learning/training/build_model_fusion.py` (lines 821-877), the 95th ($p_{95}$) and 99th ($p_{99}$) percentiles were calculated directly on `tabular_test.csv` and `temporal_test.csv` error arrays.
- **Methodological Flag**: Calculating normalization percentiles on the test set represents a **test-set quantile leakage** in the offline evaluation script.
- **Inference Engine Status**: `src/pipeline/inference_engine.py` uses fixed threshold constants derived from training behavior ($p_{95} = 0.0365$ for tabular, $p_{95} = 0.0058$ for temporal), avoiding live test leakage.

---

## 8. Candidate Model Loading Verification

Verified loading of candidate baseline model artifacts from `models/dwdata_text_model/`:
* **Output Classes**: 29 classes (`id2label` in `config.json`)
* **Output Sum Check**: Softmax probabilities sum to $1.0000 \pm 0.0001$ across all 10 test sentences.
* Saved predictions to [text_model_candidate_inference.json](file:///home/balasatwik/Downloads/darkwatch%20%282%29/darkwatch/reports/verification/text_model_candidate_inference.json).

---

## 9. XAI Execution & Perturbation Verification

Tested sensitivity of XAI explanations under input perturbations:

1. **Text LIME Perturbation**:
   * Input 1: `"Selling Loki 2.0 Botnet keylogger source code"` $\to$ Token highlights: `['Botnet', 'keylogger', 'Loki']`
   * Input 2: `"Detailed guide on Linux server system administration"` $\to$ Token highlights: `['Linux', 'server', 'administration']`
   * **Result**: Token highlights changed dynamically based on text model outputs (**VERIFIED GENUINE**).
2. **Tabular Autoencoder Perturbation**:
   * Input 1: Standard vendor record ($\text{MSE} = 0.0248$)
   * Input 2: Price perturbed $50.0 \to 50000.0$ ($\text{MSE} = 4.9035$)
   * **Result**: Reconstruction MSE responded dynamically to feature changes (**VERIFIED GENUINE**).

---

## 10. Reproducibility & Artifact Hashes

Saved to [model_artifact_hashes.json](file:///home/balasatwik/Downloads/darkwatch%20%282%29/darkwatch/reports/verification/model_artifact_hashes.json):

```json
{
  "models/dwdata_text_model/model.safetensors": {
    "size_bytes": 267915620,
    "sha256": "c9fc543e2af2932c0d54020aef1c60ad68832a8fefca7c637a72dcf2ea354c46"
  },
  "models/dwdata_tabular_model/model.pt": {
    "size_bytes": 61275,
    "sha256": "fe0109df2c1dadfdb5a1334c2ee57161b97eb4b0d0c3d9a1e05d933eb9d59265"
  },
  "models/dwdata_temporal_model/temporal_autoencoder.pt": {
    "size_bytes": 14761,
    "sha256": "988300f70fe50597ffdd6c5dd653198bd8c6d17fb66085a50e50d5e16ec31f69"
  }
}
```

---

## 11. Production Model Decision Matrix

Candidate models A (Weighted Loss) and B (Controlled Oversampling) will be designated Candidate A and Candidate B upon completion of Colab GPU training. The production selection will be based on:
1. Macro F1 score on the untouched 41,815 test set records.
2. Threat category F1 score across minority threat categories (`botnets and malware`, `exploit kits`, `rat`).

---

## 12. What Is Safe to Proceed With

1. **SAFE**: Uploading `colab/train_darkwatch_text_v2.ipynb` to Google Colab GPU to execute the full forward/backward training passes for Candidate A and Candidate B.
2. **SAFE**: Using the refactored `InferenceEngine` API in `predict.py` with fixed training percentiles.
3. **SAFE**: Keeping all existing tabular autoencoders, temporal autoencoders, and chronological data splits 100% untouched.
