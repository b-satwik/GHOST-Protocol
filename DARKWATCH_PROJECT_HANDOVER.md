# DARKWATCH XAI — COMPREHENSIVE PROJECT HANDOVER REPORT

**Project Name:** DarkWatch XAI  
**Analysis Date:** September 25, 2026  
**Analysis Mode:** READ-ONLY / AUDIT ONLY (No files modified, deleted, or retrained)  
**Handover Context:** Transfer of ownership from Someshekar to incoming team member  

---

## PART 1 — PROJECT STRUCTURE

Below is the complete file and folder hierarchy found under the project root `/home/balasatwik/Downloads/darkwatch (2)/darkwatch`:

```
darkwatch/
├── data/
│   ├── raw/
│   │   ├── DWData-master/                [Dark web marketplace dump CSVs from 2021-2024]
│   │   ├── DWData_inventory/             [Inventory text files for raw CSVs]
│   │   ├── surface_cti.csv               [Surface web network traffic CTI dataset]
│   │   └── safe_corpus.json              [Benign text corpus]
│   └── processed/
│       ├── dwdata_optimized.csv          [Normalized dark web listings dataset]
│       ├── dwdata_features.csv           [Engineered feature dataset]
│       └── training/
│           ├── tabular_train.csv         [70% Train split - Tabular features]
│           ├── tabular_validation.csv    [20% Val split - Tabular features]
│           ├── tabular_test.csv          [10% Test split - Tabular features]
│           ├── text_train.csv            [70% Train split - Text & Semantic Labels]
│           ├── text_validation.csv       [20% Val split - Text & Semantic Labels]
│           ├── text_test.csv             [10% Test split - Text & Semantic Labels]
│           ├── text_test_balanced.csv    [150-sample balanced test set]
│           ├── temporal_train.csv        [70% Train split - Temporal features]
│           ├── temporal_validation.csv   [20% Val split - Temporal features]
│           ├── temporal_test.csv         [10% Test split - Temporal features]
│           ├── tabular_features.json     [List of 50 tabular feature names]
│           ├── text_label_map.json       [29 semantic class label mappings]
│           └── training_data_summary.json[Dataset split record summary]
├── preprocessing/
│   ├── normalize_dwdata.py               [Raw data schema mapping & normalization script]
│   ├── extract_dwdata_features.py        [Feature engineering & semantic labeling script]
│   └── prepare_dwdata_model.py           [Feature selection, missingness & sanity checks]
├── preprocessing_codes/                  [EMPTY DIRECTORY - Unused / Legacy]
├── learning/
│   └── training/
│       ├── prepare_training_data.py      [Chronological time-safe dataset splitting script]
│       ├── train_text_model.py           [DistilBERT text classifier training script]
│       ├── train_tabular_model.py        [Tabular behavioral Autoencoder training script]
│       ├── train_temporal_model.py       [Temporal Autoencoder training script]
│       ├── build_model_fusion.py         [Tri-modal weighted risk fusion script]
│       ├── analyze_text_model.py         [Text model classification error & confusion matrix script]
│       ├── create_balanced_test.py       [Balanced 150-sample test set creation script]
│       ├── evaluate_balanced_text.py     [Evaluation script for balanced text test set]
│       ├── investigate_tabular_shift.py  [Distribution shift investigation script]
│       ├── intelligence_correlation.py   [Cross-modal intelligence correlation script]
│       ├── explain_text_lime.py          [LIME text feature attribution script]
│       ├── explain_behavioral_shap.py    [SHAP tabular feature attribution script]
│       ├── explain_temporal.py           [Reconstruction-based temporal feature attribution script]
│       └── explain_fusion.py             [Unified tri-modal XAI explanation script]
├── models/
│   ├── dwdata_text_model/
│   │   ├── config.json                   [DistilBERT model config]
│   │   ├── model.safetensors             [DistilBERT fine-tuned model weights (268 MB)]
│   │   ├── tokenizer.json                [Tokenizer vocabulary & config]
│   │   └── tokenizer_config.json         [Tokenizer parameters]
│   ├── dwdata_tabular_model/
│   │   ├── model.pt                      [Tabular Autoencoder PyTorch state_dict (6.5 KB)]
│   │   ├── scaler.joblib                 [StandardScaler object for tabular features]
│   │   └── features.json                 [List of 39 input feature names]
│   ├── dwdata_temporal_model/
│   │   ├── temporal_autoencoder.pt       [Temporal Autoencoder PyTorch state_dict (2.6 KB)]
│   │   ├── temporal_scaler.npz           [Numpy mean & scale arrays for temporal features]
│   │   └── temporal_features.json        [List of 14 temporal feature names]
│   ├── dwdata_fusion/                    [Fusion output directory containing JSON configs]
│   ├── checkpoints/                      [EMPTY DIRECTORY - Unused intermediate checkpoints]
│   └── tokenizers/                       [Directory structure for tokenizer cache]
├── reports/
│   ├── dwdata_schema_mapping.csv         [Mapping report for raw marketplace columns]
│   ├── dwdata_normalization_report.csv   [Summary of raw data normalization]
│   ├── dwdata_feature_report.csv         [Summary of engineered features]
│   ├── dwdata_model_feature_report.csv   [Feature selection reasoning & status report]
│   ├── dwdata_time_safe_report.csv       [Time-safe dataset splitting statistics]
│   ├── dwdata_learning_summary.txt       [Executive text summary of learning pipeline]
│   ├── training/
│   │   ├── text_model_metrics.json       [Evaluation metrics for DistilBERT on test.csv]
│   │   ├── text_confusion_matrix.csv     [Confusion matrix for DistilBERT on test.csv]
│   │   ├── balanced_text_metrics.json    [Evaluation metrics on balanced 150 test set]
│   │   ├── balanced_text_confusion_matrix.csv [Confusion matrix on balanced test set]
│   │   ├── tabular_model_metrics.json    [Evaluation metrics for Tabular Autoencoder]
│   │   ├── tabular_training_history.json [Epoch-by-epoch loss history for Tabular Autoencoder]
│   │   ├── tabular_distribution_shift_report.csv [Distribution shift analysis per feature]
│   │   ├── tabular_standardized_shift_report.csv [Standardized feature drift report]
│   │   ├── tabular_test_anomaly_scores.csv [Per-record anomaly scores for tabular test set]
│   │   ├── tabular_extreme_test_features.csv [Top anomalous test feature values]
│   │   ├── temporal_model_metrics.json   [Evaluation metrics for Temporal Autoencoder]
│   │   ├── temporal_training_history.csv [Epoch-by-epoch loss history for Temporal Autoencoder]
│   │   ├── temporal_test_scores.csv      [Per-record anomaly scores for temporal test set]
│   │   ├── model_fusion_summary.json     [Fusion risk distribution and threshold summary]
│   │   ├── model_fusion_test.csv         [Per-record tri-modal risk scores and fusion bands]
│   │   ├── intelligence_correlation.csv [Cross-modal score correlation matrix]
│   │   ├── intelligence_correlation_summary.csv [Summary of cross-modal correlation]
│   │   └── intelligence_global_xai_evidence.txt [Textual summary of global XAI findings]
│   └── xai/
│       ├── text_lime_summary.csv         [LIME explanation summary for text model]
│       ├── text_lime_cases.csv           [Selected text case predictions and explanations]
│       ├── text_lime_tokens.csv          [Per-token LIME attribution weights]
│       ├── behavioral_shap_summary.csv   [SHAP explanation summary for tabular model]
│       ├── behavioral_shap_cases.csv     [Selected tabular case predictions and SHAP values]
│       ├── behavioral_feature_importance.csv [Global SHAP feature importance rankings]
│       ├── temporal_xai_summary.csv      [Temporal attribution summary]
│       ├── temporal_xai_cases.csv        [Selected temporal case explanations]
│       ├── temporal_xai_features.csv     [Global temporal feature attribution rankings]
│       ├── unified_xai_summary.csv       [Unified XAI coverage summary across modalities]
│       └── unified_xai_explanations.csv  [Per-case multi-modal combined XAI narratives]
└── dashboard/                            [EMPTY DIRECTORY - UI/Frontend NOT started]
```

### File & Folder Categorization Table

| File / Folder | Category | Purpose / Description | Usage Status |
| :--- | :--- | :--- | :--- |
| `data/raw/DWData-master/` | INPUT | 54+ CSV dumps from 15+ darknet marketplaces (2021-2024) | ACTIVE |
| `data/raw/surface_cti.csv` | INPUT | Surface web CICFlowMeter network traffic CTI dataset (158k rows) | UNUSED in model training |
| `data/raw/safe_corpus.json` | INPUT | 2,000 JSON lines of benign text | UNUSED in model training |
| `data/processed/dwdata_optimized.csv` | PROCESSING | Cleaned & normalized dataset (388,379 rows x 31 cols) | ACTIVE |
| `data/processed/dwdata_features.csv` | PROCESSING | Engineered features dataset (388,379 rows x 73 cols) | ACTIVE |
| `data/processed/training/` | INPUT TO MODEL | Chronologically split train/val/test CSVs & JSON mappings | ACTIVE |
| `preprocessing/*.py` | PROCESSING | Core ETL scripts (normalization, feature extraction, selection) | ACTIVE |
| `preprocessing_codes/` | PROCESSING | Empty directory | UNUSED (Legacy placeholder) |
| `learning/training/*.py` | MODEL / XAI | 14 scripts for training, evaluation, analysis, and XAI generation | ACTIVE |
| `models/dwdata_text_model/` | MODEL | Fine-tuned DistilBERT model weights (safetensors), config & tokenizer | ACTIVE |
| `models/dwdata_tabular_model/` | MODEL | Tabular Autoencoder PyTorch model, StandardScaler & feature list | ACTIVE |
| `models/dwdata_temporal_model/` | MODEL | Temporal Autoencoder PyTorch model, scaler & feature list | ACTIVE |
| `models/dwdata_fusion/` | MODEL | Directory containing fusion configs & outputs | ACTIVE |
| `models/checkpoints/` | MODEL | Empty directory for intermediate training checkpoints | UNUSED |
| `reports/` | OUTPUT | Evaluation JSONs, confusion matrices, shift reports, XAI CSVs | ACTIVE |
| `dashboard/` | DEPLOYMENT | Empty directory intended for web app / dashboard | UNUSED (Not started) |

---

## PART 2 — DATASETS

Below is the verified breakdown of every dataset found in the repository. All row/column counts, missing values, duplicates, and class distributions have been computed directly from the actual files.

### 1. Dark Web Marketplace Listings (`DWData-master`)
- **Original Source:** DWData GitHub repository (historical dark web market scrapes from 2021 to 2024 across markets like AlphaBay, Darkode, Tor2Door, White House Market, Abacus, Nemesis, Kingdom, Bohemia, ASAP, MGM Grand, etc.).
- **Local Path:** `data/raw/DWData-master/`
- **File Type:** CSV (54+ separate CSV files across historical date folders).
- **Number of Rows:** 388,379 total raw rows.
- **Number of Columns:** 4 to 6 columns depending on marketplace export format (mapped to standard schema: `vendor`, `title/name`, `category`, `price`, `rating`).
- **Target / Label Column:** Unlabeled in raw state; heuristically mapped to 29 semantic categories in `extract_dwdata_features.py`.
- **Duplicates & Missing Values:** High raw duplicate count (~15-30% depending on marketplace scrape overlap). Missing values present in raw ratings/prices.
- **Preprocessing & Cleaning:** Fully normalized into `data/processed/dwdata_optimized.csv` and feature-engineered into `dwdata_features.csv`.
- **Splitting:** Chronological time-safe split: 70% Train (271,266), 20% Validation (75,298), 10% Test (41,815).
- **Status:** **ACTIVE / COMPLETED PIPELINE**.

### 2. Surface Web Network CTI (`surface_cti.csv`)
- **Original Source:** CICFlowMeter network traffic dataset (Surface web threat intelligence / traffic capturing).
- **Local Path:** `data/raw/surface_cti.csv`
- **File Type:** CSV (73.3 MB)
- **Number of Rows:** 158,616 rows
- **Number of Columns:** 85 columns (Network flow metrics: `Flow Duration`, `Total Fwd Packet`, `Dst Port`, etc.)
- **Target / Label Column:** `Label`
- **Number of Classes:** 4 classes
- **Class Distribution:** `Non-Tor`: 110,442, `NonVPN`: 23,863, `VPN`: 22,919, `Tor`: 1,392
- **Missing Values:** 48 missing values
- **Duplicate Rows:** 39,004 duplicates
- **Status:** **PARTIALLY FOUND / UNUSED IN TRAINING**. Present in `data/raw/`, but never merged, processed, or fed into any model in `learning/training/`.

### 3. Safe Benign Corpus (`safe_corpus.json`)
- **Local Path:** `data/raw/safe_corpus.json`
- **File Type:** JSON Lines (365 KB)
- **Number of Samples:** 2,000 JSON lines
- **Status:** **UNUSED IN TRAINING**. Present in `data/raw/`, but not included in model training pipeline.

### 4. Processed Model-Ready Datasets (`data/processed/training/`)
- **Tabular Features Dataset (`tabular_*.csv`):**
  - Columns: 50 columns (39 input features + 11 evidence/metadata columns).
  - Split Sizes: Train = 271,266 | Val = 75,298 | Test = 41,815.
  - Preprocessing: Imputed missing values with median, removed 10 constant features, removed 6 redundant correlated features, StandardScaler normalized.
- **Text & Semantic Category Dataset (`text_*.csv`):**
  - Columns: 2 columns (`text`, `semantic_label`).
  - Target Column: `semantic_label` (29 classes: `OTHER_SEMANTIC`, `drugs`, `malware`, `botnets and malware`, `cracked`, `cvv & cards`, `accounts & bank drops`, etc.).
  - Class Imbalance: Extremely imbalanced (`OTHER_SEMANTIC` represents ~93.8% of the dataset; rare classes like `ransomware` or `zero-day` have under 100 samples).
  - Subsampling in Training: Someshekar subsampled only 5,000 training records, 1,000 validation records, and 1,000 test records for DistilBERT training due to CPU compute limits.
- **Balanced Text Evaluation Dataset (`text_test_balanced.csv`):**
  - Path: `data/processed/training/text_test_balanced.csv`
  - Rows: 150 rows (30 per class across 5 categories: `drugs`, `malware`, `botnets and malware`, `cracked`, `OTHER_SEMANTIC`). Created by `create_balanced_test.py`.
- **Temporal Features Dataset (`temporal_*.csv`):**
  - Columns: 14 features (`price_value`, `vendor_observation_number`, `vendor_previous_observation_gap`, `vendor_activity_days`, `total_indicator_count`, etc.).
  - Split Sizes: Train = 271,266 | Val = 75,298 | Test = 41,815.

### Comprehensive Dataset Summary Table

| Dataset | File Path | Rows | Cols | Classes | Top Class Distribution | Used For | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DWData Raw** | `data/raw/DWData-master/...` | 388,379 | 4-6 | N/A | Raw market dumps (2021-2024) | Raw input ETL | **FOUND / USED** |
| **Surface CTI** | `data/raw/surface_cti.csv` | 158,616 | 85 | 4 | Non-Tor: 110,442, NonVPN: 23,863, VPN: 22,919, Tor: 1,392 | Unmerged raw asset | **FOUND / UNUSED** |
| **Safe Corpus** | `data/raw/safe_corpus.json` | 2,000 | N/A | N/A | Benign text records | Unmerged raw asset | **FOUND / UNUSED** |
| **DW Optimized** | `data/processed/dwdata_optimized.csv` | 388,379 | 31 | 29 | Normalized dark web listings | Intermediate ETL | **FOUND / USED** |
| **DW Features** | `data/processed/dwdata_features.csv` | 388,379 | 73 | 29 | Engineered multi-modal features | Intermediate ETL | **FOUND / USED** |
| **Tabular Train** | `data/processed/training/tabular_train.csv` | 271,266 | 50 | N/A | 39 numerical/behavioral features | Tabular Autoencoder train | **FOUND / USED** |
| **Tabular Val** | `data/processed/training/tabular_validation.csv` | 75,298 | 50 | N/A | 39 numerical/behavioral features | Tabular Autoencoder val | **FOUND / USED** |
| **Tabular Test** | `data/processed/training/tabular_test.csv` | 41,815 | 50 | N/A | 39 numerical/behavioral features | Tabular Autoencoder test | **FOUND / USED** |
| **Text Train** | `data/processed/training/text_train.csv` | 271,266 | 2 | 29 | OTHER_SEMANTIC: ~93.8% | Text Classifier train (5k sample) | **FOUND / PARTIAL** |
| **Text Val** | `data/processed/training/text_validation.csv` | 75,298 | 2 | 29 | OTHER_SEMANTIC: ~93.8% | Text Classifier val (1k sample) | **FOUND / PARTIAL** |
| **Text Test** | `data/processed/training/text_test.csv` | 41,815 | 2 | 29 | OTHER_SEMANTIC: ~93.8% | Text Classifier test (1k sample) | **FOUND / PARTIAL** |
| **Text Balanced**| `data/processed/training/text_test_balanced.csv`| 150 | 2 | 5 | 30 per class (5 classes) | Balanced model evaluation | **FOUND / USED** |
| **Temporal Train**| `data/processed/training/temporal_train.csv` | 271,266 | 14 | N/A | 14 temporal/vendor features | Temporal Autoencoder train | **FOUND / USED** |
| **Temporal Val** | `data/processed/training/temporal_validation.csv`| 75,298 | 14 | N/A | 14 temporal/vendor features | Temporal Autoencoder val | **FOUND / USED** |
| **Temporal Test**| `data/processed/training/temporal_test.csv` | 41,815 | 14 | N/A | 14 temporal/vendor features | Temporal Autoencoder test | **FOUND / USED** |

---

## PART 3 — OUR EXPECTED DATASET SOURCES

Checking specifically against the 7 expected data sources:

1. **Darknet/Dark Web posts dataset:** **FOUND**.  
   - *File/Path:* `data/raw/DWData-master/` & `data/processed/dwdata_optimized.csv`  
   - *Sample Count:* 388,379 rows across 54+ CSVs from 15+ marketplaces.  
   - *Usage:* Primary source for all tabular, text, and temporal feature engineering and training.  
   - *Included in Training:* YES.

2. **Vectored/VECTOR cyber-threat dataset:** **NOT FOUND**.  
   - *Status:* Missing. No file, code reference, or mention in scripts.

3. **Cyber threat intelligence dataset:** **PARTIALLY FOUND**.  
   - *File/Path:* `data/raw/surface_cti.csv`  
   - *Sample Count:* 158,616 rows (85 network flow metrics).  
   - *Usage:* None.  
   - *Included in Training:* NO. Unmerged in `data/raw/`.

4. **CyberBERT-related dataset/model:** **NOT FOUND**.  
   - *Status:* Missing. The project used `distilbert-base-uncased` instead of CyberBERT.

5. **Any Reddit/social-media-style cybersecurity posts:** **NOT FOUND**.  
   - *Status:* Missing. No Reddit or social media scrapers or data present.

6. **Any darknet website/forum data:** **FOUND**.  
   - *File/Path:* `data/raw/DWData-master/` (Marketplace listings: AlphaBay, Darkode, Tor2Door, Whitehouse, Abacus, etc.).  
   - *Included in Training:* YES.

7. **Any additional dataset that was added later:** **FOUND**.  
   - *File/Path:* `data/raw/safe_corpus.json` (2,000 JSON lines of benign text).  
   - *Included in Training:* NO. Present in raw data, but unused in model training.

---

## PART 4 — DATA PROCESSING PIPELINE

The complete data processing flow was successfully traced through the Python scripts:

```
RAW DATA (DWData-master CSVs)
   ↓
[preprocessing/normalize_dwdata.py]
   • Schema mapping, price/currency normalization, date parsing, missingness handling
   ↓ Output: data/processed/dwdata_optimized.csv (388,379 rows, 31 cols)
   ↓
[preprocessing/extract_dwdata_features.py]
   • 73 engineered features: IOC extraction (IPs, domains, emails, hashes), vendor history stats, 
     temporal gap metrics, keyword matches (malware, credentials, exploits), semantic labeling (29 classes)
   ↓ Output: data/processed/dwdata_features.csv (388,379 rows, 73 cols)
   ↓
[preprocessing/prepare_dwdata_model.py]
   • Removes 10 constant features & 6 correlated redundant features
   • Imputes missing numeric values using median
   • Retains 39 model features + 11 evidence metadata fields
   ↓ Output: data/processed/training/tabular_features.json
   ↓
[learning/training/prepare_training_data.py]
   • Performs strict chronological time-safe split based on snapshot_date:
     - Train: 70% (271,266 rows) [Dates up to mid-2022]
     - Validation: 20% (75,298 rows) [Mid-2022 to early-2023]
     - Test: 10% (41,815 rows) [Late-2023 to 2024]
   • Outputs modal sub-datasets for Text, Tabular, and Temporal models
   ↓ Output: data/processed/training/*.csv & training_data_summary.json
```

**Final Preprocessing Pipeline Version:** The scripts in `preprocessing/` (`normalize_dwdata.py` -> `extract_dwdata_features.py` -> `prepare_dwdata_model.py` -> `learning/training/prepare_training_data.py`) form the active, final pipeline. (`preprocessing_codes/` is empty and obsolete).

---

## PART 5 — MODEL TRAINING

Someshekar designed and implemented a **Tri-Modal Architecture** consisting of three specialized neural models and one fusion module.

### Model 1: Text Semantic Classifier (`dwdata_text_model`)
- **Base / Architecture:** Pretrained `distilbert-base-uncased` (Sequence Classification Head, 29 output classes).
- **Parameters:** ~66 Million.
- **Input Format:** Raw text string (`listing_name` / title).
- **Output Classes:** 29 semantic category IDs mapped in `text_label_map.json`.
- **Training Dataset:** Subsampled `text_train.csv` (5,000 samples out of 271,266).
- **Validation / Test Dataset:** 1,000 samples each (subsampled from full val/test sets).
- **Epochs:** 1 epoch.
- **Batch Size:** 16 (train), 32 (eval).
- **Learning Rate:** 2e-5 (AdamW optimizer, PyTorch, HuggingFace Trainer style loop).
- **Loss Function:** CrossEntropyLoss.
- **Max Sequence Length:** 128 tokens.
- **Execution Device:** CPU (`device: cpu`).
- **Completion Status:** **COMPLETED FOR 1 EPOCH ON 5K SAMPLES**, but **INCOMPLETE / UNDERTRAINED** with respect to the full 271k dataset (trained on only ~1.8% of available training data for just 1 epoch).
- **Artifact Location:** `models/dwdata_text_model/model.safetensors` (268 MB).

### Model 2: Tabular Behavioral Autoencoder (`dwdata_tabular_model`)
- **Architecture:** PyTorch MLP Autoencoder.
  - Encoder: `Linear(39 -> 24) -> ReLU -> Linear(24 -> 12) -> ReLU`
  - Decoder: `Linear(12 -> 24) -> ReLU -> Linear(24 -> 39) -> Sigmoid`
- **Input Format:** 39 standardized numerical/behavioral features (`StandardScaler`).
- **Output:** Reconstructed 39 features (Anomaly score = Reconstruction MSE Loss).
- **Training Samples:** 271,266 full train split.
- **Validation / Test Samples:** 75,298 val | 41,815 test.
- **Epochs:** 28 epochs (Early stopping triggered after patience=5; best validation loss at epoch 22).
- **Batch Size:** 256.
- **Learning Rate:** 1e-3 (Adam optimizer).
- **Loss Function:** MSELoss.
- **Execution Device:** CPU.
- **Completion Status:** **FULLY COMPLETED**.
- **Artifact Location:** `models/dwdata_tabular_model/model.pt` (6.5 KB) & `scaler.joblib` (2.8 KB).

### Model 3: Temporal Autoencoder (`dwdata_temporal_model`)
- **Architecture:** PyTorch MLP Autoencoder.
  - Encoder: `Linear(14 -> 10) -> ReLU -> Linear(10 -> 6) -> ReLU`
  - Decoder: `Linear(6 -> 10) -> ReLU -> Linear(10 -> 14) -> Sigmoid`
- **Input Format:** 14 temporal & vendor activity dynamics features (`MinMaxScaler` 0-1).
- **Output:** Reconstructed 14 features (Anomaly score = Reconstruction MSE Loss).
- **Training Samples:** 271,266 full train split.
- **Validation / Test Samples:** 75,298 val | 41,815 test.
- **Epochs:** 40 epochs (Full training run completed).
- **Batch Size:** 256.
- **Learning Rate:** 1e-3 (Adam optimizer).
- **Loss Function:** MSELoss.
- **Execution Device:** CPU.
- **Completion Status:** **FULLY COMPLETED**.
- **Artifact Location:** `models/dwdata_temporal_model/temporal_autoencoder.pt` (2.6 KB) & `temporal_scaler.npz` (1.0 KB).

### Model 4: Tri-Modal Risk Fusion Module (`dwdata_fusion`)
- **Architecture:** Rule-based Weighted Decision Fusion.
  - Formula: $\text{Fusion Score} = 0.40 \times \text{BehavioralScore} + 0.35 \times \text{TemporalScore} + 0.25 \times (1 - \text{SemanticConfidence})$
- **Inputs:** Reconstructed anomaly scores from Tabular & Temporal autoencoders + DistilBERT prediction confidence.
- **Risk Bands:** `LOW` ($<0.30$), `MODERATE` ($0.30 - 0.50$), `ELEVATED` ($0.50 - 0.70$), `HIGH` ($>0.70$).
- **Completion Status:** **FULLY COMPLETED**. Evaluated on 41,815 test records.
- **Artifact Location:** `models/dwdata_fusion/` & `reports/training/model_fusion_summary.json`.

---

## PART 6 — TRAINING RESULTS / SCORES

All metrics below have been extracted **VERIFIED** directly from the JSON and CSV report files in `reports/training/`:

### 1. Text Semantic Classifier (`distilbert-base-uncased`)
- **Evaluated on Unbalanced Test Set (1,000 samples, 29 classes):**
  - **Test Loss:** 2.05395 (VERIFIED — `text_model_metrics.json`)
  - **Accuracy:** 47.0% (0.4700) (VERIFIED)
  - **Macro Precision:** 92.07% (0.9207) (VERIFIED)
  - **Recall:** 47.0% (0.4700) (VERIFIED)
  - **Weighted F1:** 0.6198 (VERIFIED)
  - *Diagnosis from `text_confusion_matrix.csv`:* The model predicts `OTHER_SEMANTIC` for 938 out of 1,000 test cases because 93.8% of training data belonged to `OTHER_SEMANTIC`. It fails to detect minority threat classes like `malware` or `cracked`.
- **Evaluated on Balanced Test Set (150 samples across 5 categories):**
  - **Accuracy:** 16.0% (0.1600) (VERIFIED — `balanced_text_metrics.json`)
  - **Macro Precision:** 0.0896 (VERIFIED)
  - **Macro Recall:** 0.1333 (VERIFIED)
  - **Macro F1:** 0.1023 (VERIFIED)
  - **Weighted F1:** 0.1228 (VERIFIED)
  - *Note:* This confirms severe underfitting / class imbalance failure on minority categories.

### 2. Tabular Behavioral Autoencoder
- **Best Validation Loss:** 0.037586 (VERIFIED — `tabular_model_metrics.json`, Epoch 22)
- **Train Reconstruction Mean MSE:** 0.024109 (VERIFIED)
- **Validation Reconstruction Mean MSE:** 0.037586 (VERIFIED)
- **Test Reconstruction Mean MSE:** 0.090613 (VERIFIED)
- **Test Reconstruction Median MSE:** 0.046952 (VERIFIED)
- **95th Percentile Anomaly Threshold:** 0.036527 (VERIFIED)
- **99th Percentile Anomaly Threshold:** 0.133943 (VERIFIED)
- **Test Anomaly Flag Rate (@ 95% threshold):** 55.56% (23,231 / 41,815 flagged anomalous) (VERIFIED)
  - *Diagnosis from `tabular_distribution_shift_report.csv`:* The test set (2023-2024 data) suffered a strong temporal distribution shift compared to the train set (2021-2022 data), causing high reconstruction errors on newer marketplaces.

### 3. Temporal Autoencoder
- **Best Validation Loss:** 0.011047 (VERIFIED — `temporal_model_metrics.json`, Epoch 40)
- **Train Reconstruction Mean MSE:** 0.015330 (VERIFIED)
- **Validation Reconstruction Mean MSE:** 0.011047 (VERIFIED)
- **Test Reconstruction Mean MSE:** 0.011436 (VERIFIED)
- **Test Reconstruction Median MSE:** 0.000143 (VERIFIED)
- **95th Percentile Anomaly Threshold:** 0.005851 (VERIFIED)
- **99th Percentile Anomaly Threshold:** 0.027091 (VERIFIED)
- **Test Anomaly Flag Rate (@ 95% threshold):** 15.27% (6,384 / 41,815 flagged anomalous) (VERIFIED)

### 4. Tri-Modal Model Risk Fusion (41,815 Test Records)
- **Mean Fusion Score:** 0.20988 (VERIFIED — `model_fusion_summary.json`)
- **Median Fusion Score:** 0.21273 (VERIFIED)
- **Risk Band Breakdown:**
  - `LOW` Risk ($<0.30$): 39,632 records (94.78%)
  - `MODERATE` Risk ($0.30 - 0.50$): 1,903 records (4.55%)
  - `ELEVATED` Risk ($0.50 - 0.70$): 254 records (0.61%)
  - `HIGH` Risk ($>0.70$): 26 records (0.06%)
  - **Multi-Signal Overlap:** 2,922 records triggered $\ge 2$ anomaly signals; 79 records triggered all 3 signals (`HIGH` severity).

---

## PART 7 — MODEL COMPARISON

| Experiment | Model | Dataset | Train Size | Val Size | Test Size | Key Metric (Verified) | Completion Status | Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Exp 1: Text Classifier** | DistilBERT | DWData Text | 5,000 | 1,000 | 1,000 | Acc: 47% (Unbal) / 16% (Bal) | **INCOMPLETE / UNDERTRAINED** | **DO NOT USE AS IS**. Retrain with class weighting / full train set |
| **Exp 2: Tabular Autoencoder**| PyTorch MLP (39 feat) | DWData Tabular | 271,266 | 75,298 | 41,815 | Best Val Loss: 0.037586 | **COMPLETED** | **ACTIVE MODEL**. Ready for behavioral anomaly scoring |
| **Exp 3: Temporal Autoencoder**| PyTorch MLP (14 feat) | DWData Temporal| 271,266 | 75,298 | 41,815 | Best Val Loss: 0.011047 | **COMPLETED** | **ACTIVE MODEL**. Ready for temporal anomaly scoring |
| **Exp 4: Tri-Modal Fusion** | Decision Fusion | All 3 Models | N/A | N/A | 41,815 | 26 HIGH risk cases flagged | **COMPLETED** | **ACTIVE ENSEMBLE**. Ready for unified risk scoring |

---

## PART 8 — CHECKPOINTS AND SAVED MODELS

All model artifacts in `models/` were inspected and verified loadable:

1. **`models/dwdata_text_model/model.safetensors`**
   - **Size:** 267,823,208 bytes (~268 MB)
   - **Format:** HuggingFace Safetensors (`distilbert-base-uncased`)
   - **Associated Code:** `learning/training/train_text_model.py`
   - **Associated Configs:** `config.json`, `tokenizer.json`, `tokenizer_config.json`
   - **Loadability:** Complete and loadable via `AutoModelForSequenceClassification.from_pretrained()`.
   - **Status:** Latest text checkpoint (Subsampled version).

2. **`models/dwdata_tabular_model/model.pt`**
   - **Size:** 6,517 bytes
   - **Format:** PyTorch state_dict (`TabularAutoencoder`)
   - **Associated Code:** `learning/training/train_tabular_model.py`
   - **Associated Scaler:** `scaler.joblib` (2,752 bytes)
   - **Loadability:** Complete and loadable.
   - **Status:** Final trained behavioral autoencoder model.

3. **`models/dwdata_temporal_model/temporal_autoencoder.pt`**
   - **Size:** 2,607 bytes
   - **Format:** PyTorch state_dict (`TemporalAutoencoder`)
   - **Associated Code:** `learning/training/train_temporal_model.py`
   - **Associated Scaler:** `temporal_scaler.npz` (1,006 bytes)
   - **Loadability:** Complete and loadable.
   - **Status:** Final trained temporal autoencoder model.

4. **`models/checkpoints/`**
   - **Status:** Empty directory (No intermediate epoch checkpoints preserved).

---

## PART 9 — PREDICTION PIPELINE

### Tracing the Current Inference Flow
The current inference mechanism is implemented inside `learning/training/explain_fusion.py`:

```
Input Record (Text + Tabular Features + Temporal Features)
   ↓
Preprocessing & Scaling (StandardScaler & MinMaxScaler)
   ↓
Tokenization (DistilBERT Fast Tokenizer, max_length=128)
   ↓
Model Forward Passes:
   ├─ DistilBERT -> Softmax Probabilities -> Max Conf & Predicted Class
   ├─ Tabular Autoencoder -> Reconstruction MSE -> Anomaly Flag
   └─ Temporal Autoencoder -> Reconstruction MSE -> Anomaly Flag
   ↓
Risk Fusion Computation:
   Fusion Score = 0.40 * TabularMSE + 0.35 * TemporalMSE + 0.25 * (1 - TextConf)
   ↓
Risk Band Mapping: LOW / MODERATE / ELEVATED / HIGH
   ↓
Output Batch File: reports/training/model_fusion_test.csv
```

### Working vs Missing Prediction Components
- **WORKING:** Offline batch prediction over test CSV files (`model_fusion_test.csv`).
- **MISSING:** A standalone interactive prediction script (e.g., `predict.py` or `generate_predictions.py`) that accepts raw single-text or JSON input from a user/API and returns immediate predictions and XAI explanations.

---

## PART 10 — XAI / EXPLAINABILITY

Explainability is **ACTUALLY IMPLEMENTED** in the repository across all three modalities:

1. **LIME (Local Interpretable Model-agnostic Explanations) for Text:**
   - *Script:* `learning/training/explain_text_lime.py`
   - *Target Model:* `dwdata_text_model` (DistilBERT)
   - *Outputs:* `reports/xai/text_lime_cases.csv`, `text_lime_tokens.csv`, `text_lime_summary.csv`
   - *Functionality:* Computes top positive and negative token weights contributing to the predicted semantic category.

2. **SHAP (SHapley Additive exPlanations) for Tabular Features:**
   - *Script:* `learning/training/explain_behavioral_shap.py`
   - *Target Model:* `dwdata_tabular_model` (Tabular Autoencoder)
   - *Outputs:* `reports/xai/behavioral_shap_cases.csv`, `behavioral_shap_summary.csv`, `behavioral_feature_importance.csv`
   - *Functionality:* Uses `shap.KernelExplainer` to calculate feature contributions to reconstruction error.

3. **Reconstruction-Based Attribution for Temporal Features:**
   - *Script:* `learning/training/explain_temporal.py`
   - *Target Model:* `dwdata_temporal_model` (Temporal Autoencoder)
   - *Outputs:* `reports/xai/temporal_xai_cases.csv`, `temporal_xai_summary.csv`, `temporal_xai_features.csv`
   - *Functionality:* Computes per-feature reconstruction error metrics to identify which temporal feature caused the anomaly flag.

4. **Unified Multi-Modal XAI:**
   - *Script:* `learning/training/explain_fusion.py`
   - *Outputs:* `reports/xai/unified_xai_explanations.csv`, `unified_xai_summary.csv`
   - *Functionality:* Combines LIME token highlights, SHAP feature rankings, and temporal reconstruction errors into a human-readable text narrative for analyst reports.

5. **What Remains to be Implemented for XAI:**
   - Real-time XAI generation for single user inputs in an interactive web UI / REST API.

---

## PART 11 — DARKNET / DARK WEB COMPONENT

| Component | Status | Evidence / Details |
| :--- | :--- | :--- |
| **Dark Web Marketplace Scrapes** | **IMPLEMENTED** | `data/raw/DWData-master/` (54+ CSVs from AlphaBay, Darkode, Tor2Door, Whitehouse, Abacus, Nemesis, Kingdom, etc.) |
| **Dark Web Feature Extraction** | **IMPLEMENTED** | `extract_dwdata_features.py` (Onion URLs, vendor observation numbers, price/currency parsing, malware/exploit keywords) |
| **Tor / Whonix Routing** | **NOT IMPLEMENTED** | No Tor proxy setup or SOCKS configuration in codebase |
| **Live Onion Crawler / Scraper**| **NOT IMPLEMENTED** | No live web scraping or crawling scripts present |
| **Forum / Social Media Scrapers**| **NOT IMPLEMENTED** | No Reddit, Telegram, or darkweb forum scrapers present |
| **Real-time Threat Intelligence Feed**| **PLANNED** | Concept documented in project plan, but no live connection implemented |

---

## PART 12 — DASHBOARD / DEMO

- **Framework Used:** None implemented yet (`dashboard/` folder is empty).
- **Files:** 0 files in `dashboard/`.
- **Current Functionality:** **0% IMPLEMENTED**.
- **Model Connected:** NO.
- **Prediction Connected:** NO.
- **XAI Connected:** NO.
- **Live Data Connected:** NO.
- **Execution Command:** N/A (Dashboard code does not exist).

---

## PART 13 — REQUIREMENTS / ENVIRONMENT

No `requirements.txt` or `environment.yml` file was included in the repository. Based on the import statements across all Python scripts, the required environment comprises:

- **Python Version:** Python 3.9+ recommended
- **Core ML & Deep Learning Libraries:**
  - `torch` (PyTorch)
  - `transformers` (HuggingFace Transformers)
  - `scikit-learn` / `sklearn`
  - `pandas`
  - `numpy`
  - `joblib`
- **XAI Libraries:**
  - `lime` (LIME explainer)
  - `shap` (SHAP explainer)
- **Frontend / Dashboard Dependencies (Required for Next Stage):**
  - `streamlit` or `gradio` (or React/FastAPI)

---

## PART 14 — TRAINING COMPLETION STATUS

```
DATA COLLECTION       [COMPLETE]  (Evidence: data/raw/DWData-master - 388,379 listings)
DATA CLEANING         [COMPLETE]  (Evidence: preprocessing/normalize_dwdata.py & dwdata_optimized.csv)
DATASET INTEGRATION   [PARTIAL]   (Evidence: DWData integrated; surface_cti.csv & safe_corpus.json unmerged)
LABELING              [COMPLETE]  (Evidence: extract_dwdata_features.py - 29 semantic categories)
TRAIN/VAL/TEST SPLIT  [COMPLETE]  (Evidence: prepare_training_data.py - 70/20/10 time-safe split)
MODEL TRAINING        [PARTIAL]   (Evidence: Tabular & Temporal Autoencoders COMPLETE; Text DistilBERT subsampled 5k)
MODEL EVALUATION      [COMPLETE]  (Evidence: reports/training/ - all JSON metrics & confusion matrices)
CHECKPOINT            [COMPLETE]  (Evidence: models/ - model.safetensors, model.pt, temporal_autoencoder.pt)
PREDICTION            [PARTIAL]   (Evidence: Batch offline prediction COMPLETE; interactive API MISSING)
XAI                   [PARTIAL]   (Evidence: Batch LIME/SHAP/Fusion XAI COMPLETE; real-time XAI API MISSING)
DASHBOARD             [NOT STARTED](Evidence: dashboard/ folder is completely empty)
DARKNET MONITORING    [PARTIAL]   (Evidence: Historical scrape ETL COMPLETE; live crawler NOT IMPLEMENTED)
DEPLOYMENT            [NOT STARTED](Evidence: No web server, Dockerfile, or app host setup)
```

---

## PART 15 — WHAT SOMESHEKAR ACTUALLY COMPLETED

Based strictly on code and file evidence, Someshekar completed the following items in project order:

1. **Ingested Dark Web Marketplace Dataset:** Downloaded and structured 388,379 listing records from 54+ CSV dumps (`DWData-master`).
2. **Built Raw Data Normalization Pipeline:** Wrote `preprocessing/normalize_dwdata.py` to standardize schemas, normalize currencies/prices, and parse dates into `dwdata_optimized.csv`.
3. **Implemented Multi-Modal Feature Extraction:** Wrote `preprocessing/extract_dwdata_features.py` to engineer 73 features (IOC indicators, vendor history, temporal gaps, keyword matches, and 29 semantic categories) into `dwdata_features.csv`.
4. **Performed Feature Selection & Cleaning:** Wrote `preprocessing/prepare_dwdata_model.py` to filter out 10 constant and 6 redundant features, handle missing values via median imputation, and output `tabular_features.json`.
5. **Executed Chronological Time-Safe Dataset Splitting:** Wrote `learning/training/prepare_training_data.py` to perform a 70% train / 20% val / 10% test split based on snapshot dates.
6. **Trained Tabular Behavioral Autoencoder:** Wrote `learning/training/train_tabular_model.py` and trained a PyTorch autoencoder for 28 epochs on 39 features (`models/dwdata_tabular_model/model.pt`).
7. **Trained Temporal Autoencoder:** Wrote `learning/training/train_temporal_model.py` and trained a PyTorch autoencoder for 40 epochs on 14 vendor/temporal features (`models/dwdata_temporal_model/temporal_autoencoder.pt`).
8. **Created Initial Text Classifier Baseline:** Wrote `learning/training/train_text_model.py` and fine-tuned `distilbert-base-uncased` for 1 epoch on 5,000 subsampled records (`models/dwdata_text_model/model.safetensors`).
9. **Built Tri-Modal Risk Fusion Module:** Wrote `learning/training/build_model_fusion.py` to calculate weighted risk scores across all 41,815 test records (`model_fusion_test.csv`).
10. **Diagnosed Text Model & Tabular Shift Issues:** Wrote `analyze_text_model.py`, `create_balanced_test.py`, `evaluate_balanced_text.py`, and `investigate_tabular_shift.py` to analyze class imbalance and temporal drift.
11. **Implemented Tri-Modal Explainability (XAI):** Developed `explain_text_lime.py` (LIME), `explain_behavioral_shap.py` (SHAP), `explain_temporal.py` (Reconstruction attribution), and `explain_fusion.py` (Unified XAI report generation).

---

## PART 16 — WHAT I SHOULD DO NEXT

### Project Status Overview
- **CURRENT STAGE:** Model Optimization & Interactive Application Integration
- **COMPLETED:** ETL pipeline, dataset splitting, tabular autoencoder, temporal autoencoder, fusion algorithm, batch offline XAI pipeline.
- **INCOMPLETE:** DistilBERT text model (needs retraining on full dataset with class weighting), interactive single-sample prediction script.
- **MISSING:** Dashboard UI, real-time XAI API, live dark web crawling, `requirements.txt`.

### Step-by-Step Continuation Plan

#### STEP 1: Retrain the Text Model (DistilBERT / CyberBERT)
- *Problem:* Current DistilBERT was trained on only 5,000 samples for 1 epoch and suffers from 93.8% class imbalance.
- *Action:* Modify `learning/training/train_text_model.py` to use class weights in `CrossEntropyLoss` (or SMOTE / Focal Loss) and train on GPU (or larger CPU batch) across the full `text_train.csv` dataset.

#### STEP 2: Build Interactive Prediction & Real-Time XAI Pipeline
- *Problem:* Models currently only evaluate statically over CSV test files.
- *Action:* Create a standalone script `predict.py` that takes an arbitrary input string (e.g. `"Selling 100x Credit Card CVVs with PIN"`) and runs instant inference through Text + Tabular + Temporal models, returning the fused risk score and real-time LIME/SHAP token highlights.

#### STEP 3: Integrate Unused CTI Dataset (`surface_cti.csv`)
- *Action:* Evaluate whether `surface_cti.csv` (158k rows) can be merged as a secondary threat intelligence feature stream or baseline benchmark.

#### STEP 4: Build Web Dashboard (`dashboard/`)
- *Action:* Implement a clean Streamlit or React web UI inside `dashboard/` that connects directly to `predict.py` and displays live threat risk gauges, LIME token highlights, SHAP feature importance charts, and risk band indicators.

#### STEP 5: Add Requirements & Setup Environment File
- *Action:* Create `requirements.txt` containing all exact library versions (`torch`, `transformers`, `lime`, `shap`, `streamlit`, `scikit-learn`, `pandas`).

---

## PART 17 — DO NOT REDO WORK

To avoid wasting time or duplicating existing progress, **DO NOT REDO** the following:

- **DO NOT REDO Raw Data Normalization:** `preprocessing/normalize_dwdata.py` and `dwdata_optimized.csv` are 100% complete and accurate.
- **DO NOT REDO Feature Extraction:** `preprocessing/extract_dwdata_features.py` and `dwdata_features.csv` successfully engineer all 73 features.
- **DO NOT REDO Dataset Splitting:** `prepare_training_data.py` and `data/processed/training/*.csv` form a clean, time-safe 70/20/10 split.
- **DO NOT REDO Tabular & Temporal Autoencoder Training:** Both `dwdata_tabular_model` and `dwdata_temporal_model` are fully trained with convergence verified by loss logs.
- **DO NOT REDO Fusion Logic:** `build_model_fusion.py` provides a working 0.40 / 0.35 / 0.25 weighted tri-modal risk fusion formula.
- **DO NOT REDO Batch XAI Logic:** LIME, SHAP, and temporal attribution scripts are written and functional.

### Obsolete / Incomplete Experiments to Ignore
- **Subsampled 5k DistilBERT Training Run:** Do not use `models/dwdata_text_model/` for final demonstration without retraining, as its balanced accuracy is only 16.0%.
- **`preprocessing_codes/` Directory:** Ignore this folder (it is empty).

---

## PART 18 — FINAL HANDOVER REPORT SUMMARY

```text
PROJECT:
DarkWatch XAI

DATASETS:
- Dataset 1: DWData-master (Dark Web Marketplace Listings - 388,379 raw rows across 54+ CSVs)
- Dataset 2: surface_cti.csv (Surface Web CTI Network Traffic - 158,616 rows, UNUSED)
- Dataset 3: safe_corpus.json (Benign Text Corpus - 2,000 JSON lines, UNUSED)
- Dataset 4: Processed Tabular Dataset (388,379 rows x 50 columns)
- Dataset 5: Processed Text Dataset (388,379 rows x 2 columns, 29 semantic classes)
- Dataset 6: Processed Temporal Dataset (388,379 rows x 14 columns)

TOTAL DATA:
- Raw samples: 388,379
- Cleaned samples: 388,379
- Final training samples: 271,266 (70% chronological split)
- Validation samples: 75,298 (20% split)
- Test samples: 41,815 (10% split)

MODELS:
- Model 1: Text Classifier (distilbert-base-uncased, 66M params, 29 classes)
- Model 2: Tabular Behavioral Autoencoder (PyTorch MLP, 39 features)
- Model 3: Temporal Autoencoder (PyTorch MLP, 14 features)
- Model 4: Tri-Modal Weighted Risk Fusion (0.40 Behavioral + 0.35 Temporal + 0.25 Semantic)

FINAL/ACTIVE MODEL:
Tri-Modal Fusion Ensemble (Tabular Autoencoder + Temporal Autoencoder + DistilBERT)

TRAINING STATUS:
- Tabular Autoencoder: COMPLETED (28 epochs, Best Val Loss: 0.037586)
- Temporal Autoencoder: COMPLETED (40 epochs, Best Val Loss: 0.011047)
- DistilBERT Text Model: PARTIAL / UNDERTRAINED (1 epoch on 5,000 subsampled rows)
- Risk Fusion: COMPLETED (41,815 test cases evaluated)

BEST/FINAL VERIFIED METRICS:
- Text Model (Unbalanced Test 1k): Accuracy = 47.0%, Macro Precision = 92.07%, Weighted F1 = 0.6198
- Text Model (Balanced Test 150): Accuracy = 16.0%, Macro F1 = 0.1023 (Failed due to class imbalance)
- Tabular Autoencoder: Best Val Loss = 0.037586, Test Reconstruction Mean = 0.090613
- Temporal Autoencoder: Best Val Loss = 0.011047, Test Reconstruction Mean = 0.011436
- Fusion Ensemble: 26 HIGH risk cases, 254 ELEVATED risk cases flagged on test set

XAI STATUS:
COMPLETED (Batch offline LIME for Text, SHAP for Tabular, Reconstruction attribution for Temporal, and Unified Multi-Modal XAI text report generator). Real-time UI connection MISSING.

PREDICTION STATUS:
PARTIAL (Batch offline evaluation over test CSVs complete; single-sample interactive prediction CLI/API script MISSING).

DASHBOARD STATUS:
NOT STARTED (dashboard/ directory is 100% empty).

DARKNET MONITORING STATUS:
PARTIAL (Offline ETL and feature extraction for 54+ dark web marketplace dumps complete; live Tor crawling/scraping NOT IMPLEMENTED).

SOMESHEKAR COMPLETED:
1. End-to-end ETL pipeline (normalization, feature extraction, 70/20/10 time-safe split).
2. Training & evaluation of Tabular Behavioral Autoencoder and Temporal Autoencoder.
3. Baseline DistilBERT text model training (5k subsampled).
4. Weighted tri-modal decision risk fusion module.
5. Batch LIME, SHAP, and unified XAI explanation generators.

REMAINING WORK:
1. Retrain DistilBERT text model on full 271k dataset with class imbalance handling.
2. Write interactive single-sample prediction script (`predict.py`).
3. Build Streamlit or React Web UI in `dashboard/`.
4. Create `requirements.txt`.

MY NEXT STEP:
Retrain the DistilBERT text model with weighted loss / full dataset, then write `predict.py` to enable interactive inference and real-time XAI output.

CRITICAL FILES I NEED TO KNOW:
1. data/processed/dwdata_features.csv (Engineered dataset containing all 73 features)
2. learning/training/prepare_training_data.py (Time-safe dataset splitting logic)
3. learning/training/train_text_model.py (Text classifier training code to be updated)
4. learning/training/build_model_fusion.py (Tri-modal risk fusion scoring formula)
5. learning/training/explain_fusion.py (Unified XAI narrative explanation generator)
```

---

## PART 9 — DARKWATCH GOLD DATASET PIPELINE (OPERATIONAL GUIDANCE)

### 9.1 Overview & Architecture

The **DarkWatch Gold Dataset Pipeline** constructs a Dark-Web-specific training corpus directly from sanitized evidence harvested by the Whonix/Tor collector, avoiding complete reliance on synthetic or third-party datasets (such as CoDA).

```
Collector SQLite (data/collector_evidence.db)
        ↓
Content Sanitizer (strips active HTML/JS/executables, calculates SHA-256)
        ↓
Exact (SHA-256) & Near-Duplicate Detection (MinHash LSH, Jaccard threshold = 0.85)
        ↓
Existing CTI / Entity Extraction (ThreatExtractor & STIXExtractor)
        ↓
Existing MITRE Enrichment (MITREMapper & MITREEnricher STIX 2.1)
        ↓
Candidate Semantic Labels (WeakSupervisionEngine)
        ↓
SQLite Dataset Storage (AnnotationStore in data/gold_dataset.db)
        ↓
Human-Review Queue (ReviewQueueManager in reports/review_tasks_pilot.json)
        ↓
Human-Validated Gold Dataset (Promoted to HUMAN_VERIFIED tier)
        ↓
Training Dataset Exporters (DatasetExporter -> JSONL & CSV in data/processed/)
```

### 9.2 Key Components & File Locations

1. **`dataset/schema.py`** (`src/dataset/schema.py`)
   - `GoldRecord` schema version `1.0.0`.
   - Annotation Tiers: `AUTOMATED`, `WEAK_SUPERVISION`, `HUMAN_VERIFIED`.
   - Categorical Taxonomies: `ActivityCategory`, `Intent`, `Severity`, `TargetSector`.
   - Schema validation and JSON serialization / deserialization methods.

2. **`dataset/annotation_store.py`** (`src/dataset/annotation_store.py`)
   - SQLite persistence layer for Gold Dataset records in `data/gold_dataset.db`.
   - Maintains `gold_dataset_records` and complete `annotation_history` tables.
   - Tracks annotator IDs, confidence scores, state transitions, and disputed labels.

3. **`dataset/weak_supervision.py`** (`src/dataset/weak_supervision.py`)
   - Generates candidate activity, intent, severity, and target sector labels.
   - Reuses existing CTI entity extractors (`ThreatExtractor`, `STIXExtractor`) and MITRE mappers/enrichers (`MITREMapper`, `MITREEnricher`).
   - **Invariant:** Candidate labels are assigned tier `WEAK_SUPERVISION` with confidence $\le 0.85$ and are **never** treated as ground truth.

4. **`deduplication/minhash_lsh.py`** (`src/deduplication/minhash_lsh.py`)
   - `MinHashLSHDeduplicator`: Exact SHA-256 hash matching + MinHash LSH near-duplicate detection.
   - Configurable $K$-shingle size, MinHash permutations ($N=64$), LSH bands ($B=16$), and Jaccard threshold ($0.85$).
   - Preserves complete duplicate provenance (`duplicate_of`, duplicate source IDs, onion addresses, timestamps).

5. **`review/reviewer.py`** (`src/review/reviewer.py`)
   - `ReviewQueueManager`: Manages human review queue tasks.
   - `export_review_tasks()`: Exports candidate review tasks to `reports/review_tasks_pilot.json`.
   - `import_completed_reviews()`: Validates reviewer inputs and promotes records to `HUMAN_VERIFIED` **only** when `human_validation_confirmed: true` and a valid human `annotator_id` are provided.

6. **`review/quality_auditor.py`** (`src/review/quality_auditor.py`)
   - `QualityAuditor`: Evaluates dataset health, tier breakdowns, label distributions, schema violations, and unlinked duplicates.
   - Calculates Cohen's Kappa ($\kappa$) inter-annotator agreement score between Weak Supervision candidate labels and Human Verified ground truth.

7. **`exporter/export_runner.py`** (`src/exporter/export_runner.py`)
   - `DatasetExporter`: Exports curated Gold records to line-delimited JSONL and tabular CSV formats.
   - Configurable tier filtering (e.g. `HUMAN_VERIFIED` only, or `HUMAN_VERIFIED` + `WEAK_SUPERVISION`).
   - Automatically excludes duplicate records to prevent train/test data leakage.
   - Generates companion `.manifest.json` files with SHA-256 file hashes.

8. **`pilot_runner.py`**
   - End-to-end pilot script reading directly from the actual collector SQLite database (`data/collector_evidence.db`).

9. **Tests** (`tests/test_gold_dataset_pipeline.py`)
   - Comprehensive test suite covering schema, storage, weak supervision, MinHash LSH deduplication, review queue workflows, auditor metrics, exporter manifests, and end-to-end pilot execution.

---

### 9.3 How to Run the Gold Dataset Pipeline

#### 1. Execute the Pilot Runner against Collector Evidence:
```bash
python3 pilot_runner.py
```

#### 2. Export Review Queue Tasks for Human Validation:
```python
from src.dataset.annotation_store import AnnotationStore
from src.review.reviewer import ReviewQueueManager

store = AnnotationStore("data/gold_dataset.db")
manager = ReviewQueueManager(store)
manager.export_review_tasks("reports/review_tasks_pilot.json", limit=50)
```

#### 3. Ingest Completed Human Reviews & Promote to HUMAN_VERIFIED:
Human reviewers update `reports/review_tasks_pilot.json` by setting `"human_validation_confirmed": true`, providing their `"annotator_id"`, and reviewing label selections, then re-import:
```python
results = manager.import_completed_reviews("reports/review_tasks_pilot.json")
print(f"Promoted to HUMAN_VERIFIED: {results['promoted_to_human_verified']}")
```

#### 4. Export Training Dataset for Model Training:
```python
from src.dataset.annotation_store import AnnotationStore
from src.exporter.export_runner import DatasetExporter

store = AnnotationStore("data/gold_dataset.db")
exporter = DatasetExporter(store)

# Export only human-verified records (excluding duplicates)
exporter.export_jsonl("data/processed/gold_dataset_human_verified.jsonl", allowed_tiers=["HUMAN_VERIFIED"], include_duplicates=False)

# Export combined human-verified and weak-supervision dataset
exporter.export_csv("data/processed/gold_dataset_training.csv", allowed_tiers=["HUMAN_VERIFIED", "WEAK_SUPERVISION"], include_duplicates=False)
```

#### 5. Run Complete Test Suite:
```bash
python3 -m unittest discover -s tests
```

---

### 9.4 Current Pilot Status & Limitations

- **Collector Database:** The existing collector SQLite database (`data/collector_evidence.db`) contains 1 observation (`SRC_DEMO_001`). The pipeline explicitly detects and flags synthetic/demo observations without fabricating data.
- **Model Training:** Model architectures (DistilBERT, XGBoost, Autoencoders, Fusion) have not been altered.
- **Human Verification:** Currently 0 records are marked `HUMAN_VERIFIED` until human review task payloads are ingested.

---

### 9.5 Recommended Next Steps

1. **Deploy Collector:** Deploy the Whonix/Tor collector script to continuously harvest real dark web evidence into `data/collector_evidence.db`.
2. **Conduct Human Reviews:** Process exported review tasks (`reports/review_tasks_pilot.json`) to build a high-confidence `HUMAN_VERIFIED` gold training corpus.
3. **Model Fine-Tuning:** Use exported `gold_dataset_human_verified.jsonl` to fine-tune DistilBERT and re-calibrate risk fusion models.

