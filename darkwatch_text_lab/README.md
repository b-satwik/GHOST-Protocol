# DarkWatch Text Training Lab 🧪

A fully portable, self-contained NLP research and training laboratory for DarkWatch threat text intelligence models.

---

## 📁 Laboratory Architecture

```
darkwatch_text_lab/
│
├── notebooks/
│   └── DarkWatch_Text_Training.ipynb   # Master end-to-end interactive notebook
│
├── data/
│   ├── raw/                            # Original copied datasets & DATASET_MANIFEST.json
│   ├── unified/                        # Unified source-aware jsonl corpus
│   ├── future_observations/            # Ingested live observations pending/verified
│   └── versions/                       # Versioned datasets (dataset_v1, dataset_v2, ...)
│
├── models/
│   ├── baselines/                      # Trained TF-IDF LR, SVM, XGBoost joblib artifacts
│   ├── transformers/                   # Fine-tuned multi-task Transformer checkpoints
│   └── cached/                         # Offline cached pretrained models
│
├── results/
│   ├── metrics/                        # Raw evaluation JSON files & classification reports
│   ├── confusion_matrices/             # Saved confusion matrix JSONs & plots
│   ├── curves/                         # Loss & metric training curves
│   ├── error_analysis/                 # False positives/negatives & confused class pairs
│   ├── xai/                            # Token importance attributions & CTI correlations
│   └── experiments/                    # Model comparison CSV (model_comparison.csv)
│
├── scripts/
│   ├── build_unified_dataset.py        # Generates unified jsonl and dataset_v1
│   ├── train_baselines.py              # Trains TF-IDF LR, SVM, XGBoost baselines
│   ├── train_transformer.py            # Fine-tunes Multi-Task DistilBERT / custom transformer
│   ├── evaluate_models.py              # Evaluates untouched test set & error analysis
│   ├── explain_predictions.py          # Token XAI attributions + CTI/MITRE correlation
│   ├── ingest_future_observations.py   # Ingests live text observations
│   ├── promote_verified_data.py        # Promotes human-verified / corrected observations
│   └── create_dataset_version.py       # Builds dataset_v2, dataset_v3 continual releases
│
├── configs/
│   └── training_config.json            # Central experiment & environment configuration
│
├── logs/                               # Execution logs
├── requirements.txt                    # Portable Python dependencies
├── README.md                           # Laboratory sitemap and documentation
└── RUN_GUIDE.md                        # Quickstart execution guide
```

---

## 🚀 Key Features

1. **Dual Task Semantics**:
   - **Task A (DWData)**: 29-class Dark Web semantic activity classification.
   - **Task B (CySecED Dark)**: 36-class cybersecurity event classification.
2. **Multi-Task Architecture**:
   - Shared Transformer encoder backbone (DistilBERT, DarkBERT, SecureBERT, RoBERTa).
   - Dual classification heads trained with task loss masking.
3. **Continual Learning & Versioning**:
   - Ingest live observation streams into `future_observations.jsonl` (`PENDING_REVIEW`).
   - Analyst human review promotes `HUMAN_VERIFIED` or `HUMAN_CORRECTED` records.
   - Incrementally creates `dataset_v2`, `dataset_v3` without altering original held-out test splits.
4. **CTI & MITRE ATT&CK Integration**:
   - Reuses DarkWatch `ThreatExtractor` (IPs, URLs, CVEs, Hashes, Malware) and `MITREMapper`.
   - Explicitly distinguishes:
     - `OBSERVED_EVIDENCE`
     - `MODEL_INFERENCE`
     - `CTI_KNOWLEDGE`
     - `MITRE_KNOWLEDGE`
5. **Portability & Offline Support**:
   - Works seamlessly in **VS Code**, **Jupyter Lab**, and **Google Colab**.
   - Supports `OFFLINE_MODE = True` loading models from `models/cached/`.

---

## 🛠️ Environment Setup

```bash
# Activate existing DarkWatch environment
source ../.venv/bin/activate

# Install requirements if needed
pip install -r requirements.txt
```

---

## 📓 Running the Notebook

Open `darkwatch_text_lab/notebooks/DarkWatch_Text_Training.ipynb` in VS Code or Jupyter Lab and execute cells top-to-bottom.
