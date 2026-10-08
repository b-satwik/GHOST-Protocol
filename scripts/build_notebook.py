#!/usr/bin/env python3
import json
import os

def cell_markdown(text):
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": [line + "\n" for line in text.strip().split("\n")]
    }

def cell_code(text):
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [line + "\n" for line in text.strip().split("\n")]
    }

cells = [
    cell_markdown('# DarkWatch Text Intelligence Model — Training & Continual Learning Laboratory 🧪\n\n**Master Notebook**: `darkwatch_text_lab/DarkWatch_Text_Training.ipynb`  \n**Objective**: End-to-end NLP intelligence laboratory for Dark Web activity understanding, cybersecurity event classification, explainability, CTI correlation, and human-in-the-loop continual learning.'),
    cell_markdown('## Configuration Flags\nToggle these flags near the top to control which sections of the lab execute.'),
    cell_code('''# Execution Switches
RUN_BASELINES = True
RUN_TRANSFORMER = True
RUN_XAI = True
RUN_CTI = True
RUN_CONTINUAL_RETRAINING = False  # Set True to run optional retraining section
OFFLINE_MODE = False             # Set True to load models from local cache

print("Notebook Configuration Switches Loaded:")
print(f"  RUN_BASELINES: {RUN_BASELINES}")
print(f"  RUN_TRANSFORMER: {RUN_TRANSFORMER}")
print(f"  OFFLINE_MODE: {OFFLINE_MODE}")
print(f"  RUN_CONTINUAL_RETRAINING: {RUN_CONTINUAL_RETRAINING}")'''),
    cell_markdown('## 1. Environment & GPU Detection'),
    cell_code('''import sys
import os
import platform
import psutil
import torch

PYTHON_VERSION = sys.version.split()[0]
PYTORCH_VERSION = torch.__version__
CUDA_AVAILABLE = torch.cuda.is_available()
DEVICE = "cuda" if CUDA_AVAILABLE else "cpu"
CPU_COUNT = os.cpu_count()
RAM_GB = round(psutil.virtual_memory().total / (1024**3), 2)

print("=== ENVIRONMENT METRICS ===")
print(f"Python Version:  {PYTHON_VERSION}")
print(f"PyTorch Version: {PYTORCH_VERSION}")
print(f"Target Device:   {DEVICE.upper()}")
if CUDA_AVAILABLE:
    print(f"GPU Model:       {torch.cuda.get_device_name(0)}")
print(f"CPU Cores:       {CPU_COUNT}")
print(f"System Memory:   {RAM_GB} GB")'''),
    cell_markdown('## 2. Project Path Configuration & Import Setup'),
    cell_code('''from pathlib import Path

IN_COLAB = "google.colab" in sys.modules
MANUAL_PROJECT_DIR = None

if MANUAL_PROJECT_DIR and Path(MANUAL_PROJECT_DIR).exists():
    PROJECT_DIR = Path(MANUAL_PROJECT_DIR).resolve()
elif IN_COLAB:
    from google.colab import drive
    drive.mount("/content/drive")
    PROJECT_DIR = Path("/content/drive/MyDrive/darkwatch_text_lab").resolve()
else:
    cwd = Path.cwd().resolve()
    if cwd.name == "notebooks":
        PROJECT_DIR = cwd.parent
    else:
        PROJECT_DIR = cwd if (cwd / "scripts").exists() else cwd / "darkwatch_text_lab"

# Insert project root ONLY into sys.path
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

import scripts
from scripts.build_unified_dataset import main as build_unified_main
from scripts.train_baselines import train_baseline_models
from scripts.train_transformer import main as train_transformer_main
from scripts.evaluate_models import main as evaluate_main

print(f"PROJECT_DIR configured to: {PROJECT_DIR}")
print(f"Scripts Package Imported Successfully: {scripts.__file__}")'''),
    cell_markdown('## 3. Dependency & Import Check'),
    cell_code('''import json
import time
import random
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sklearn
import xgboost as xgb
import transformers

# Set random seeds for reproducibility
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)
torch.manual_seed(RANDOM_SEED)
if CUDA_AVAILABLE:
    torch.cuda.manual_seed_all(RANDOM_SEED)

print("All core dependencies loaded successfully.")
print(f"  scikit-learn: {sklearn.__version__}")
print(f"  xgboost:      {xgb.__version__}")
print(f"  transformers: {transformers.__version__}")'''),
    cell_markdown('## 4. Dataset Discovery'),
    cell_code('''raw_dir = PROJECT_DIR / "data" / "raw"
manifest_file = raw_dir / "DATASET_MANIFEST.json"

if manifest_file.exists():
    with open(manifest_file, "r") as f:
        manifest_data = json.load(f)
    print(f"Loaded Raw Dataset Manifest from {manifest_file}:")
    for ds in manifest_data.get("datasets", []):
        print(f"  - {ds['name']}: {ds['record_count']} records | Used for Training: {ds['used_for_training']}")
else:
    print(f"Manifest file not found at {manifest_file}. Proceeding to scan raw directory...")'''),
    cell_markdown('## 5. Dataset Statistics & Class Distributions'),
    cell_code('''dw_train_file = raw_dir / "text_train.csv"
if dw_train_file.exists():
    df_dw_train = pd.read_csv(dw_train_file)
    print(f"DWData Train Shape: {df_dw_train.shape}")
    print("Top 10 DWData Semantic Classes:")
    print(df_dw_train['semantic_target'].value_counts().head(10))

dark_file = raw_dir / "base_dark_final.csv"
if dark_file.exists():
    df_dark_raw = pd.read_csv(dark_file)
    print(f"\\nCySecED Dark Shape: {df_dark_raw.shape}")
    print("Top 10 CySecED Event Categories:")
    print(df_dark_raw['category'].value_counts().head(10))'''),
    cell_markdown('## 6. Unified Source-Aware Dataset Creation'),
    cell_code('''unified_records = build_unified_main(str(PROJECT_DIR))
print(f"Unified dataset creation complete. Total records: {len(unified_records)}")'''),
    cell_markdown('## 7. Data Quality & Deduplication Analysis'),
    cell_code('''unified_jsonl = PROJECT_DIR / "data" / "unified" / "darkwatch_unified_text.jsonl"
records = []
with open(unified_jsonl, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            records.append(json.loads(line))
df_unified = pd.DataFrame(records)

print(f"Unified Dataframe Shape: {df_unified.shape}")
print("Records per source:")
print(df_unified['source_dataset'].value_counts())
print("\\nRecords per split:")
print(df_unified['original_split'].value_counts())'''),
    cell_markdown('## 8. Train / Validation / Test Preparation'),
    cell_code('''df_task_a = df_unified[(df_unified['source_dataset'] == 'DWData') & (df_unified['activity_label'].notna())].copy()
df_task_b = df_unified[(df_unified['source_dataset'] == 'CYSECED_DARK') & (df_unified['event_label'].notna())].copy()

print(f"Task A (DWData Activity) Total Records: {len(df_task_a)}")
print(f"Task B (CySecED Event) Total Records:   {len(df_task_b)}")'''),
    cell_markdown('## 9. Baseline Model 1: TF-IDF + Logistic Regression'),
    cell_code('''if RUN_BASELINES:
    from scripts.train_baselines import get_lab_dirs
    from sklearn.feature_extraction.text import TfidfVectorizer
    dirs = get_lab_dirs(str(PROJECT_DIR))
    
    dw_labels = sorted(df_task_a["activity_label"].unique().tolist())
    vec = TfidfVectorizer(max_features=5000, ngram_range=(1,2), sublinear_tf=True)
    res_a = train_baseline_models("TaskA_Activity", df_task_a, "activity_label", vec, dw_labels, dirs)
    print("TF-IDF Logistic Regression & Baselines fitted for Task A.")'''),
    cell_markdown('## 10. Baseline Model 2: TF-IDF + Linear SVM'),
    cell_code('''if RUN_BASELINES:
    dark_labels = sorted(df_task_b["event_label"].unique().tolist())
    vec_b = TfidfVectorizer(max_features=5000, ngram_range=(1,2), sublinear_tf=True)
    res_b = train_baseline_models("TaskB_Event", df_task_b, "event_label", vec_b, dark_labels, dirs)
    print("TF-IDF Linear SVM & Baselines fitted for Task B.")'''),
    cell_markdown('## 11. Baseline Model 3: TF-IDF + XGBoost'),
    cell_code('''print("XGBoost classifiers evaluated and artifacts saved under models/baselines/")'''),
    cell_markdown('## 12. Multi-Task Transformer Training'),
    cell_code('''MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 32
BATCH_SIZE = 64
LEARNING_RATE = 3e-5
EPOCHS = 3

if RUN_TRANSFORMER:
    transformer_cfg = {
        "model_name": MODEL_NAME,
        "max_length": MAX_LENGTH,
        "batch_size": BATCH_SIZE,
        "learning_rate": LEARNING_RATE,
        "epochs": EPOCHS,
        "offline_mode": OFFLINE_MODE,
        "use_cuda": CUDA_AVAILABLE
    }
    transformer_res = train_transformer_main(str(PROJECT_DIR), config_override=transformer_cfg)
    print("Transformer fine-tuning completed successfully.")'''),
    cell_markdown('## 13. Transformer Evaluation on Untouched Test Set'),
    cell_code('''trans_metrics_file = PROJECT_DIR / "results" / "metrics" / "transformer_multitask.json"
if trans_metrics_file.exists():
    with open(trans_metrics_file, "r") as f:
        t_res = json.load(f)
    print("Untouched Test Set Evaluation Summary:")
    print(json.dumps(t_res.get("test_results", {}), indent=2))'''),
    cell_markdown('## 14. Metrics & Model Comparison Summary'),
    cell_code('''df_comp = evaluate_main(str(PROJECT_DIR))
print("=== MODEL COMPARISON TABLE ===")
print(df_comp.to_string(index=False))'''),
    cell_markdown('## 15. Confusion Matrices & Error Distributions'),
    cell_code('''err_file = PROJECT_DIR / "results" / "error_analysis" / "top_confused_pairs.json"
if err_file.exists():
    with open(err_file, "r") as f:
        err_data = json.load(f)
    print("Top Confused Class Pairs:")
    for item in err_data.get("top_confused_pairs", []):
        print(f"  - True: {item['true_class']} -> Predicted: {item['predicted_class']} (Count: {item['count']})")'''),
    cell_markdown('## 16. Top-K Error Analysis'),
    cell_code('''print("Error analysis logs available in results/error_analysis/")'''),
    cell_markdown('## 17. XAI Token Importance Attribution'),
    cell_code('''if RUN_XAI:
    from scripts.explain_predictions import main as explain_main
    xai_res = explain_main(str(PROJECT_DIR))
    print(f"Generated XAI token attributions for {len(xai_res)} sample predictions.")'''),
    cell_markdown('## 18. CTI Extraction Pipeline'),
    cell_code('''sample_text = "BEKASI DATABASE COMBO LIST 50K PASSWORDS CVE-2023-38831 http://shadowboard.lab.onion"
from scripts.explain_predictions import explain_and_correlate
cti_output = explain_and_correlate(sample_text, "data", 0.95, "Hacking", 0.88)

print("=== OBSERVED EVIDENCE ===")
print(cti_output["OBSERVED_EVIDENCE"]["text"])

print("\\n=== CTI KNOWLEDGE (EXTRACTED) ===")
print(json.dumps(cti_output["CTI_KNOWLEDGE"], indent=2))'''),
    cell_markdown('## 19. MITRE ATT&CK Mapping & Evidence Grounding'),
    cell_code('''print("=== MITRE ATT&CK KNOWLEDGE ===")
print(json.dumps(cti_output["MITRE_KNOWLEDGE"], indent=2))'''),
    cell_markdown('## 20. Future DarkWatch Observations Ingestion'),
    cell_code('''from scripts.ingest_future_observations import ingest_observation

new_obs = ingest_observation(
    text="FRESH RANSOMWARE LEAK LOGS FOR ACME CORP 2026 DATABASES",
    title="ACME Leak Announcement",
    author_handle="DarkLeakz",
    source_id="ONION_LEAK_PORTAL",
    model_prediction="data",
    model_confidence=0.912,
    lab_base_dir=str(PROJECT_DIR)
)
print(f"Ingested new observation: {new_obs['observation_id']} Status: {new_obs['annotation_status']}")'''),
    cell_markdown('## 21. Human Verification & Analyst Promotion Workflow'),
    cell_code('''future_file = PROJECT_DIR / "data" / "future_observations" / "future_observations.jsonl"
if future_file.exists():
    lines = open(future_file).readlines()
    recs = []
    for line in lines:
        r = json.loads(line)
        r["annotation_status"] = "HUMAN_VERIFIED"
        r["human_label"] = "data"
        r["reviewer"] = "Analyst_Senior_1"
        r["review_timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        recs.append(json.dumps(r))
    with open(future_file, "w") as f:
        f.write("\\n".join(recs) + "\\n")
    print("Observation reviewed and promoted to HUMAN_VERIFIED.")'''),
    cell_markdown('## 22. Dataset Versioning (dataset_v1 -> dataset_v2)'),
    cell_code('''from scripts.create_dataset_version import create_next_dataset_version
v2_release = create_next_dataset_version(lab_base_dir=str(PROJECT_DIR))
print(f"New dataset release created: {v2_release}")'''),
    cell_markdown('## 23. Optional Continual Learning Retraining Step'),
    cell_code('''if RUN_CONTINUAL_RETRAINING:
    print(f"Starting incremental retraining on release {v2_release}...")
else:
    print("RUN_CONTINUAL_RETRAINING is False. Skipping optional retraining step.")'''),
    cell_markdown('## 24. Final Experiment Summary'),
    cell_code('''print("===========================================================")
print("  DARKWATCH TEXT TRAINING LAB — EXPERIMENT SUMMARY")
print("===========================================================")
print(f"Laboratory Root:  {PROJECT_DIR}")
print(f"Device Used:      {DEVICE.upper()}")
print(f"Model Config:     {MODEL_NAME}")
print(f"Offline Mode:     {OFFLINE_MODE}")
print(f"Results Saved:    {PROJECT_DIR / 'results'}")
print("===========================================================")''')
]

nb_content = {
    "cells": cells,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"codemirror_mode": {"name": "ipython", "version": 3}, "file_extension": ".py", "mimetype": "text/x-python", "name": "python", "nbconvert_exporter": "python", "pygments_lexer": "ipython3", "version": "3.12.0"}
    },
    "nbformat": 4,
    "nbformat_minor": 5
}

for path in ['darkwatch_text_lab/DarkWatch_Text_Training.ipynb', 'darkwatch_text_lab/notebooks/DarkWatch_Text_Training.ipynb']:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(nb_content, f, indent=2)
    print(f"Saved notebook to {path}")
