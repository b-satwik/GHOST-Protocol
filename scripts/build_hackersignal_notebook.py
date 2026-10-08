#!/usr/bin/env python3
"""
Generator script for DarkWatch_XAI_DistilBERT_HackerSignal.ipynb
Builds a clean, runnable, research-quality Google Colab notebook.
"""

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
    cell_markdown('# DarkWatch XAI — DistilBERT HackerSignal Task 2 Training Laboratory 🛡️\n\n**Dataset**: Hugging Face `DatasetSubmission/HackerSignal` (`task2_exploit_type` / `task2_etc`)  \n**Task**: Exploit Type Classification (8 classes)  \n**Model**: `distilbert-base-uncased`  \n**Target**: Google Colab GPU / Drive Persistence'),
    
    cell_markdown('## 1. Mount Google Drive'),
    cell_code('''import sys
import os

# Mount Google Drive when running in Google Colab
if "google.colab" in sys.modules:
    from google.colab import drive
    drive.mount("/content/drive")
    print("Google Drive mounted successfully.")
else:
    print("Running in local environment (Colab drive mount skipped).")'''),
    
    cell_markdown('## 2. Directory Structure Setup'),
    cell_code('''from pathlib import Path

if "google.colab" in sys.modules:
    DRIVE_BASE_DIR = Path("/content/drive/MyDrive/DarkWatch_XAI/distilbert_hackersignal")
else:
    DRIVE_BASE_DIR = Path.cwd() / "DarkWatch_XAI" / "distilbert_hackersignal"

subdirs = ["checkpoints", "final_model", "tokenizer", "metrics", "logs", "predictions"]
for sd in subdirs:
    (DRIVE_BASE_DIR / sd).mkdir(parents=True, exist_ok=True)

print(f"Directory structure initialized under: {DRIVE_BASE_DIR}")
for sd in subdirs:
    print(f"  - {(DRIVE_BASE_DIR / sd)}")'''),
    
    cell_markdown('## 3. Install & Import Required Libraries'),
    cell_code('''!pip install -q transformers datasets evaluate scikit-learn pandas numpy matplotlib seaborn accelerate

import json
import time
import torch
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

import sklearn
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support

import transformers
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding,
    EarlyStoppingCallback,
    set_seed
)

import datasets
from datasets import load_dataset
import evaluate

# Set seed for reproducibility
SEED = 42
set_seed(SEED)

print("Environment Dependencies Loaded:")
print(f"  PyTorch:      {torch.__version__} (CUDA: {torch.cuda.is_available()})")
print(f"  Transformers: {transformers.__version__}")
print(f"  Datasets:     {datasets.__version__}")
if torch.cuda.is_available():
    print(f"  GPU Device:   {torch.cuda.get_device_name(0)}")'''),
    
    cell_markdown('## 4. Load HackerSignal Task 2 Dataset'),
    cell_code('''# Load HackerSignal Task 2 Exploit Type Classification configuration
try:
    dataset = load_dataset("DatasetSubmission/HackerSignal", "task2_exploit_type")
    config_used = "task2_exploit_type"
except Exception as e:
    print(f"Fallback to task2_etc: {e}")
    dataset = load_dataset("DatasetSubmission/HackerSignal", "task2_etc")
    config_used = "task2_etc"

print(f"Successfully loaded HackerSignal configuration: {config_used}")
print(dataset)'''),
    
    cell_markdown('## 5. Schema Inspection & Dataset Statistics'),
    cell_code('''print("=== DATASET SPLITS & EXEMPLARS ===")
print(f"Train samples:      {len(dataset['train'])}")
print(f"Validation samples: {len(dataset['validation'])}")
print(f"Test samples:       {len(dataset['test'])}")
print(f"Column Names:       {dataset['train'].column_names}")

print("\\nSample Record [Train #0]:")
sample_rec = dataset['train'][0]
print(f"  ID:        {sample_rec.get('id')}")
print(f"  Label:     {sample_rec.get('label')}")
print(f"  Source:    {sample_rec.get('source')}")
print(f"  Timestamp: {sample_rec.get('timestamp')}")
print(f"  Text Snippet (first 200 chars): {sample_rec.get('text', '')[:200]}...")

# Inspect label distribution
train_df = pd.DataFrame(dataset['train'])
val_df = pd.DataFrame(dataset['validation'])
test_df = pd.DataFrame(dataset['test'])

print("\\nTrain Label Distribution:")
print(train_df['label'].value_counts())
print("\\nTest Label Distribution (Temporal OOD Split):")
print(test_df['label'].value_counts())'''),
    
    cell_markdown('## 6. Build Dynamic Label Mapping'),
    cell_code('''unique_labels = sorted(list(set(dataset["train"]["label"])))
num_labels = len(unique_labels)

label2id = {label: i for i, label in enumerate(unique_labels)}
id2label = {i: label for i, label in enumerate(unique_labels)}

print(f"Discovered {num_labels} Exploit Type Classes:")
for i, l in id2label.items():
    print(f"  {i}: {l}")

label_map_path = DRIVE_BASE_DIR / "metrics" / "label_mapping.json"
with open(label_map_path, "w") as f:
    json.dump({"label2id": label2id, "id2label": id2label}, f, indent=2)
print(f"Saved label mapping to {label_map_path}")'''),
    
    cell_markdown('## 7. Tokenization & Dynamic Padding Setup'),
    cell_code('''MODEL_NAME = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def preprocess_function(examples):
    # Tokenize text with truncation up to 512 tokens
    tokenized = tokenizer(examples["text"], truncation=True, max_length=512)
    # Map label string to integer ID
    tokenized["label"] = [label2id[l] for l in examples["label"]]
    return tokenized

print("Tokenizing HackerSignal dataset splits...")
encoded_dataset = dataset.map(preprocess_function, batched=True, remove_columns=dataset["train"].column_names)
data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

print("Tokenization completed. Encoded features:", encoded_dataset["train"].column_names)'''),
    
    cell_markdown('## 8. Model Architecture & Fine-Tuning Setup'),
    cell_code('''model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=num_labels,
    id2label=id2label,
    label2id=label2id
)

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    
    acc = accuracy_score(labels, preds)
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(labels, preds, average="macro", zero_division=0)
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(labels, preds, average="weighted", zero_division=0)
    
    return {
        "accuracy": acc,
        "macro_precision": p_macro,
        "macro_recall": r_macro,
        "macro_f1": f1_macro,
        "weighted_f1": f1_weighted
    }

# Fine-tuning Hyperparameters
use_gpu = torch.cuda.is_available()
batch_size = 16 if use_gpu else 8
eval_batch_size = 32 if use_gpu else 16

training_args = TrainingArguments(
    output_dir=str(DRIVE_BASE_DIR / "checkpoints"),
    logging_dir=str(DRIVE_BASE_DIR / "logs"),
    eval_strategy="epoch",
    save_strategy="epoch",
    learning_rate=2e-5,
    per_device_train_batch_size=batch_size,
    per_device_eval_batch_size=eval_batch_size,
    num_train_epochs=3,
    weight_decay=0.01,
    fp16=use_gpu,
    load_best_model_at_end=True,
    metric_for_best_model="macro_f1",
    greater_is_better=True,
    logging_steps=100,
    save_total_limit=2,
    seed=SEED,
    report_to="none"
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=encoded_dataset["train"],
    eval_dataset=encoded_dataset["validation"],
    tokenizer=tokenizer,
    data_collator=data_collator,
    compute_metrics=compute_metrics,
    callbacks=[EarlyStoppingCallback(early_stopping_patience=2)]
)

print(f"Trainer configured on {'GPU' if use_gpu else 'CPU'}. Starting fine-tuning...")
train_result = trainer.train()
print("Fine-tuning complete!")'''),
    
    cell_markdown('## 9. Validation Evaluation & Best Checkpoint Loading'),
    cell_code('''val_metrics = trainer.evaluate(encoded_dataset["validation"])
print("=== VALIDATION METRICS ===")
for k, v in val_metrics.items():
    print(f"  {k}: {v}")

val_metrics_path = DRIVE_BASE_DIR / "metrics" / "val_metrics.json"
with open(val_metrics_path, "w") as f:
    json.dump(val_metrics, f, indent=2)'''),
    
    cell_markdown('## 10. Final Evaluation on Untouched Temporal/OOD Test Split'),
    cell_code('''print("Executing final evaluation on untouched temporal test split (1,735 records)...")
test_results = trainer.predict(encoded_dataset["test"])
test_metrics = test_results.metrics

test_preds = np.argmax(test_results.predictions, axis=-1)
test_trues = [label2id[l] for l in dataset["test"]["label"]]

test_acc = accuracy_score(test_trues, test_preds)
p_m, r_m, f1_m, _ = precision_recall_fscore_support(test_trues, test_preds, average="macro", zero_division=0)
p_w, r_w, f1_w, _ = precision_recall_fscore_support(test_trues, test_preds, average="weighted", zero_division=0)

report_dict = classification_report(test_trues, test_preds, target_names=[id2label[i] for i in range(num_labels)], output_dict=True, zero_division=0)
cm = confusion_matrix(test_trues, test_preds)

print("=== FINAL TEST METRICS (TEMPORAL OOD) ===")
print(f"  Accuracy:         {test_acc:.4f}")
print(f"  Macro Precision:  {p_m:.4f}")
print(f"  Macro Recall:     {r_m:.4f}")
print(f"  Macro F1:         {f1_m:.4f}")
print(f"  Weighted F1:      {f1_w:.4f}")

# Save metrics & report
test_metrics_summary = {
    "test_accuracy": test_acc,
    "test_macro_precision": p_m,
    "test_macro_recall": r_m,
    "test_macro_f1": f1_m,
    "test_weighted_f1": f1_w,
    "test_raw_metrics": test_metrics
}

with open(DRIVE_BASE_DIR / "metrics" / "test_metrics.json", "w") as f:
    json.dump(test_metrics_summary, f, indent=2)

with open(DRIVE_BASE_DIR / "metrics" / "classification_report.json", "w") as f:
    json.dump(report_dict, f, indent=2)'''),
    
    cell_markdown('## 11. Plot & Save Confusion Matrix & Predictions CSV'),
    cell_code('''# Confusion Matrix Plot
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=[id2label[i] for i in range(num_labels)], yticklabels=[id2label[i] for i in range(num_labels)])
plt.title("HackerSignal Task 2 Test Set Confusion Matrix")
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()

cm_path = DRIVE_BASE_DIR / "metrics" / "confusion_matrix.png"
plt.savefig(cm_path, dpi=300)
plt.close()
print(f"Saved confusion matrix plot to {cm_path}")

# Save predictions CSV
test_df_out = pd.DataFrame({
    "id": dataset["test"]["id"],
    "text_snippet": [t[:100] for t in dataset["test"]["text"]],
    "true_label": dataset["test"]["label"],
    "predicted_label": [id2label[p] for p in test_preds],
    "correct": [t == p for t, p in zip([label2id[l] for l in dataset["test"]["label"]], test_preds)]
})

preds_csv_path = DRIVE_BASE_DIR / "predictions" / "test_predictions.csv"
test_df_out.to_csv(preds_csv_path, index=False)
print(f"Saved test predictions CSV to {preds_csv_path}")'''),
    
    cell_markdown('## 12. Save Final Model & Tokenizer to Google Drive'),
    cell_code('''final_model_dir = DRIVE_BASE_DIR / "final_model"
tokenizer_dir = DRIVE_BASE_DIR / "tokenizer"

model.save_pretrained(final_model_dir)
tokenizer.save_pretrained(tokenizer_dir)

print(f"Saved final DistilBERT model to: {final_model_dir}")
print(f"Saved Tokenizer to:             {tokenizer_dir}")'''),
    
    cell_markdown('## 13. Final Experiment Summary Output'),
    cell_code('''summary_str = f"""
========================================
DARKWATCH DISTILBERT TRAINING COMPLETE
========================================
Dataset: HackerSignal Task 2
Model: distilbert-base-uncased
Classes: {num_labels}
Train samples: {len(dataset['train'])}
Validation samples: {len(dataset['validation'])}
Test samples: {len(dataset['test'])}

Test Accuracy: {test_acc:.4f}
Test Macro Precision: {p_m:.4f}
Test Macro Recall: {r_m:.4f}
Test Macro F1: {f1_m:.4f}

Model saved to:
{DRIVE_BASE_DIR / 'final_model'}

Tokenizer saved to:
{DRIVE_BASE_DIR / 'tokenizer'}

Metrics saved to:
{DRIVE_BASE_DIR / 'metrics'}

========================================
"""
print(summary_str.strip())'''),
    
    cell_markdown('## 14. Text Prediction & Inference Function'),
    cell_code('''def predict_text(text, model_path=None, tokenizer_path=None):
    if model_path is None:
        model_path = DRIVE_BASE_DIR / "final_model"
    if tokenizer_path is None:
        tokenizer_path = DRIVE_BASE_DIR / "tokenizer"
        
    eval_tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
    eval_model = AutoModelForSequenceClassification.from_pretrained(model_path)
    eval_model.eval()
    
    inputs = eval_tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = eval_model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1).squeeze(0).cpu().numpy()
        
    pred_idx = int(np.argmax(probs))
    pred_label = eval_model.config.id2label[pred_idx]
    confidence = float(probs[pred_idx])
    
    all_probs = {eval_model.config.id2label[i]: float(probs[i]) for i in range(len(probs))}
    
    return {
        "text_snippet": text[:100],
        "predicted_class": pred_label,
        "confidence": confidence,
        "class_probabilities": all_probs
    }

# Example Usage
sample_exploit = """
##
# AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow
##
require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
    include Msf::Exploit::Remote::SunRPC
    def brute_exploit(brute_target)
        buf = rand_text_alphanumeric(payload_space)
        buf << [brute_target['Ret']].pack('N')
    end
end
"""

inference_result = predict_text(sample_exploit)
print("=== SAMPLE INFERENCE RESULT ===")
print(json.dumps(inference_result, indent=2))''')
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

output_paths = [
    "DarkWatch_XAI_DistilBERT_HackerSignal.ipynb",
    "colab/DarkWatch_XAI_DistilBERT_HackerSignal.ipynb",
    "darkwatch_text_lab/notebooks/DarkWatch_XAI_DistilBERT_HackerSignal.ipynb"
]

for p in output_paths:
    os.makedirs(os.path.dirname(p) if os.path.dirname(p) else ".", exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(nb_content, f, indent=2)
    print(f"Saved notebook to {p}")
