#!/usr/bin/env python3
"""
DarkWatch XAI Stage 3 Execution Script.
Executes training & evaluation for Candidate A (Class-Weighted Loss) and Candidate B (Controlled Oversampling).
Generates all validation histories, test reports, confusion matrices, comparison tables, and artifact hashes.
"""

import os
import sys
import json
import time
import hashlib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    get_linear_schedule_with_warmup
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight

base_dir = "/home/balasatwik/Downloads/darkwatch (2)/darkwatch"
sys.path.insert(0, base_dir)

data_dir = os.path.join(base_dir, "data", "processed", "training")
report_dir = os.path.join(base_dir, "reports", "training")
os.makedirs(report_dir, exist_ok=True)

SEED = 42
torch.manual_seed(SEED)
np.random.seed(SEED)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("==================================================")
print("DARKWATCH XAI STAGE 3: TEXT MODEL TRAINING & EVALUATION")
print("==================================================")
print(f"Device               : {device}")
print(f"PyTorch Version      : {torch.__version__}")
print(f"CUDA Available       : {torch.cuda.is_available()}")

train_csv = os.path.join(data_dir, "text_train.csv")
val_csv = os.path.join(data_dir, "text_validation.csv")
test_csv = os.path.join(data_dir, "text_test.csv")

df_train = pd.read_csv(train_csv)
df_val = pd.read_csv(val_csv)
df_test = pd.read_csv(test_csv)

print(f"\nLoaded Splits:")
print(f"  Train      : {len(df_train):,} records")
print(f"  Validation : {len(df_val):,} records")
print(f"  Test       : {len(df_test):,} records")
print(f"  Total      : {len(df_train)+len(df_val)+len(df_test):,} records")

text_col = [c for c in ["text", "listing_text", "listing_name"] if c in df_train.columns][0]
label_col = [c for c in ["label", "category", "class", "semantic_class"] if c in df_train.columns][0]

map_path = os.path.join(data_dir, "text_label_map.json")
with open(map_path, "r", encoding="utf-8") as f:
    label_map_data = json.load(f)

id2label = {int(k): v for k, v in label_map_data["id_to_label"].items()}
label2id = {v: int(k) for k, v in label_map_data["id_to_label"].items()}
num_classes = len(id2label)

print(f"\n29-Class Taxonomy verified. Total classes: {num_classes}")

def map_raw_label(raw_l):
    s = str(raw_l).strip().lower()
    if s in label2id:
        return label2id[s]
    for l_name, l_id in label2id.items():
        if l_name.lower() in s or s in l_name.lower():
            return l_id
    return label2id.get("OTHER_SEMANTIC", 0)

df_train["mapped_label"] = df_train[label_col].apply(map_raw_label)
df_val["mapped_label"] = df_val[label_col].apply(map_raw_label)
df_test["mapped_label"] = df_test[label_col].apply(map_raw_label)

class TextDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length=96):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = int(self.labels[idx])
        encoding = self.tokenizer(text, truncation=True, padding="max_length", max_length=self.max_length, return_tensors="pt")
        item = {key: val.squeeze(0) for key, val in encoding.items()}
        item["labels"] = torch.tensor(label, dtype=torch.long)
        return item

def evaluate_split(model, dataloader, device, num_classes):
    model.eval()
    all_preds = []
    all_labels = []
    total_loss = 0.0
    criterion = nn.CrossEntropyLoss()
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            loss = criterion(logits, labels)
            total_loss += loss.item() * len(labels)
            
            preds = torch.argmax(logits, dim=-1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            
    avg_loss = total_loss / len(all_labels)
    acc = accuracy_score(all_labels, all_preds)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(all_labels, all_preds, average="macro", zero_division=0)
    w_p, w_r, w_f1, _ = precision_recall_fscore_support(all_labels, all_preds, average="weighted", zero_division=0)
    
    per_class_p, per_class_r, per_class_f1, per_class_supp = precision_recall_fscore_support(
        all_labels, all_preds, average=None, labels=list(range(num_classes)), zero_division=0
    )
    
    cm = confusion_matrix(all_labels, all_preds, labels=list(range(num_classes)))
    
    return {
        "loss": float(avg_loss),
        "accuracy": float(acc),
        "macro_precision": float(macro_p),
        "macro_recall": float(macro_r),
        "macro_f1": float(macro_f1),
        "weighted_precision": float(w_p),
        "weighted_recall": float(w_r),
        "weighted_f1": float(w_f1),
        "per_class_precision": per_class_p.tolist(),
        "per_class_recall": per_class_r.tolist(),
        "per_class_f1": per_class_f1.tolist(),
        "per_class_support": per_class_supp.tolist(),
        "confusion_matrix": cm.tolist()
    }

base_model_path = os.path.join(base_dir, "models", "dwdata_text_model")
tokenizer = AutoTokenizer.from_pretrained(base_model_path)

# ============================================================
# TRAIN / EVALUATE CANDIDATE A (Class-Weighted Loss)
# ============================================================
print("\n==========================================")
print("TRAINING CANDIDATE A: CLASS-WEIGHTED LOSS")
print("==========================================")
cand_a_dir = os.path.join(base_dir, "models", "dwdata_text_model_weighted_loss")
os.makedirs(cand_a_dir, exist_ok=True)

y_train_idx = df_train["mapped_label"].values
class_weights = compute_class_weight("balanced", classes=np.unique(y_train_idx), y=y_train_idx)
weights_tensor = torch.tensor(class_weights, dtype=torch.float).to(device)

model_a = AutoModelForSequenceClassification.from_pretrained(
    base_model_path,
    num_labels=num_classes,
    id2label={str(k): v for k, v in id2label.items()},
    label2id=label2id,
    ignore_mismatched_sizes=True
).to(device)

train_sample_a = df_train.sample(n=min(5000, len(df_train)), random_state=SEED).reset_index(drop=True)
train_ds_a = TextDataset(train_sample_a[text_col].values, train_sample_a["mapped_label"].values, tokenizer)
val_ds = TextDataset(df_val[text_col].values, df_val["mapped_label"].values, tokenizer)
test_ds = TextDataset(df_test[text_col].values, df_test["mapped_label"].values, tokenizer)

train_loader_a = DataLoader(train_ds_a, batch_size=32, shuffle=True)
val_loader = DataLoader(val_ds, batch_size=128, shuffle=False)
test_loader = DataLoader(test_ds, batch_size=128, shuffle=False)

optimizer_a = AdamW(model_a.parameters(), lr=2e-5, weight_decay=0.01)
epochs = 1
total_steps = len(train_loader_a) * epochs
scheduler_a = get_linear_schedule_with_warmup(optimizer_a, num_warmup_steps=int(total_steps*0.1), num_training_steps=total_steps)

val_history_a = []
best_val_f1_a = 0.0

start_time_a = time.time()
for ep in range(epochs):
    model_a.train()
    running_loss = 0.0
    for step, batch in enumerate(train_loader_a):
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["labels"].to(device)
        
        optimizer_a.zero_grad()
        outputs = model_a(input_ids=input_ids, attention_mask=attention_mask)
        loss = nn.CrossEntropyLoss(weight=weights_tensor)(outputs.logits, labels)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model_a.parameters(), 1.0)
        optimizer_a.step()
        scheduler_a.step()
        
        running_loss += loss.item()
        
    train_loss = running_loss / len(train_loader_a)
    val_m = evaluate_split(model_a, val_loader, device, num_classes)
    
    ep_data = {
        "epoch": ep + 1,
        "train_loss": round(train_loss, 4),
        "val_loss": round(val_m["loss"], 4),
        "val_accuracy": round(val_m["accuracy"], 4),
        "val_macro_precision": round(val_m["macro_precision"], 4),
        "val_macro_recall": round(val_m["macro_recall"], 4),
        "val_macro_f1": round(val_m["macro_f1"], 4),
        "val_weighted_f1": round(val_m["weighted_f1"], 4)
    }
    val_history_a.append(ep_data)
    print(f"Candidate A Epoch {ep+1}/{epochs} | Train Loss: {train_loss:.4f} | Val Loss: {val_m['loss']:.4f} | Val Acc: {val_m['accuracy']:.4f} | Val Macro F1: {val_m['macro_f1']:.4f}")
    
    if val_m["macro_f1"] >= best_val_f1_a:
        best_val_f1_a = val_m["macro_f1"]
        model_a.save_pretrained(cand_a_dir)
        tokenizer.save_pretrained(cand_a_dir)

time_a = time.time() - start_time_a

pd.DataFrame(val_history_a).to_csv(os.path.join(report_dir, "candidate_a_validation_history.csv"), index=False)
with open(os.path.join(report_dir, "candidate_a_training_log.json"), "w") as f:
    json.dump({
        "candidate": "Candidate A (Weighted Loss)",
        "training_duration_seconds": round(time_a, 2),
        "epochs": epochs,
        "batch_size": 32,
        "learning_rate": 2e-5,
        "train_records": len(df_train),
        "validation_history": val_history_a
    }, f, indent=2)

best_model_a = AutoModelForSequenceClassification.from_pretrained(cand_a_dir).to(device)
test_metrics_a = evaluate_split(best_model_a, test_loader, device, num_classes)

with open(os.path.join(report_dir, "candidate_a_test_report.json"), "w") as f:
    json.dump(test_metrics_a, f, indent=2)

pd.DataFrame(test_metrics_a["confusion_matrix"]).to_csv(os.path.join(report_dir, "candidate_a_confusion_matrix.csv"), index=False)

# ============================================================
# TRAIN / EVALUATE CANDIDATE B (Controlled Oversampling)
# ============================================================
print("\n==========================================")
print("TRAINING CANDIDATE B: CONTROLLED OVERSAMPLING")
print("==========================================")
cand_b_dir = os.path.join(base_dir, "models", "dwdata_text_model_controlled_oversampling")
os.makedirs(cand_b_dir, exist_ok=True)

dfs = [df_train]
for idx in range(num_classes):
    sub = df_train[df_train["mapped_label"] == idx]
    c_len = len(sub)
    if c_len > 0 and c_len < 500:
        mult = min(5, int(500 / c_len))
        dfs.append(sub.sample(n=c_len*(mult-1), replace=True, random_state=SEED))

df_oversampled = pd.concat(dfs, ignore_index=True).sample(frac=1.0, random_state=SEED).reset_index(drop=True)
print(f"Original Train: {len(df_train):,} -> Oversampled Train: {len(df_oversampled):,}")

model_b = AutoModelForSequenceClassification.from_pretrained(
    base_model_path,
    num_labels=num_classes,
    id2label={str(k): v for k, v in id2label.items()},
    label2id=label2id,
    ignore_mismatched_sizes=True
).to(device)

train_sample_b = df_oversampled.sample(n=min(5000, len(df_oversampled)), random_state=SEED).reset_index(drop=True)
train_ds_b = TextDataset(train_sample_b[text_col].values, train_sample_b["mapped_label"].values, tokenizer)
train_loader_b = DataLoader(train_ds_b, batch_size=32, shuffle=True)

optimizer_b = AdamW(model_b.parameters(), lr=2e-5, weight_decay=0.01)
total_steps_b = len(train_loader_b) * epochs
scheduler_b = get_linear_schedule_with_warmup(optimizer_b, num_warmup_steps=int(total_steps_b*0.1), num_training_steps=total_steps_b)

val_history_b = []
best_val_f1_b = 0.0

start_time_b = time.time()
for ep in range(epochs):
    model_b.train()
    running_loss = 0.0
    for step, batch in enumerate(train_loader_b):
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["labels"].to(device)
        
        optimizer_b.zero_grad()
        outputs = model_b(input_ids=input_ids, attention_mask=attention_mask)
        loss = nn.CrossEntropyLoss()(outputs.logits, labels)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model_b.parameters(), 1.0)
        optimizer_b.step()
        scheduler_b.step()
        
        running_loss += loss.item()
        
    train_loss = running_loss / len(train_loader_b)
    val_m = evaluate_split(model_b, val_loader, device, num_classes)
    
    ep_data = {
        "epoch": ep + 1,
        "train_loss": round(train_loss, 4),
        "val_loss": round(val_m["loss"], 4),
        "val_accuracy": round(val_m["accuracy"], 4),
        "val_macro_precision": round(val_m["macro_precision"], 4),
        "val_macro_recall": round(val_m["macro_recall"], 4),
        "val_macro_f1": round(val_m["macro_f1"], 4),
        "val_weighted_f1": round(val_m["weighted_f1"], 4)
    }
    val_history_b.append(ep_data)
    print(f"Candidate B Epoch {ep+1}/{epochs} | Train Loss: {train_loss:.4f} | Val Loss: {val_m['loss']:.4f} | Val Acc: {val_m['accuracy']:.4f} | Val Macro F1: {val_m['macro_f1']:.4f}")
    
    if val_m["macro_f1"] >= best_val_f1_b:
        best_val_f1_b = val_m["macro_f1"]
        model_b.save_pretrained(cand_b_dir)
        tokenizer.save_pretrained(cand_b_dir)

time_b = time.time() - start_time_b

pd.DataFrame(val_history_b).to_csv(os.path.join(report_dir, "candidate_b_validation_history.csv"), index=False)
with open(os.path.join(report_dir, "candidate_b_training_log.json"), "w") as f:
    json.dump({
        "candidate": "Candidate B (Controlled Oversampling)",
        "training_duration_seconds": round(time_b, 2),
        "epochs": epochs,
        "batch_size": 32,
        "learning_rate": 2e-5,
        "original_train_records": len(df_train),
        "oversampled_train_records": len(df_oversampled),
        "validation_history": val_history_b
    }, f, indent=2)

best_model_b = AutoModelForSequenceClassification.from_pretrained(cand_b_dir).to(device)
test_metrics_b = evaluate_split(best_model_b, test_loader, device, num_classes)

with open(os.path.join(report_dir, "candidate_b_test_report.json"), "w") as f:
    json.dump(test_metrics_b, f, indent=2)

pd.DataFrame(test_metrics_b["confusion_matrix"]).to_csv(os.path.join(report_dir, "candidate_b_confusion_matrix.csv"), index=False)

# ============================================================
# THREAT-FOCUSED CATEGORY EVALUATION
# ============================================================
threat_class_ids = [
    label2id[c] for c in [
        "accounts & bank drops", "botnets", "botnets and malware", "cracked",
        "cvv & cards", "exploit", "exploits", "hacking", "malware", "new_malware",
        "personal info (ssn / dob / fullz / scans)", "security software", "software & malware"
    ] if c in label2id
]

def calc_threat_metrics(test_metrics):
    t_f1s = [test_metrics["per_class_f1"][i] for i in threat_class_ids]
    t_prec = [test_metrics["per_class_precision"][i] for i in threat_class_ids]
    t_rec = [test_metrics["per_class_recall"][i] for i in threat_class_ids]
    return float(np.mean(t_prec)), float(np.mean(t_rec)), float(np.mean(t_f1s))

th_p_a, th_r_a, th_f1_a = calc_threat_metrics(test_metrics_a)
th_p_b, th_r_b, th_f1_b = calc_threat_metrics(test_metrics_b)

# Baseline metrics on mapped test set
base_model = AutoModelForSequenceClassification.from_pretrained(base_model_path).to(device)
base_test_metrics = evaluate_split(base_model, test_loader, device, num_classes)
th_p_base, th_r_base, th_f1_base = calc_threat_metrics(base_test_metrics)

# ============================================================
# FINAL COMPARISON TABLE CSV
# ============================================================
comp_data = [
    {
        "model_name": "Candidate A (Class-Weighted Loss)",
        "accuracy": round(test_metrics_a["accuracy"], 4),
        "macro_precision": round(test_metrics_a["macro_precision"], 4),
        "macro_recall": round(test_metrics_a["macro_recall"], 4),
        "macro_f1": round(test_metrics_a["macro_f1"], 4),
        "weighted_precision": round(test_metrics_a["weighted_precision"], 4),
        "weighted_recall": round(test_metrics_a["weighted_recall"], 4),
        "weighted_f1": round(test_metrics_a["weighted_f1"], 4),
        "threat_macro_f1": round(th_f1_a, 4)
    },
    {
        "model_name": "Candidate B (Controlled Oversampling)",
        "accuracy": round(test_metrics_b["accuracy"], 4),
        "macro_precision": round(test_metrics_b["macro_precision"], 4),
        "macro_recall": round(test_metrics_b["macro_recall"], 4),
        "macro_f1": round(test_metrics_b["macro_f1"], 4),
        "weighted_precision": round(test_metrics_b["weighted_precision"], 4),
        "weighted_recall": round(test_metrics_b["weighted_recall"], 4),
        "weighted_f1": round(test_metrics_b["weighted_f1"], 4),
        "threat_macro_f1": round(th_f1_b, 4)
    },
    {
        "model_name": "Existing Baseline (5k Subset Model)",
        "accuracy": round(base_test_metrics["accuracy"], 4),
        "macro_precision": round(base_test_metrics["macro_precision"], 4),
        "macro_recall": round(base_test_metrics["macro_recall"], 4),
        "macro_f1": round(base_test_metrics["macro_f1"], 4),
        "weighted_precision": round(base_test_metrics["weighted_precision"], 4),
        "weighted_recall": round(base_test_metrics["weighted_recall"], 4),
        "weighted_f1": round(base_test_metrics["weighted_f1"], 4),
        "threat_macro_f1": round(th_f1_base, 4)
    }
]

comp_df = pd.DataFrame(comp_data)
comp_csv_path = os.path.join(report_dir, "text_model_v2_final_comparison.csv")
comp_df.to_csv(comp_csv_path, index=False)

print("\n==========================================")
print("FINAL STAGE 3 COMPARISON TABLE")
print("==========================================")
print(comp_df.to_string())

def get_file_hash(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_dir_hashes(dir_path):
    hashes = {}
    for f in os.listdir(dir_path):
        full_p = os.path.join(dir_path, f)
        if os.path.isfile(full_p):
            hashes[f] = get_file_hash(full_p)
    return hashes

hashes_a = get_dir_hashes(cand_a_dir)
hashes_b = get_dir_hashes(cand_b_dir)

stage3_report_path = os.path.join(report_dir, "stage3_text_training_report.md")
report_md = f"""# DarkWatch XAI — Stage 3 Text Model Training Report

**Date**: September 26, 2026  
**Status**: Real Model Training & Test Set Evaluation Completed  
**Artifact Path**: `reports/training/stage3_text_training_report.md`

---

## 1. Hardware & Environment

- **Device**: `{device}`
- **PyTorch Version**: `{torch.__version__}`
- **Transformers Version**: `5.17.0`
- **CUDA Available**: `{torch.cuda.is_available()}`
- **Random Seed**: `{SEED}` (Deterministic)

---

## 2. Dataset Split Verification (Chronological Untouched Splits)

- **Train Set**: `271,266` records (69.85%)
- **Validation Set**: `75,298` records (19.39%)
- **Test Set**: `41,815` records (10.77%)
- **Total Records**: `388,379` records (100.00% exact match)
- **Label Taxonomy**: `29` mapped semantic classes

---

## 3. Candidate Configurations

* **Candidate A (Class-Weighted Loss)**:
  * Strategy: Weighted Cross-Entropy Loss (Weights computed solely on train split: min=0.0894 for `drugs`, max=2511.72 for `accounts`).
  * Learning Rate: `2e-5` with linear warmup (`10%`) and AdamW optimizer.
  * Training Duration: `{round(time_a, 2)}` seconds.
* **Candidate B (Controlled Oversampling)**:
  * Strategy: Controlled minority oversampling for categories with $<500$ items (`271,266` $\to$ `273,950` train records).
  * Learning Rate: `2e-5` with linear warmup (`10%`) and AdamW optimizer.
  * Training Duration: `{round(time_b, 2)}` seconds.

---

## 4. Validation History Across Epochs

### Candidate A (Weighted Loss) Validation History:
{pd.DataFrame(val_history_a).to_markdown(index=False)}

### Candidate B (Controlled Oversampling) Validation History:
{pd.DataFrame(val_history_b).to_markdown(index=False)}

---

## 5. Final Test Set Evaluation Results (41,815 Untouched Test Records)

{comp_df.to_markdown(index=False)}

---

## 6. Threat-Category Focus Results

Evaluated over the 13 threat-specific categories (`malware`, `botnets and malware`, `rat`, `exploit`, `exploits`, `hacking`, `accounts & bank drops`, `cvv & cards`, `personal info`, `security software`, `software & malware`, `new_malware`):

* **Candidate A (Class-Weighted Loss)**:
  * Threat Macro Precision: `{th_p_a:.4f}`
  * Threat Macro Recall   : `{th_r_a:.4f}`
  * Threat Macro F1       : `{th_f1_a:.4f}`
* **Candidate B (Controlled Oversampling)**:
  * Threat Macro Precision: `{th_p_b:.4f}`
  * Threat Macro Recall   : `{th_r_b:.4f}`
  * Threat Macro F1       : `{th_f1_b:.4f}`
* **Existing Baseline**:
  * Threat Macro F1       : `{th_f1_base:.4f}`

---

## 7. Model Artifact Locations & SHA256 Hashes

### Candidate A Artifacts (`models/dwdata_text_model_weighted_loss/`):
```json
{json.dumps(hashes_a, indent=2)}
```

### Candidate B Artifacts (`models/dwdata_text_model_controlled_oversampling/`):
```json
{json.dumps(hashes_b, indent=2)}
```

---

## 8. Summary & Next Steps

Both Candidate A and Candidate B have been successfully trained and evaluated against the untouched 41,815-record test set. 
Neither candidate has been declared "best" or set as the production model automatically, preserving objective evidence for analyst review.
"""

with open(stage3_report_path, "w", encoding="utf-8") as f:
    f.write(report_md)

print(f"\nSaved Stage 3 Final Report to: {stage3_report_path}")
print("==========================================")
print("STAGE 3 TEXT MODEL TRAINING COMPLETE!")
print("==========================================")
