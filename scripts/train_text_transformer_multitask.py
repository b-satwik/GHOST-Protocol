#!/usr/bin/env python3
"""
DarkWatch Multi-Task Transformer Model Training
------------------------------------------------
Trains a multi-task DistilBERT model with:
- Shared Transformer encoder backbone
- Activity Classification Head (Task A: DWData 29 classes)
- Event Classification Head (Task B: CySecED Dark 36 classes)

Loss masking is applied so each head is trained strictly on records with valid labels for that task.
"""

import os
import sys
import json
import math
import random
import numpy as np
import pandas as pd
from tqdm import tqdm
from collections import Counter

import torch
import torch.nn as nn
import torch.nn.functional as F
torch.set_num_threads(16)
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoConfig, AutoModel, get_linear_schedule_with_warmup
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNIFIED_JSONL = os.path.join(PROJECT_ROOT, "data", "unified", "darkwatch_unified_text.jsonl")
PRETRAINED_MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "dwdata_text_model")
OUTPUT_MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "text_unified", "transformer_multitask")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results", "text_unified")

os.makedirs(OUTPUT_MODEL_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

class UnifiedTextDataset(Dataset):
    def __init__(self, records, tokenizer, activity_map, event_map, max_length=128):
        self.records = records
        self.tokenizer = tokenizer
        self.activity_map = activity_map
        self.event_map = event_map
        self.max_length = max_length

    def __len__(self):
        return len(self.records)

    def __getitem__(self, idx):
        rec = self.records[idx]
        text = rec.get("text", "") or ""
        
        # Tokenize text
        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
        
        activity_lbl = rec.get("activity_label")
        event_lbl = rec.get("event_label")
        
        act_id = self.activity_map[activity_lbl] if activity_lbl in self.activity_map else -100
        evt_id = self.event_map[event_lbl] if event_lbl in self.event_map else -100
        
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "activity_labels": torch.tensor(act_id, dtype=torch.long),
            "event_labels": torch.tensor(evt_id, dtype=torch.long),
            "source_dataset": rec.get("source_dataset", ""),
            "record_id": rec.get("record_id", "")
        }

class MultiTaskDistilBert(nn.Module):
    def __init__(self, base_model_name_or_path, num_activity_classes, num_event_classes):
        super().__init__()
        if os.path.exists(base_model_name_or_path):
            print(f"Loading base Transformer encoder from local path: {base_model_name_or_path}")
            self.encoder = AutoModel.from_pretrained(base_model_name_or_path)
        else:
            print("Loading default distilbert-base-uncased encoder...")
            self.encoder = AutoModel.from_pretrained("distilbert-base-uncased")
            
        hidden_size = self.encoder.config.hidden_size
        self.dropout = nn.Dropout(0.2)
        
        self.activity_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, num_activity_classes)
        )
        
        self.event_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, num_event_classes)
        )

    def forward(self, input_ids, attention_mask):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        # DistilBERT cls token is output[0][:, 0, :]
        cls_rep = outputs.last_hidden_state[:, 0, :]
        cls_rep = self.dropout(cls_rep)
        
        activity_logits = self.activity_head(cls_rep)
        event_logits = self.event_head(cls_rep)
        
        return activity_logits, event_logits, cls_rep

def compute_task_metrics(y_true, y_pred, class_names):
    if len(y_true) == 0:
        return {"accuracy": 0.0, "macro_f1": 0.0, "weighted_f1": 0.0}
    acc = accuracy_score(y_true, y_pred)
    p_m, r_m, f1_m, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    p_w, r_w, f1_w, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    return {
        "accuracy": float(acc),
        "macro_precision": float(p_m),
        "macro_recall": float(r_m),
        "macro_f1": float(f1_m),
        "weighted_precision": float(p_w),
        "weighted_recall": float(r_w),
        "weighted_f1": float(f1_w),
    }

def evaluate_model(model, dataloader, device, activity_classes, event_classes):
    model.eval()
    act_preds, act_trues = [], []
    evt_preds, evt_trues = [], []
    
    total_loss = 0.0
    act_criterion = nn.CrossEntropyLoss(ignore_index=-100)
    evt_criterion = nn.CrossEntropyLoss(ignore_index=-100)
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            act_labels = batch["activity_labels"].to(device)
            evt_labels = batch["event_labels"].to(device)
            
            act_logits, evt_logits, _ = model(input_ids, attention_mask)
            
            loss_act = act_criterion(act_logits, act_labels)
            loss_evt = evt_criterion(evt_logits, evt_labels)
            
            loss = 0.0
            if not torch.isnan(loss_act) and (act_labels != -100).any():
                loss += loss_act
            if not torch.isnan(loss_evt) and (evt_labels != -100).any():
                loss += loss_evt
            total_loss += loss.item() if isinstance(loss, torch.Tensor) else 0.0
            
            # Collect valid activity preds
            act_mask = (act_labels != -100)
            if act_mask.any():
                act_p = torch.argmax(act_logits[act_mask], dim=-1).cpu().numpy()
                act_t = act_labels[act_mask].cpu().numpy()
                act_preds.extend(act_p)
                act_trues.extend(act_t)
                
            # Collect valid event preds
            evt_mask = (evt_labels != -100)
            if evt_mask.any():
                evt_p = torch.argmax(evt_logits[evt_mask], dim=-1).cpu().numpy()
                evt_t = evt_labels[evt_mask].cpu().numpy()
                evt_preds.extend(evt_p)
                evt_trues.extend(evt_t)
                
    act_metrics = compute_task_metrics(act_trues, act_preds, activity_classes)
    evt_metrics = compute_task_metrics(evt_trues, evt_preds, event_classes)
    avg_loss = total_loss / max(1, len(dataloader))
    
    return avg_loss, act_metrics, evt_metrics, (act_trues, act_preds), (evt_trues, evt_preds)

def main():
    set_seed(42)
    print("[1/5] Loading unified jsonl corpus...")
    records = []
    with open(UNIFIED_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
                
    # Gather unique activity and event classes
    activity_classes = sorted(list({r["activity_label"] for r in records if r["activity_label"] is not None}))
    event_classes = sorted(list({r["event_label"] for r in records if r["event_label"] is not None}))
    
    activity_map = {c: i for i, c in enumerate(activity_classes)}
    event_map = {c: i for i, c in enumerate(event_classes)}
    
    print(f"Loaded Task A Activity Classes ({len(activity_classes)}): {activity_classes[:5]}...")
    print(f"Loaded Task B Event Classes ({len(event_classes)}): {event_classes[:5]}...")
    
    # Save label maps
    label_map_file = os.path.join(OUTPUT_MODEL_DIR, "label_maps.json")
    with open(label_map_file, "w", encoding="utf-8") as f:
        json.dump({
            "activity_classes": activity_classes,
            "activity_map": activity_map,
            "event_classes": event_classes,
            "event_map": event_map
        }, f, indent=2)
        
    # Subsample train_recs for practical CPU training while preserving full Val and Test sets
    np.random.seed(42)
    dw_train = [r for r in train_recs if r["source_dataset"] == "DWData"]
    dark_train = [r for r in train_recs if r["source_dataset"] == "CYSECED_DARK"]
    surf_train = [r for r in train_recs if r["source_dataset"] == "CYSECED_SURFACE"]
    
    # Take all CySecED Dark (since it's small & precious), sample DWData & CySecED Surface
    dw_sample_idx = np.random.choice(len(dw_train), size=min(15000, len(dw_train)), replace=False)
    surf_sample_idx = np.random.choice(len(surf_train), size=min(5000, len(surf_train)), replace=False)
    
    sampled_train_recs = dark_train + [dw_train[i] for i in dw_sample_idx] + [surf_train[i] for i in surf_sample_idx]
    random.seed(42)
    random.shuffle(sampled_train_recs)
    
    print(f"Sampled Training Records: {len(sampled_train_recs)} (DWData={len(dw_sample_idx)}, Dark={len(dark_train)}, Surface={len(surf_sample_idx)})")
    
    train_dataset = UnifiedTextDataset(sampled_train_recs, tokenizer, activity_map, event_map, max_length=32)
    val_dataset = UnifiedTextDataset(val_recs, tokenizer, activity_map, event_map, max_length=32)
    test_dataset = UnifiedTextDataset(test_recs, tokenizer, activity_map, event_map, max_length=32)
    
    # DataLoader batch size
    batch_size = 64
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=4)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=4)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, num_workers=4)
    
    print("[3/5] Instantiating Multi-Task DistilBERT Architecture...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training device: {device}")
    
    model = MultiTaskDistilBert(PRETRAINED_MODEL_DIR, len(activity_classes), len(event_classes))
    model.to(device)
    
    # Class weights for activity and event losses
    act_counts = Counter([r["activity_label"] for r in train_recs if r["activity_label"] is not None])
    evt_counts = Counter([r["event_label"] for r in train_recs if r["event_label"] is not None])
    
    total_act = sum(act_counts.values())
    act_weights = [total_act / max(1, act_counts.get(c, 1)) for c in activity_classes]
    act_weights_tensor = torch.tensor(act_weights, dtype=torch.float).to(device)
    act_weights_tensor = act_weights_tensor / act_weights_tensor.sum() * len(activity_classes)
    
    total_evt = sum(evt_counts.values())
    evt_weights = [total_evt / max(1, evt_counts.get(c, 1)) for c in event_classes]
    evt_weights_tensor = torch.tensor(evt_weights, dtype=torch.float).to(device)
    evt_weights_tensor = evt_weights_tensor / evt_weights_tensor.sum() * len(event_classes)
    
    act_criterion = nn.CrossEntropyLoss(weight=act_weights_tensor, ignore_index=-100)
    evt_criterion = nn.CrossEntropyLoss(weight=evt_weights_tensor, ignore_index=-100)
    
    epochs = 3
    gradient_accumulation_steps = 2
    total_steps = (len(train_loader) // gradient_accumulation_steps) * epochs
    
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-5, weight_decay=0.01)
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=int(total_steps * 0.1), num_training_steps=total_steps)
    
    best_val_score = -1.0
    training_history = []
    
    print(f"[4/5] Starting Multi-Task Fine-Tuning ({epochs} epochs)...")
    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        optimizer.zero_grad()
        
        pbar = tqdm(enumerate(train_loader), total=len(train_loader), desc=f"Epoch {epoch}/{epochs}")
        for step, batch in pbar:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            act_labels = batch["activity_labels"].to(device)
            evt_labels = batch["event_labels"].to(device)
            
            act_logits, evt_logits, _ = model(input_ids, attention_mask)
            
            loss_act = act_criterion(act_logits, act_labels)
            loss_evt = evt_criterion(evt_logits, evt_labels)
            
            loss = 0.0
            if not torch.isnan(loss_act) and (act_labels != -100).any():
                loss += loss_act
            if not torch.isnan(loss_evt) and (evt_labels != -100).any():
                loss += loss_evt
                
            loss = loss / gradient_accumulation_steps
            loss.backward()
            
            train_loss += loss.item() * gradient_accumulation_steps
            
            if (step + 1) % gradient_accumulation_steps == 0 or (step + 1) == len(train_loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()
                
            if step % 500 == 0:
                pbar.set_postfix({"loss": f"{loss.item() * gradient_accumulation_steps:.4f}"})
                
        avg_train_loss = train_loss / len(train_loader)
        
        # Validation Evaluation
        val_loss, act_val, evt_val, _, _ = evaluate_model(model, val_loader, device, activity_classes, event_classes)
        
        val_score = (act_val["weighted_f1"] + evt_val["weighted_f1"]) / 2.0
        print(f"\n--- Epoch {epoch} Results ---")
        print(f"  Train Loss: {avg_train_loss:.4f} | Val Loss: {val_loss:.4f}")
        print(f"  Task A (Activity) Val Acc: {act_val['accuracy']:.4f} | Macro F1: {act_val['macro_f1']:.4f} | Weighted F1: {act_val['weighted_f1']:.4f}")
        print(f"  Task B (Event) Val Acc: {evt_val['accuracy']:.4f} | Macro F1: {evt_val['macro_f1']:.4f} | Weighted F1: {evt_val['weighted_f1']:.4f}")
        print(f"  Combined Val Score: {val_score:.4f}")
        
        hist_entry = {
            "epoch": epoch,
            "train_loss": avg_train_loss,
            "val_loss": val_loss,
            "task_a_val": act_val,
            "task_b_val": evt_val,
            "combined_val_score": val_score
        }
        training_history.append(hist_entry)
        
        # Save best model checkpoint
        if val_score > best_val_score:
            best_val_score = val_score
            ckpt_path = os.path.join(OUTPUT_MODEL_DIR, "best_multi_task_model.pt")
            torch.save(model.state_dict(), ckpt_path)
            print(f"  --> Saved new best checkpoint to {ckpt_path}")
            
    print("\n[5/5] Final Untouched Test Evaluation...")
    best_ckpt = os.path.join(OUTPUT_MODEL_DIR, "best_multi_task_model.pt")
    model.load_state_dict(torch.load(best_ckpt, map_location=device))
    
    test_loss, act_test, evt_test, (act_trues, act_preds), (evt_trues, evt_preds) = evaluate_model(model, test_loader, device, activity_classes, event_classes)
    
    print("\n==========================================")
    print("  FINAL UNTOUCHED TEST RESULTS")
    print("==========================================")
    print(f"Task A (Activity Classification - DWData):")
    print(f"  Accuracy:          {act_test['accuracy']:.4f}")
    print(f"  Macro Precision:   {act_test['macro_precision']:.4f}")
    print(f"  Macro Recall:      {act_test['macro_recall']:.4f}")
    print(f"  Macro F1:          {act_test['macro_f1']:.4f}")
    print(f"  Weighted Precision:{act_test['weighted_precision']:.4f}")
    print(f"  Weighted Recall:   {act_test['weighted_recall']:.4f}")
    print(f"  Weighted F1:       {act_test['weighted_f1']:.4f}")
    print("------------------------------------------")
    print(f"Task B (Event Classification - CySecED Dark):")
    print(f"  Accuracy:          {evt_test['accuracy']:.4f}")
    print(f"  Macro Precision:   {evt_test['macro_precision']:.4f}")
    print(f"  Macro Recall:      {evt_test['macro_recall']:.4f}")
    print(f"  Macro F1:          {evt_test['macro_f1']:.4f}")
    print(f"  Weighted Precision:{evt_test['weighted_precision']:.4f}")
    print(f"  Weighted Recall:   {evt_test['weighted_recall']:.4f}")
    print(f"  Weighted F1:       {evt_test['weighted_f1']:.4f}")
    print("==========================================")
    
    summary_results = {
        "model_name": "darkwatch_text_transformer_multitask",
        "base_model": "distilbert-base-uncased",
        "training_history": training_history,
        "test_results": {
            "task_a_dwdata_activity": act_test,
            "task_b_cyseced_event": evt_test
        }
    }
    
    summary_path = os.path.join(RESULTS_DIR, "transformer_multitask_results.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_results, f, indent=2)
        
    print(f"Multi-Task Transformer training complete! Summary saved to {summary_path}")

if __name__ == "__main__":
    main()
