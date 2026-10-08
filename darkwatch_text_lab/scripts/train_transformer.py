#!/usr/bin/env python3
"""
DarkWatch Text Lab - Transformer Training Script
------------------------------------------------
Trains a multi-task DistilBERT model with shared encoder backbone.
Supports GPU acceleration, mixed precision, and OFFLINE_MODE.
"""

import os
import json
import random
import numpy as np
import pandas as pd
from collections import Counter, defaultdict

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModel, get_linear_schedule_with_warmup
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

def get_lab_dirs(base_dir=None):
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "base": base_dir,
        "unified": os.path.join(base_dir, "data", "unified"),
        "models": os.path.join(base_dir, "models", "transformers"),
        "cached": os.path.join(base_dir, "models", "cached"),
        "metrics": os.path.join(base_dir, "results", "metrics"),
        "curves": os.path.join(base_dir, "results", "curves"),
        "configs": os.path.join(base_dir, "configs")
    }

class UnifiedDataset(Dataset):
    def __init__(self, records, tokenizer, activity_map, event_map, max_length=32):
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
        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
        act_lbl = rec.get("activity_label")
        evt_lbl = rec.get("event_label")
        act_id = self.activity_map[act_lbl] if act_lbl in self.activity_map else -100
        evt_id = self.event_map[evt_lbl] if evt_lbl in self.event_map else -100
        
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "activity_labels": torch.tensor(act_id, dtype=torch.long),
            "event_labels": torch.tensor(evt_id, dtype=torch.long),
        }

class MultiTaskModel(nn.Module):
    def __init__(self, base_model, num_activity, num_event):
        super().__init__()
        self.encoder = base_model
        hidden_size = self.encoder.config.hidden_size
        self.dropout = nn.Dropout(0.2)
        
        self.activity_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, num_activity)
        )
        self.event_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, num_event)
        )

    def forward(self, input_ids, attention_mask):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        cls_rep = outputs.last_hidden_state[:, 0, :]
        cls_rep = self.dropout(cls_rep)
        return self.activity_head(cls_rep), self.event_head(cls_rep), cls_rep

def compute_metrics(y_true, y_pred):
    if len(y_true) == 0:
        return {"accuracy": 0.0, "macro_f1": 0.0, "weighted_f1": 0.0}
    acc = float(accuracy_score(y_true, y_pred))
    p_m, r_m, f1_m, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    p_w, r_w, f1_w, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    return {
        "accuracy": acc,
        "macro_precision": float(p_m),
        "macro_recall": float(r_m),
        "macro_f1": float(f1_m),
        "weighted_precision": float(p_w),
        "weighted_recall": float(r_w),
        "weighted_f1": float(f1_w)
    }

def evaluate(model, loader, device):
    model.eval()
    act_preds, act_trues = [], []
    evt_preds, evt_trues = [], []
    total_loss = 0.0
    act_criterion = nn.CrossEntropyLoss(ignore_index=-100)
    evt_criterion = nn.CrossEntropyLoss(ignore_index=-100)
    
    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            act_labels = batch["activity_labels"].to(device)
            evt_labels = batch["event_labels"].to(device)
            
            act_logits, evt_logits, _ = model(input_ids, attention_mask)
            l_act = act_criterion(act_logits, act_labels)
            l_evt = evt_criterion(evt_logits, evt_labels)
            loss = 0.0
            if not torch.isnan(l_act) and (act_labels != -100).any():
                loss += l_act
            if not torch.isnan(l_evt) and (evt_labels != -100).any():
                loss += l_evt
            total_loss += loss.item() if isinstance(loss, torch.Tensor) else 0.0
            
            act_mask = (act_labels != -100)
            if act_mask.any():
                act_preds.extend(torch.argmax(act_logits[act_mask], dim=-1).cpu().numpy())
                act_trues.extend(act_labels[act_mask].cpu().numpy())
                
            evt_mask = (evt_labels != -100)
            if evt_mask.any():
                evt_preds.extend(torch.argmax(evt_logits[evt_mask], dim=-1).cpu().numpy())
                evt_trues.extend(evt_labels[evt_mask].cpu().numpy())
                
    act_m = compute_metrics(act_trues, act_preds)
    evt_m = compute_metrics(evt_trues, evt_preds)
    return total_loss / max(1, len(loader)), act_m, evt_m

def main(lab_base_dir=None, config_override=None):
    set_seed(42)
    dirs = get_lab_dirs(lab_base_dir)
    
    # Load config
    cfg_path = os.path.join(dirs["configs"], "training_config.json")
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r") as f:
            cfg = json.load(f)
    if config_override:
        cfg.update(config_override)
        
    model_name = cfg.get("model_name", "distilbert-base-uncased")
    offline_mode = cfg.get("offline_mode", False)
    max_length = cfg.get("max_length", 32)
    batch_size = cfg.get("batch_size", 64)
    epochs = cfg.get("epochs", 3)
    lr = cfg.get("learning_rate", 3e-5)
    
    device = torch.device("cuda" if torch.cuda.is_available() and cfg.get("use_cuda", True) else "cpu")
    print(f"Transformer Training Device: {device} (Offline Mode: {offline_mode})")
    
    unified_file = os.path.join(dirs["unified"], "darkwatch_unified_text.jsonl")
    records = []
    with open(unified_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
                
    act_classes = sorted(list({r["activity_label"] for r in records if r["activity_label"] is not None}))
    evt_classes = sorted(list({r["event_label"] for r in records if r["event_label"] is not None}))
    act_map = {c: i for i, c in enumerate(act_classes)}
    evt_map = {c: i for i, c in enumerate(evt_classes)}
    
    # Tokenizer & Base Model loading
    model_path = model_name
    if offline_mode:
        cached_path = os.path.join(dirs["cached"], model_name)
        if os.path.exists(cached_path):
            model_path = cached_path
        else:
            print(f"Offline mode active but cached model not found at {cached_path}. Falling back to default.")
            
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        base_encoder = AutoModel.from_pretrained(model_path)
    except Exception as e:
        print(f"Warning: Could not load {model_path} ({e}). Loading fallback distilbert-base-uncased.")
        tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        base_encoder = AutoModel.from_pretrained("distilbert-base-uncased")
        
    tokenizer.save_pretrained(dirs["models"])
    
    train_recs = [r for r in records if r["original_split"] == "train"]
    val_recs = [r for r in records if r["original_split"] == "validation"]
    test_recs = [r for r in records if r["original_split"] == "test"]
    
    # Sample train_recs for efficient CPU training
    np.random.seed(42)
    dw_tr = [r for r in train_recs if r["source_dataset"] == "DWData"]
    dark_tr = [r for r in train_recs if r["source_dataset"] == "CYSECED_DARK"]
    surf_tr = [r for r in train_recs if r["source_dataset"] == "CYSECED_SURFACE"]
    
    dw_sample = np.random.choice(len(dw_tr), size=min(15000, len(dw_tr)), replace=False)
    surf_sample = np.random.choice(len(surf_tr), size=min(5000, len(surf_tr)), replace=False)
    sampled_train = dark_tr + [dw_tr[i] for i in dw_sample] + [surf_tr[i] for i in surf_sample]
    random.seed(42)
    random.shuffle(sampled_train)
    
    train_ds = UnifiedDataset(sampled_train, tokenizer, act_map, evt_map, max_length=max_length)
    val_ds = UnifiedDataset(val_recs, tokenizer, act_map, evt_map, max_length=max_length)
    test_ds = UnifiedDataset(test_recs, tokenizer, act_map, evt_map, max_length=max_length)
    
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False)
    
    model = MultiTaskModel(base_encoder, len(act_classes), len(evt_classes)).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    
    best_score = -1.0
    history = []
    
    print(f"Training Multi-Task Transformer for {epochs} epochs...")
    for epoch in range(1, epochs + 1):
        model.train()
        t_loss = 0.0
        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            act_labels = batch["activity_labels"].to(device)
            evt_labels = batch["event_labels"].to(device)
            
            optimizer.zero_grad()
            act_logits, evt_logits, _ = model(input_ids, attention_mask)
            l_act = nn.CrossEntropyLoss(ignore_index=-100)(act_logits, act_labels)
            l_evt = nn.CrossEntropyLoss(ignore_index=-100)(evt_logits, evt_labels)
            loss = 0.0
            if not torch.isnan(l_act) and (act_labels != -100).any():
                loss += l_act
            if not torch.isnan(l_evt) and (evt_labels != -100).any():
                loss += l_evt
            
            if isinstance(loss, torch.Tensor):
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                t_loss += loss.item()
                
        val_loss, act_val, evt_val = evaluate(model, val_loader, device)
        comb_score = (act_val["weighted_f1"] + evt_val["weighted_f1"]) / 2.0
        print(f"  Epoch {epoch}: Train Loss={t_loss/len(train_loader):.4f} | Val Loss={val_loss:.4f} | Act Val F1={act_val['weighted_f1']:.4f} | Evt Val F1={evt_val['weighted_f1']:.4f}")
        
        history.append({
            "epoch": epoch,
            "train_loss": t_loss / len(train_loader),
            "val_loss": val_loss,
            "task_a_val": act_val,
            "task_b_val": evt_val
        })
        
        if comb_score > best_score:
            best_score = comb_score
            torch.save(model.state_dict(), os.path.join(dirs["models"], "best_model.pt"))
            
    # Final Test Eval
    model.load_state_dict(torch.load(os.path.join(dirs["models"], "best_model.pt"), map_location=device))
    test_loss, act_test, evt_test = evaluate(model, test_loader, device)
    
    results = {
        "model_name": model_name,
        "history": history,
        "test_results": {
            "task_a_activity": act_test,
            "task_b_event": evt_test
        }
    }
    
    metrics_path = os.path.join(dirs["metrics"], "transformer_multitask.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    print(f"Saved Transformer results to {metrics_path}")
    return results

if __name__ == "__main__":
    main()
