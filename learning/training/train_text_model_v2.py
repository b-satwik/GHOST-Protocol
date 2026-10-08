"""
DarkWatch XAI — Full DistilBERT Text Model Training V2 Script.
Implements:
1. Chronological Train/Val/Test Split Preservation
2. Handling of Severe Class Imbalance via:
   - Strategy A: Class-Weighted Cross Entropy Loss
   - Strategy B: Controlled Minority Oversampling
3. Comprehensive evaluation (Macro P/R/F1, Weighted F1, Per-Class F1, Confusion Matrix)
4. Model, Tokenizer, Config, and Metrics Artifact Saving
"""

import os
import sys
import json
import argparse
import numpy as np
import pandas as pd
from typing import Dict, Any

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    AdamW,
    get_linear_schedule_with_warmup
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight

# Set PyTorch seed for reproducibility
torch.manual_seed(42)
np.random.seed(42)

class TextDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = int(self.labels[idx])
        
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt"
        )
        
        item = {key: val.squeeze(0) for key, val in encoding.items()}
        item["labels"] = torch.tensor(label, dtype=torch.long)
        return item

def evaluate_model(model, dataloader, device, num_classes):
    model.eval()
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            preds = torch.argmax(logits, dim=-1)
            
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            
    acc = accuracy_score(all_labels, all_preds)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(all_labels, all_preds, average="macro", zero_division=0)
    w_p, w_r, w_f1, _ = precision_recall_fscore_support(all_labels, all_preds, average="weighted", zero_division=0)
    
    per_class_p, per_class_r, per_class_f1, _ = precision_recall_fscore_support(
        all_labels, all_preds, average=None, labels=list(range(num_classes)), zero_division=0
    )
    
    cm = confusion_matrix(all_labels, all_preds, labels=list(range(num_classes)))
    
    return {
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
        "confusion_matrix": cm.tolist()
    }

def train_model(
    strategy: str = "weighted_loss",
    epochs: int = 3,
    batch_size: int = 32,
    lr: float = 2e-5,
    max_length: int = 128,
    output_dir: str = None
):
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    data_dir = os.path.join(base_dir, "data", "processed", "training")
    
    if output_dir is None:
        output_dir = os.path.join(base_dir, "models", f"dwdata_text_model_{strategy}")
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n==========================================")
    print(f"TRAINING DISTILBERT TEXT MODEL (Strategy: {strategy})")
    print(f"==========================================")

    # 1. Load Data
    train_df = pd.read_csv(os.path.join(data_dir, "text_train.csv"))
    val_df = pd.read_csv(os.path.join(data_dir, "text_validation.csv"))
    test_df = pd.read_csv(os.path.join(data_dir, "text_test.csv"))
    
    text_col = [c for c in ["text", "listing_text", "listing_name"] if c in train_df.columns][0]
    label_col = [c for c in ["label", "category", "class", "semantic_class"] if c in train_df.columns][0]
    
    # Label Mapping
    unique_labels = sorted(train_df[label_col].unique())
    label2id = {l: i for i, l in enumerate(unique_labels)}
    id2label = {i: l for i, l in enumerate(unique_labels)}
    num_classes = len(unique_labels)
    
    train_df["mapped_label"] = train_df[label_col].map(label2id)
    val_df["mapped_label"] = val_df[label_col].map(label2id)
    test_df["mapped_label"] = test_df[label_col].map(label2id)

    # Apply Strategy B (Controlled Oversampling) if specified
    if strategy == "controlled_oversampling":
        print("Applying controlled oversampling for minority classes (< 500 samples)...")
        dfs = [train_df]
        for l_idx in range(num_classes):
            sub = train_df[train_df["mapped_label"] == l_idx]
            if len(sub) > 0 and len(sub) < 500:
                mult = min(5, int(500 / len(sub)))
                dfs.append(sub.sample(n=len(sub)*(mult-1), replace=True, random_state=42))
        train_df = pd.concat(dfs, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
        print(f"Oversampled train dataset size: {len(train_df):,}")

    # 2. Tokenizer & Dataloaders
    pretrained_model_name = "distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(pretrained_model_name)
    
    train_dataset = TextDataset(train_df[text_col].values, train_df["mapped_label"].values, tokenizer, max_length)
    val_dataset = TextDataset(val_df[text_col].values, val_df["mapped_label"].values, tokenizer, max_length)
    test_dataset = TextDataset(test_df[text_col].values, test_df["mapped_label"].values, tokenizer, max_length)
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    # 3. Model & Loss Setup
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training device: {device}")
    
    model = AutoModelForSequenceClassification.from_pretrained(
        pretrained_model_name,
        num_labels=num_classes,
        id2label={str(k): v for k, v in id2label.items()},
        label2id={k: int(v) for k, v in label2id.items()}
    )
    model.to(device)

    # Loss function for Strategy A (Weighted Cross Entropy)
    if strategy == "weighted_loss":
        class_weights = compute_class_weight("balanced", classes=np.unique(train_df["mapped_label"]), y=train_df["mapped_label"].values)
        weights_tensor = torch.tensor(class_weights, dtype=torch.float).to(device)
        loss_fn = nn.CrossEntropyLoss(weight=weights_tensor)
        print("Using Class-Weighted Cross Entropy Loss.")
    else:
        loss_fn = nn.CrossEntropyLoss()

    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    total_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=int(total_steps*0.1), num_training_steps=total_steps)

    # 4. Training Loop
    best_val_f1 = 0.0
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        for step, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            
            optimizer.zero_grad()
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = loss_fn(outputs.logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            
            total_loss += loss.item()
            
        avg_loss = total_loss / len(train_loader)
        val_metrics = evaluate_model(model, val_loader, device, num_classes)
        print(f"Epoch {epoch+1}/{epochs} - Train Loss: {avg_loss:.4f} | Val Acc: {val_metrics['accuracy']:.4f} | Val Macro F1: {val_metrics['macro_f1']:.4f}")
        
        if val_metrics["macro_f1"] > best_val_f1:
            best_val_f1 = val_metrics["macro_f1"]
            model.save_pretrained(output_dir)
            tokenizer.save_pretrained(output_dir)

    # 5. Final Test Evaluation
    best_model = AutoModelForSequenceClassification.from_pretrained(output_dir).to(device)
    test_metrics = evaluate_model(best_model, test_loader, device, num_classes)
    
    print("\n--- FINAL TEST SET METRICS ---")
    print(f"Test Accuracy        : {test_metrics['accuracy']:.4f}")
    print(f"Test Macro Precision : {test_metrics['macro_precision']:.4f}")
    print(f"Test Macro Recall    : {test_metrics['macro_recall']:.4f}")
    print(f"Test Macro F1        : {test_metrics['macro_f1']:.4f}")
    print(f"Test Weighted F1     : {test_metrics['weighted_f1']:.4f}")

    # Save Config and Metrics
    metrics_path = os.path.join(output_dir, "test_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(test_metrics, f, indent=2)

    return test_metrics

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--strategy", type=str, default="weighted_loss", choices=["weighted_loss", "controlled_oversampling"])
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch_size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=2e-5)
    args = parser.parse_args()
    
    train_model(strategy=args.strategy, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr)
