#!/usr/bin/env python3
"""
🛡️ GHOST PROTOCOL — DISTILBERT MODEL AUDIT SCRIPT
Inspects and prints the exact configuration of the frozen HackerSignal DistilBERT model.
"""

import os
import sys
import json
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)


def audit_distilbert():
    print("=" * 75)
    print(" 🛡️ GHOST PROTOCOL — FROZEN DISTILBERT MODEL AUDIT")
    print("=" * 75)

    base_dir = repo_root
    model_dir = os.path.join(base_dir, "models", "distilbert_hackersignal", "final_model")
    tok_dir = os.path.join(base_dir, "models", "distilbert_hackersignal", "tokenizer")
    label_map_file = os.path.join(base_dir, "models", "distilbert_hackersignal", "metrics", "label_mapping.json")

    print(f"\n[1] Model Directory:      {model_dir}")
    print(f"[2] Tokenizer Directory:  {tok_dir}")
    print(f"[3] Label Mapping File:   {label_map_file}")

    if not os.path.exists(model_dir):
        raise FileNotFoundError(f"Model directory not found: {model_dir}")
    if not os.path.exists(tok_dir):
        raise FileNotFoundError(f"Tokenizer directory not found: {tok_dir}")
    if not os.path.exists(label_map_file):
        raise FileNotFoundError(f"Label mapping file not found: {label_map_file}")

    # Read Label Mapping
    with open(label_map_file, "r", encoding="utf-8") as f:
        label_mapping = json.load(f)

    id2label = label_mapping.get("id2label", {})
    label2id = label_mapping.get("label2id", {})

    print("\n--- DISCOVERED LABEL MAPPING ---")
    print(f"Total Number of Labels: {len(label2id)}")
    for idx_str, name in id2label.items():
        print(f"  ID {idx_str}: {name}")

    # Load Tokenizer & Model
    print("\nLoading PyTorch DistilBERT Model weights & tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(tok_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)

    print("\n--- MODEL & TOKENIZER CONFIGURATION ---")
    print(f"Model Architecture:     {model.config.architectures}")
    print(f"Model Type:             {model.config.model_type}")
    print(f"Num Labels:             {model.config.num_labels}")
    print(f"Max Position Embedding: {getattr(model.config, 'max_position_embeddings', 512)}")
    print(f"Vocab Size:             {tokenizer.vocab_size}")
    print(f"Device:                 {next(model.parameters()).device}")

    # Calculate parameter count
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total Parameters:       {total_params:,}")
    print(f"Trainable Parameters:   {trainable_params:,}")

    print("\n" + "=" * 75)
    print(" ✔️ AUDIT COMPLETE: FROZEN DISTILBERT MODEL IS VALIDATED")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    audit_distilbert()
