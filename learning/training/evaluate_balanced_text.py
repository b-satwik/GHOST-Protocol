# learning/training/evaluate_balanced_text.py

import os
import json
import torch
import pandas as pd
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)

# ============================================================
# PATHS
# ============================================================

PROJECT_DIR = r"C:\Users\buyya\Desktop\darkwatch"

MODEL_DIR = os.path.join(
    PROJECT_DIR,
    "models",
    "dwdata_text_model"
)

TEST_FILE = os.path.join(
    PROJECT_DIR,
    "data",
    "processed",
    "training",
    "text_test_balanced.csv"
)

LABEL_MAP_FILE = os.path.join(
    PROJECT_DIR,
    "data",
    "processed",
    "training",
    "text_label_map.json"
)

REPORT_DIR = os.path.join(
    PROJECT_DIR,
    "reports",
    "training"
)

os.makedirs(REPORT_DIR, exist_ok=True)

# ============================================================
# SETTINGS
# ============================================================

MAX_LENGTH = 96
BATCH_SIZE = 8

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print("=" * 60)
print("DARKWATCH-XAI")
print("BALANCED TEXT MODEL EVALUATION")
print("=" * 60)

print(f"Device : {DEVICE}")
print(f"Model  : {MODEL_DIR}")
print(f"Test   : {TEST_FILE}")

# ============================================================
# LOAD DATA
# ============================================================

if not os.path.exists(TEST_FILE):
    raise FileNotFoundError(
        f"\nBalanced test file not found:\n{TEST_FILE}\n"
    )

df = pd.read_csv(TEST_FILE)

required_columns = ["text", "label_id"]

for col in required_columns:
    if col not in df.columns:
        raise ValueError(
            f"Required column '{col}' not found.\n"
            f"Available columns: {list(df.columns)}"
        )

df["text"] = df["text"].fillna("").astype(str)
df["label_id"] = df["label_id"].astype(int)

print("\nDataset:")
print(f"Records : {len(df)}")
print(f"Classes : {df['label_id'].nunique()}")

print("\nClass distribution:")
print(df["label_id"].value_counts().sort_index())

# ============================================================
# LOAD LABEL MAP
# ============================================================

label_names = {}

if os.path.exists(LABEL_MAP_FILE):

    with open(LABEL_MAP_FILE, "r", encoding="utf-8") as f:
        raw_map = json.load(f)

    # Handle either:
    # {"0": "OTHER_SEMANTIC"}
    # or
    # {"label_to_id": {...}, "id_to_label": {...}}

    if "id_to_label" in raw_map:
        raw_map = raw_map["id_to_label"]

    for key, value in raw_map.items():
        try:
            label_names[int(key)] = str(value)
        except:
            pass

# Fallback to semantic_target column
if not label_names and "semantic_target" in df.columns:
    temp = df[["label_id", "semantic_target"]].drop_duplicates()

    for _, row in temp.iterrows():
        label_names[int(row["label_id"])] = str(row["semantic_target"])

print("\nLabels:")
for label_id in sorted(df["label_id"].unique()):
    print(
        f"{label_id:>3} : "
        f"{label_names.get(label_id, 'UNKNOWN')}"
    )

# ============================================================
# DATASET
# ============================================================

class TextDataset(Dataset):

    def __init__(self, texts, labels, tokenizer):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):

        encoding = self.tokenizer(
            self.texts[idx],
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
            return_tensors="pt"
        )

        item = {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(
                self.labels[idx],
                dtype=torch.long
            )
        }

        return item

# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_DIR
)

print("Loading trained model...")

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_DIR
)

model.to(DEVICE)
model.eval()

# ============================================================
# DATA LOADER
# ============================================================

dataset = TextDataset(
    df["text"].tolist(),
    df["label_id"].tolist(),
    tokenizer
)

loader = DataLoader(
    dataset,
    batch_size=BATCH_SIZE,
    shuffle=False
)

# ============================================================
# INFERENCE
# ============================================================

print("\nRunning inference...")

all_predictions = []
all_labels = []

with torch.no_grad():

    for batch in loader:

        input_ids = batch["input_ids"].to(DEVICE)
        attention_mask = batch["attention_mask"].to(DEVICE)
        labels = batch["labels"].to(DEVICE)

        outputs = model(
            input_ids=input_ids,
            attention_mask=attention_mask
        )

        predictions = torch.argmax(
            outputs.logits,
            dim=1
        )

        all_predictions.extend(
            predictions.cpu().numpy()
        )

        all_labels.extend(
            labels.cpu().numpy()
        )

# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    all_labels,
    all_predictions
)

precision, recall, f1, _ = precision_recall_fscore_support(
    all_labels,
    all_predictions,
    average="macro",
    zero_division=0
)

weighted_precision, weighted_recall, weighted_f1, _ = (
    precision_recall_fscore_support(
        all_labels,
        all_predictions,
        average="weighted",
        zero_division=0
    )
)

print("\n" + "=" * 60)
print("FINAL BALANCED TEST RESULTS")
print("=" * 60)

print(f"Accuracy          : {accuracy:.4f}")
print(f"Macro Precision   : {precision:.4f}")
print(f"Macro Recall      : {recall:.4f}")
print(f"Macro F1          : {f1:.4f}")
print(f"Weighted Precision: {weighted_precision:.4f}")
print(f"Weighted Recall   : {weighted_recall:.4f}")
print(f"Weighted F1       : {weighted_f1:.4f}")

# ============================================================
# CLASSIFICATION REPORT
# ============================================================

unique_labels = sorted(
    set(all_labels) | set(all_predictions)
)

target_names = [
    label_names.get(label, f"CLASS_{label}")
    for label in unique_labels
]

print("\nCLASSIFICATION REPORT")
print("=" * 60)

report_text = classification_report(
    all_labels,
    all_predictions,
    labels=unique_labels,
    target_names=target_names,
    zero_division=0
)

print(report_text)

# ============================================================
# CONFUSION MATRIX
# ============================================================

cm = confusion_matrix(
    all_labels,
    all_predictions,
    labels=unique_labels
)

cm_df = pd.DataFrame(
    cm,
    index=target_names,
    columns=target_names
)

cm_path = os.path.join(
    REPORT_DIR,
    "balanced_text_confusion_matrix.csv"
)

cm_df.to_csv(cm_path)

# ============================================================
# SAVE PREDICTIONS
# ============================================================

results = df.copy()

results["predicted_label_id"] = all_predictions

results["predicted_semantic_target"] = [
    label_names.get(
        pred,
        f"CLASS_{pred}"
    )
    for pred in all_predictions
]

results["correct"] = (
    results["label_id"]
    == results["predicted_label_id"]
)

prediction_path = os.path.join(
    REPORT_DIR,
    "balanced_text_predictions.csv"
)

results.to_csv(
    prediction_path,
    index=False
)

# ============================================================
# SAVE METRICS
# ============================================================

metrics = {
    "test_records": len(df),
    "classes": int(df["label_id"].nunique()),
    "accuracy": float(accuracy),
    "macro_precision": float(precision),
    "macro_recall": float(recall),
    "macro_f1": float(f1),
    "weighted_precision": float(weighted_precision),
    "weighted_recall": float(weighted_recall),
    "weighted_f1": float(weighted_f1),
    "device": str(DEVICE)
}

metrics_path = os.path.join(
    REPORT_DIR,
    "balanced_text_metrics.json"
)

with open(
    metrics_path,
    "w",
    encoding="utf-8"
) as f:
    json.dump(
        metrics,
        f,
        indent=4
    )

print("=" * 60)
print("EVALUATION COMPLETE")
print("=" * 60)

print(f"\nMetrics : {metrics_path}")
print(f"Predictions : {prediction_path}")
print(f"Confusion matrix : {cm_path}")