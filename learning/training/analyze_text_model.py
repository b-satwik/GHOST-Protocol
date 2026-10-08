import os
import json
import numpy as np
import pandas as pd
import torch

from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

# ============================================================
# PATHS
# ============================================================

BASE_DIR = r"C:\Users\buyya\Desktop\darkwatch"

TRAIN_FILE = os.path.join(
    BASE_DIR, "data", "processed", "training", "text_train.csv"
)

TEST_FILE = os.path.join(
    BASE_DIR, "data", "processed", "training", "text_test.csv"
)

LABEL_FILE = os.path.join(
    BASE_DIR, "data", "processed", "training", "text_label_map.json"
)

MODEL_DIR = os.path.join(
    BASE_DIR, "models", "dwdata_text_model"
)

REPORT_DIR = os.path.join(
    BASE_DIR, "reports", "training"
)

os.makedirs(REPORT_DIR, exist_ok=True)

# ============================================================
# SETTINGS
# ============================================================

TRAIN_SAMPLES = 5000
TEST_SAMPLES = 1000
BATCH_SIZE = 8
MAX_LENGTH = 96

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

# ============================================================
# START
# ============================================================

print("=" * 60)
print("DARKWATCH-XAI TEXT MODEL ANALYSIS")
print("=" * 60)

print(f"Device : {DEVICE}")

# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading datasets...")

train_df = pd.read_csv(TRAIN_FILE).head(TRAIN_SAMPLES).copy()
test_df = pd.read_csv(TEST_FILE).head(TEST_SAMPLES).copy()

print(f"Training samples : {len(train_df):,}")
print(f"Test samples     : {len(test_df):,}")

print("\nColumns:")
print(list(test_df.columns))

TEXT_COL = "text"
LABEL_COL = "label_id"

if TEXT_COL not in test_df.columns:
    raise ValueError("Column 'text' not found.")

if LABEL_COL not in test_df.columns:
    raise ValueError("Column 'label_id' not found.")

print(f"\nText column  : {TEXT_COL}")
print(f"Label column : {LABEL_COL}")

# ============================================================
# LOAD LABEL MAP
# ============================================================

print("\nLoading label map...")

with open(LABEL_FILE, "r", encoding="utf-8") as f:
    label_map = json.load(f)

print("Label map loaded.")

# The JSON contains nested metadata.
# We only need the mapping between IDs and class names.

id_to_label = {}

def extract_mapping(obj):

    if isinstance(obj, dict):

        # Case: {"0": "fraud"}
        for key, value in obj.items():

            if isinstance(value, str):
                try:
                    idx = int(key)
                    id_to_label[idx] = value
                except:
                    pass

        # Recursively search nested dictionaries
        for value in obj.values():
            extract_mapping(value)

    elif isinstance(obj, list):

        for item in obj:
            extract_mapping(item)


extract_mapping(label_map)

# If JSON mapping wasn't directly recoverable,
# use semantic_target/category information from CSV.

if len(id_to_label) == 0:

    print(
        "Could not directly extract label names from JSON."
    )

    temp = (
        train_df[["label_id", "semantic_target"]]
        .drop_duplicates()
    )

    for _, row in temp.iterrows():
        try:
            idx = int(row["label_id"])
            id_to_label[idx] = str(row["semantic_target"])
        except:
            pass

print(f"Classes discovered : {len(id_to_label)}")

# ============================================================
# CLASS DISTRIBUTION
# ============================================================

print("\n" + "=" * 60)
print("TEST CLASS DISTRIBUTION")
print("=" * 60)

test_distribution = (
    test_df["label_id"]
    .value_counts()
    .sort_values(ascending=False)
)

for label_id, count in test_distribution.items():

    percentage = count / len(test_df) * 100

    name = id_to_label.get(
        int(label_id),
        str(label_id)
    )

    print(
        f"{int(label_id):3} | "
        f"{name:35} | "
        f"{count:5} ({percentage:6.2f}%)"
    )

test_distribution.to_csv(
    os.path.join(
        REPORT_DIR,
        "text_test_class_distribution.csv"
    )
)

# ============================================================
# TRAIN DISTRIBUTION
# ============================================================

print("\n" + "=" * 60)
print("TRAIN CLASS DISTRIBUTION")
print("=" * 60)

train_distribution = (
    train_df["label_id"]
    .value_counts()
    .sort_values(ascending=False)
)

for label_id, count in train_distribution.items():

    percentage = count / len(train_df) * 100

    name = id_to_label.get(
        int(label_id),
        str(label_id)
    )

    print(
        f"{int(label_id):3} | "
        f"{name:35} | "
        f"{count:5} ({percentage:6.2f}%)"
    )

train_distribution.to_csv(
    os.path.join(
        REPORT_DIR,
        "text_train_class_distribution.csv"
    )
)

# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading trained model...")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_DIR
)

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_DIR
)

model.to(DEVICE)
model.eval()

print("Model loaded successfully.")

# ============================================================
# PREPARE TEST DATA
# ============================================================

texts = (
    test_df[TEXT_COL]
    .fillna("")
    .astype(str)
    .tolist()
)

true_labels = (
    test_df[LABEL_COL]
    .astype(int)
    .tolist()
)

# ============================================================
# PREDICTION
# ============================================================

print("\nGenerating predictions...")

predictions = []

for start in range(
    0,
    len(texts),
    BATCH_SIZE
):

    batch_texts = texts[
        start:start + BATCH_SIZE
    ]

    encoded = tokenizer(
        batch_texts,
        padding=True,
        truncation=True,
        max_length=MAX_LENGTH,
        return_tensors="pt"
    )

    encoded = {
        key: value.to(DEVICE)
        for key, value in encoded.items()
    }

    with torch.no_grad():

        outputs = model(**encoded)

        preds = torch.argmax(
            outputs.logits,
            dim=1
        )

    predictions.extend(
        preds.cpu().numpy().tolist()
    )

    processed = min(
        start + BATCH_SIZE,
        len(texts)
    )

    if processed % 200 < BATCH_SIZE:
        print(
            f"Processed {processed}/{len(texts)}"
        )

# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    true_labels,
    predictions
)

precision, recall, f1, _ = (
    precision_recall_fscore_support(
        true_labels,
        predictions,
        average="weighted",
        zero_division=0
    )
)

print("\n" + "=" * 60)
print("RECALCULATED TEST METRICS")
print("=" * 60)

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1        : {f1:.4f}")

# ============================================================
# PER CLASS
# ============================================================

print("\n" + "=" * 60)
print("PER-CLASS PERFORMANCE")
print("=" * 60)

class_ids = sorted(
    set(true_labels) | set(predictions)
)

target_names = [
    id_to_label.get(
        int(i),
        str(i)
    )
    for i in class_ids
]

report = classification_report(
    true_labels,
    predictions,
    labels=class_ids,
    target_names=target_names,
    output_dict=True,
    zero_division=0
)

report_df = pd.DataFrame(report).transpose()

print(
    report_df[
        [
            "precision",
            "recall",
            "f1-score",
            "support"
        ]
    ].round(4)
)

report_df.to_csv(
    os.path.join(
        REPORT_DIR,
        "text_per_class_metrics.csv"
    )
)

# ============================================================
# CONFUSION MATRIX
# ============================================================

print("\nGenerating confusion matrix...")

cm = confusion_matrix(
    true_labels,
    predictions,
    labels=class_ids
)

cm_df = pd.DataFrame(
    cm,
    index=target_names,
    columns=target_names
)

cm_df.to_csv(
    os.path.join(
        REPORT_DIR,
        "text_confusion_matrix.csv"
    )
)

# ============================================================
# MOST CONFUSED PAIRS
# ============================================================

print("\n" + "=" * 60)
print("MOST CONFUSED CLASS PAIRS")
print("=" * 60)

confusions = []

for i in range(len(class_ids)):

    for j in range(len(class_ids)):

        if i == j:
            continue

        count = cm[i, j]

        if count > 0:

            confusions.append({
                "actual": id_to_label.get(
                    int(class_ids[i]),
                    str(class_ids[i])
                ),
                "predicted": id_to_label.get(
                    int(class_ids[j]),
                    str(class_ids[j])
                ),
                "count": int(count)
            })

confusions_df = pd.DataFrame(
    confusions
)

if len(confusions_df) > 0:

    confusions_df = confusions_df.sort_values(
        "count",
        ascending=False
    )

    print(
        confusions_df.head(20).to_string(
            index=False
        )
    )

confusions_df.to_csv(
    os.path.join(
        REPORT_DIR,
        "text_most_confused_pairs.csv"
    ),
    index=False
)

# ============================================================
# WRONG PREDICTIONS
# ============================================================

wrong_rows = []

for i in range(len(test_df)):

    if true_labels[i] != predictions[i]:

        wrong_rows.append({
            "text": texts[i],
            "actual": id_to_label.get(
                int(true_labels[i]),
                str(true_labels[i])
            ),
            "predicted": id_to_label.get(
                int(predictions[i]),
                str(predictions[i])
            )
        })

wrong_df = pd.DataFrame(
    wrong_rows
)

wrong_df.to_csv(
    os.path.join(
        REPORT_DIR,
        "text_wrong_predictions.csv"
    ),
    index=False
)

# ============================================================
# SUMMARY
# ============================================================

summary = {
    "device": str(DEVICE),
    "train_samples": len(train_df),
    "test_samples": len(test_df),
    "classes": len(id_to_label),
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1": float(f1),
    "wrong_predictions": int(len(wrong_df))
}

with open(
    os.path.join(
        REPORT_DIR,
        "text_model_analysis_summary.json"
    ),
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        summary,
        f,
        indent=4
    )

# ============================================================
# COMPLETE
# ============================================================

print("\n" + "=" * 60)
print("ANALYSIS COMPLETE")
print("=" * 60)

print("\nReports created in:")
print(REPORT_DIR)