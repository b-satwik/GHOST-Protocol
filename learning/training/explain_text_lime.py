import os
import json
import numpy as np
import pandas as pd
import torch

from transformers import AutoTokenizer, AutoModelForSequenceClassification
from lime.lime_text import LimeTextExplainer


# ============================================================
# PATHS
# ============================================================

ROOT = r"C:\Users\buyya\Desktop\darkwatch"

TEXT_TEST = os.path.join(
    ROOT, "data", "processed", "training", "text_test.csv"
)

FUSION_FILE = os.path.join(
    ROOT, "reports", "training", "model_fusion_test.csv"
)

LABEL_MAP_FILE = os.path.join(
    ROOT, "data", "processed", "training", "text_label_map.json"
)

MODEL_DIR = os.path.join(
    ROOT, "models", "dwdata_text_model"
)

OUTPUT_DIR = os.path.join(
    ROOT, "reports", "xai"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# SETTINGS
# ============================================================

MAX_LENGTH = 96
NUM_CASES = 10
NUM_SAMPLES = 150
BATCH_SIZE = 16

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ============================================================
# CHECK FILES
# ============================================================

required_files = [
    TEXT_TEST,
    FUSION_FILE,
    LABEL_MAP_FILE,
    MODEL_DIR,
]

for path in required_files:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing required path: {path}")

print("=" * 60)
print("DARKWATCH-XAI TEXT EXPLANATION")
print("=" * 60)
print(f"Device: {DEVICE}")


# ============================================================
# LOAD LABEL MAP
# ============================================================

with open(LABEL_MAP_FILE, "r", encoding="utf-8") as f:
    label_data = json.load(f)

id_to_label = {
    int(k): v
    for k, v in label_data["id_to_label"].items()
}


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading DistilBERT model...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_DIR
)

model.to(DEVICE)
model.eval()

print("Model loaded.")


# ============================================================
# LOAD DATA
# ============================================================

text_df = pd.read_csv(TEXT_TEST)
fusion_df = pd.read_csv(FUSION_FILE)

if "text" not in text_df.columns:
    raise ValueError("text column not found in text_test.csv")

if "fusion_score" not in fusion_df.columns:
    raise ValueError("fusion_score column not found in model_fusion_test.csv")


print(f"Text records   : {len(text_df):,}")
print(f"Fusion records : {len(fusion_df):,}")


# ============================================================
# ALIGN RECORDS
# ============================================================

if "record_id" in text_df.columns and "record_id" in fusion_df.columns:

    merged = text_df.merge(
        fusion_df,
        on="record_id",
        how="inner",
        suffixes=("_text", "_fusion")
    )

else:

    min_len = min(len(text_df), len(fusion_df))

    merged = text_df.iloc[:min_len].copy()

    for column in fusion_df.columns:
        if column not in merged.columns:
            merged[column] = fusion_df.iloc[:min_len][column].values


print(f"Aligned records: {len(merged):,}")


# ============================================================
# SELECT IMPORTANT CASES
# ============================================================

merged = merged.sort_values(
    "fusion_score",
    ascending=False
).head(NUM_CASES).reset_index(drop=True)

print(f"Cases selected : {len(merged)}")


# ============================================================
# MODEL PREDICTION FUNCTION
# ============================================================

def predict_proba(texts):

    texts = [str(x) for x in texts]

    results = []

    for start in range(0, len(texts), BATCH_SIZE):

        batch = texts[start:start + BATCH_SIZE]

        encoded = tokenizer(
            batch,
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

            probabilities = torch.softmax(
                outputs.logits,
                dim=-1
            )

        results.append(
            probabilities.cpu().numpy()
        )

    return np.vstack(results)


# ============================================================
# LIME
# ============================================================

explainer = LimeTextExplainer(
    class_names=[
        id_to_label[i]
        for i in sorted(id_to_label.keys())
    ],
    random_state=42
)


case_rows = []
token_rows = []


print("\nGenerating LIME explanations...\n")


for case_index, row in merged.iterrows():

    text = str(row["text"])

    if not text.strip():
        continue

    probabilities = predict_proba([text])[0]

    predicted_id = int(
        np.argmax(probabilities)
    )

    predicted_label = id_to_label.get(
        predicted_id,
        str(predicted_id)
    )

    confidence = float(
        probabilities[predicted_id]
    )

    print(
        f"[{case_index + 1}/{len(merged)}] "
        f"{predicted_label} "
        f"(confidence={confidence:.4f})"
    )

    explanation = explainer.explain_instance(
        text,
        predict_proba,
        labels=[predicted_id],
        num_features=15,
        num_samples=NUM_SAMPLES
    )

    token_weights = explanation.as_list(
        label=predicted_id
    )

    record_id = row.get(
        "record_id",
        case_index
    )

    fusion_score = float(
        row.get("fusion_score", 0.0)
    )

    fusion_band = row.get(
        "fusion_band",
        ""
    )

    # --------------------------------------------------------
    # CASE SUMMARY
    # --------------------------------------------------------

    case_rows.append({
        "case_index": case_index,
        "record_id": record_id,
        "fusion_score": fusion_score,
        "fusion_band": fusion_band,
        "predicted_class": predicted_label,
        "prediction_confidence": confidence,
        "text": text,
        "num_explanation_tokens": len(token_weights)
    })

    # --------------------------------------------------------
    # TOKEN EXPLANATIONS
    # --------------------------------------------------------

    for rank, (token, weight) in enumerate(
        token_weights,
        start=1
    ):

        token_rows.append({
            "case_index": case_index,
            "record_id": record_id,
            "predicted_class": predicted_label,
            "prediction_confidence": confidence,
            "fusion_score": fusion_score,
            "token": token,
            "weight": float(weight),
            "absolute_weight": abs(float(weight)),
            "direction": (
                "positive"
                if weight > 0
                else "negative"
            ),
            "rank": rank
        })


# ============================================================
# SAVE OUTPUTS
# ============================================================

cases_df = pd.DataFrame(case_rows)

tokens_df = pd.DataFrame(token_rows)


cases_output = os.path.join(
    OUTPUT_DIR,
    "text_lime_cases.csv"
)

tokens_output = os.path.join(
    OUTPUT_DIR,
    "text_lime_tokens.csv"
)


cases_df.to_csv(
    cases_output,
    index=False
)

tokens_df.to_csv(
    tokens_output,
    index=False
)


# ============================================================
# GLOBAL TOKEN SUMMARY
# ============================================================

if not tokens_df.empty:

    global_summary = (
        tokens_df
        .groupby("token")
        .agg(
            mean_weight=("weight", "mean"),
            mean_absolute_weight=(
                "absolute_weight",
                "mean"
            ),
            occurrence_count=("token", "count")
        )
        .reset_index()
        .sort_values(
            "mean_absolute_weight",
            ascending=False
        )
    )

else:

    global_summary = pd.DataFrame(
        columns=[
            "token",
            "mean_weight",
            "mean_absolute_weight",
            "occurrence_count"
        ]
    )


summary_output = os.path.join(
    OUTPUT_DIR,
    "text_lime_summary.csv"
)

global_summary.to_csv(
    summary_output,
    index=False
)


# ============================================================
# FINISHED
# ============================================================

print("\n" + "=" * 60)
print("TEXT XAI COMPLETE")
print("=" * 60)

print(f"Cases explained : {len(cases_df)}")
print(f"Token records   : {len(tokens_df):,}")

print("\nOutputs:")

print(cases_output)
print(tokens_output)
print(summary_output)

if not global_summary.empty:

    print("\nTop globally important tokens:")

    for _, item in global_summary.head(10).iterrows():

        print(
            f"  {item['token']}: "
            f"{item['mean_absolute_weight']:.6f}"
        )