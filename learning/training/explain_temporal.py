import os
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

ROOT = r"C:\Users\buyya\Desktop\darkwatch"

TEST_FILE = os.path.join(
    ROOT, "data", "processed", "training", "temporal_test.csv"
)

MODEL_FILE = os.path.join(
    ROOT, "models", "dwdata_temporal_model", "temporal_autoencoder.pt"
)

FEATURE_FILE = os.path.join(
    ROOT, "models", "dwdata_temporal_model", "temporal_features.json"
)

SCALER_FILE = os.path.join(
    ROOT, "models", "dwdata_temporal_model", "temporal_scaler.npz"
)

FUSION_FILE = os.path.join(
    ROOT, "reports", "training", "model_fusion_test.csv"
)

OUTPUT_DIR = os.path.join(ROOT, "reports", "xai")

os.makedirs(OUTPUT_DIR, exist_ok=True)

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


# ============================================================
# MODEL
# Exact architecture used by the trained checkpoint:
# 14 -> 32 -> 16 -> 8 -> 16 -> 32 -> 14
# ============================================================

class TemporalAutoencoder(nn.Module):

    def __init__(self, input_dim):

        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8)
        )

        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim)
        )

    def forward(self, x):

        latent = self.encoder(x)

        return self.decoder(latent)


# ============================================================
# CHECK FILES
# ============================================================

for path in [
    TEST_FILE,
    MODEL_FILE,
    FEATURE_FILE,
    SCALER_FILE,
    FUSION_FILE
]:

    if not os.path.exists(path):
        raise FileNotFoundError(path)


print("=" * 60)
print("DARKWATCH-XAI TEMPORAL EXPLANATION")
print("=" * 60)

print(f"Device: {DEVICE}")


# ============================================================
# FEATURES
# ============================================================

with open(FEATURE_FILE, "r", encoding="utf-8") as f:
    feature_data = json.load(f)

if isinstance(feature_data, list):
    features = feature_data

elif "feature_columns" in feature_data:
    features = feature_data["feature_columns"]

elif "features" in feature_data:
    features = feature_data["features"]

else:
    raise ValueError(
        "Could not find temporal feature list."
    )

print(f"Temporal features: {len(features)}")


# ============================================================
# LOAD DATA
# ============================================================

test_df = pd.read_csv(TEST_FILE)
fusion_df = pd.read_csv(FUSION_FILE)

print(f"Temporal records: {len(test_df):,}")
print(f"Fusion records  : {len(fusion_df):,}")


# ============================================================
# ALIGN
# ============================================================

if (
    "record_id" in test_df.columns
    and "record_id" in fusion_df.columns
):

    merged = test_df.merge(
        fusion_df,
        on="record_id",
        how="inner",
        suffixes=("_temporal", "_fusion")
    )

else:

    n = min(len(test_df), len(fusion_df))

    merged = test_df.iloc[:n].copy()

    for column in fusion_df.columns:

        if column not in merged.columns:

            merged[column] = (
                fusion_df.iloc[:n][column].values
            )


print(f"Aligned records: {len(merged):,}")


# ============================================================
# LOAD SCALER
# ============================================================

scaler_data = np.load(SCALER_FILE)

mean = scaler_data["mean"]
scale = scaler_data["scale"]

X = merged[features].astype(
    np.float32
).values

scale_safe = np.where(
    scale == 0,
    1.0,
    scale
)

X_scaled = (
    X - mean
) / scale_safe


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

checkpoint = torch.load(
    MODEL_FILE,
    map_location=DEVICE
)

input_dim = int(
    checkpoint.get(
        "input_dim",
        len(features)
    )
)

model = TemporalAutoencoder(input_dim)

model.load_state_dict(
    checkpoint["model_state_dict"]
)

model.to(DEVICE)
model.eval()

print(
    f"Model loaded: "
    f"{input_dim} → 32 → 16 → 8"
)


# ============================================================
# RECONSTRUCTION
# ============================================================

tensor_x = torch.tensor(
    X_scaled,
    dtype=torch.float32,
    device=DEVICE
)

with torch.no_grad():

    reconstructed = model(
        tensor_x
    )

reconstructed = (
    reconstructed
    .cpu()
    .numpy()
)


# ============================================================
# FEATURE-LEVEL RECONSTRUCTION ERRORS
# ============================================================

feature_errors = (
    X_scaled - reconstructed
) ** 2

total_errors = feature_errors.mean(
    axis=1
)


print(
    f"Mean temporal error: "
    f"{total_errors.mean():.6f}"
)

print(
    f"Median temporal error: "
    f"{np.median(total_errors):.6f}"
)


# ============================================================
# SELECT TOP 100 CASES
# ============================================================

top_n = min(
    100,
    len(merged)
)

selected_indices = np.argsort(
    total_errors
)[-top_n:][::-1]

print(
    f"Cases explained: {top_n}"
)


# ============================================================
# EXPLANATIONS
# ============================================================

case_rows = []
feature_rows = []


for rank, idx in enumerate(
    selected_indices,
    start=1
):

    row = merged.iloc[idx]

    errors = feature_errors[idx]

    order = np.argsort(
        errors
    )[::-1]

    record_id = row.get(
        "record_id",
        idx
    )

    fusion_score = row.get(
        "fusion_score",
        np.nan
    )

    fusion_band = row.get(
        "fusion_band",
        ""
    )

    case_rows.append({

        "explanation_rank": rank,

        "record_id": record_id,

        "temporal_reconstruction_error":
            float(total_errors[idx]),

        "fusion_score":
            float(fusion_score)
            if pd.notna(fusion_score)
            else np.nan,

        "fusion_band":
            fusion_band,

        "top_temporal_feature":
            features[order[0]],

        "top_feature_error":
            float(errors[order[0]])
    })


    for feature_rank, feature_idx in enumerate(
        order[:10],
        start=1
    ):

        feature_rows.append({

            "explanation_rank": rank,

            "record_id": record_id,

            "feature_rank": feature_rank,

            "feature":
                features[feature_idx],

            "reconstruction_error":
                float(errors[feature_idx]),

            "relative_contribution":
                float(
                    errors[feature_idx]
                    /
                    (
                        errors.sum()
                        + 1e-12
                    )
                )
        })


# ============================================================
# SAVE CASES
# ============================================================

cases_df = pd.DataFrame(
    case_rows
)

features_df = pd.DataFrame(
    feature_rows
)

cases_output = os.path.join(
    OUTPUT_DIR,
    "temporal_xai_cases.csv"
)

features_output = os.path.join(
    OUTPUT_DIR,
    "temporal_xai_features.csv"
)

summary_output = os.path.join(
    OUTPUT_DIR,
    "temporal_xai_summary.csv"
)

cases_df.to_csv(
    cases_output,
    index=False
)

features_df.to_csv(
    features_output,
    index=False
)


# ============================================================
# GLOBAL SUMMARY
# ============================================================

global_summary = (
    features_df
    .groupby("feature")
    .agg(
        mean_error=(
            "reconstruction_error",
            "mean"
        ),
        mean_relative_contribution=(
            "relative_contribution",
            "mean"
        ),
        occurrence_count=(
            "feature",
            "count"
        )
    )
    .reset_index()
    .sort_values(
        "mean_error",
        ascending=False
    )
)

global_summary.to_csv(
    summary_output,
    index=False
)


# ============================================================
# FINISHED
# ============================================================

print("\n" + "=" * 60)
print("TEMPORAL XAI COMPLETE")
print("=" * 60)

print(
    f"Cases explained: {len(cases_df)}"
)

print(
    f"Feature explanations: "
    f"{len(features_df):,}"
)

print("\nTop temporal features:")

for _, item in global_summary.head(10).iterrows():

    print(
        f"  {item['feature']}: "
        f"{item['mean_error']:.6f}"
    )

print("\nOutputs:")

print(cases_output)
print(features_output)
print(summary_output)