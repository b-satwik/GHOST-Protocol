import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


# ============================================================
# DARKWATCH-XAI
# TEMPORAL DATASET PREPARATION V2
# ============================================================

print("=" * 70)
print("DARKWATCH-XAI TEMPORAL DATASET PREPARATION V2")
print("=" * 70)


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

INPUT_PATH = "data/processed/dwdata_features.csv"

OUTPUT_DIR = "data/processed/training/temporal_v2"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ------------------------------------------------------------
# TEMPORAL FEATURES
# ------------------------------------------------------------

TEMPORAL_FEATURES = [
    "snapshot_year",
    "snapshot_month",
    "snapshot_quarter",
    "snapshot_day_of_month",
    "snapshot_day_of_week",
    "snapshot_is_weekend",
    "days_since_first_snapshot",
    "vendor_activity_days",
    "vendor_listing_count",
    "marketplace_listing_count",
    "vendor_observation_number",
    "vendor_previous_observation_gap",
    "category_frequency",
    "marketplace_vendor_count",
]


# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

print("\nLoading dataset...")
df = pd.read_csv(INPUT_PATH)

print(f"Input records : {len(df):,}")
print(f"Input columns : {len(df.columns)}")


# ------------------------------------------------------------
# CHECK FEATURES
# ------------------------------------------------------------

missing_features = [
    feature
    for feature in TEMPORAL_FEATURES
    if feature not in df.columns
]

if missing_features:
    raise ValueError(
        "Missing temporal features:\n"
        + "\n".join(missing_features)
    )


temporal = df[
    ["record_id"] + TEMPORAL_FEATURES
].copy()


print(f"\nTemporal records : {len(temporal):,}")
print(f"Temporal features: {len(TEMPORAL_FEATURES)}")


# ------------------------------------------------------------
# CONVERT TO NUMERIC
# ------------------------------------------------------------

for feature in TEMPORAL_FEATURES:
    temporal[feature] = pd.to_numeric(
        temporal[feature],
        errors="coerce"
    )


# ------------------------------------------------------------
# HANDLE INFINITIES
# ------------------------------------------------------------

temporal[TEMPORAL_FEATURES] = temporal[
    TEMPORAL_FEATURES
].replace(
    [np.inf, -np.inf],
    np.nan
)


# ------------------------------------------------------------
# MISSING VALUE STATISTICS
# ------------------------------------------------------------

print("\nMissing values before imputation:")

missing_before = temporal[TEMPORAL_FEATURES].isna().sum()

for feature, count in missing_before.items():
    if count > 0:
        print(f"  {feature:<40} {count:,}")


# ------------------------------------------------------------
# MEDIAN IMPUTATION
# ------------------------------------------------------------

medians = temporal[TEMPORAL_FEATURES].median()

temporal[TEMPORAL_FEATURES] = temporal[
    TEMPORAL_FEATURES
].fillna(medians)


# ------------------------------------------------------------
# FINAL SAFETY CHECK
# ------------------------------------------------------------

if temporal[TEMPORAL_FEATURES].isna().any().any():
    raise ValueError(
        "NaN values still remain after imputation."
    )

if np.isinf(
    temporal[TEMPORAL_FEATURES].to_numpy()
).any():
    raise ValueError(
        "Infinite values still remain."
    )


print("\nMissing values handled.")


# ------------------------------------------------------------
# SPLIT DATA
# ------------------------------------------------------------

print("\nSplitting dataset...")

train_df, temp_df = train_test_split(
    temporal,
    test_size=0.30,
    random_state=42,
    shuffle=True
)

val_df, test_df = train_test_split(
    temp_df,
    test_size=0.5833333333,
    random_state=42,
    shuffle=True
)


print(f"Training   : {len(train_df):,}")
print(f"Validation : {len(val_df):,}")
print(f"Test       : {len(test_df):,}")


# ------------------------------------------------------------
# FIT SCALER ONLY ON TRAINING DATA
# ------------------------------------------------------------

print("\nFitting StandardScaler on training data only...")

scaler = StandardScaler()

train_values = train_df[TEMPORAL_FEATURES].values
val_values = val_df[TEMPORAL_FEATURES].values
test_values = test_df[TEMPORAL_FEATURES].values

scaler.fit(train_values)


# ------------------------------------------------------------
# NORMALIZE
# ------------------------------------------------------------

train_scaled = scaler.transform(train_values)
val_scaled = scaler.transform(val_values)
test_scaled = scaler.transform(test_values)


# ------------------------------------------------------------
# BUILD NORMALIZED DATASETS
# ------------------------------------------------------------

train_normalized = pd.DataFrame(
    train_scaled,
    columns=TEMPORAL_FEATURES,
    index=train_df.index
)

val_normalized = pd.DataFrame(
    val_scaled,
    columns=TEMPORAL_FEATURES,
    index=val_df.index
)

test_normalized = pd.DataFrame(
    test_scaled,
    columns=TEMPORAL_FEATURES,
    index=test_df.index
)


# Preserve record IDs

train_normalized.insert(
    0,
    "record_id",
    train_df["record_id"].values
)

val_normalized.insert(
    0,
    "record_id",
    val_df["record_id"].values
)

test_normalized.insert(
    0,
    "record_id",
    test_df["record_id"].values
)


# ------------------------------------------------------------
# ADD SPLIT COLUMN
# ------------------------------------------------------------

train_normalized["split"] = "train"
val_normalized["split"] = "validation"
test_normalized["split"] = "test"


# ------------------------------------------------------------
# COMBINE
# ------------------------------------------------------------

combined = pd.concat(
    [
        train_normalized,
        val_normalized,
        test_normalized
    ],
    ignore_index=True
)


# ------------------------------------------------------------
# STATISTICS BEFORE NORMALIZATION
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("STATISTICS BEFORE NORMALIZATION")
print("=" * 70)

before_stats = train_df[TEMPORAL_FEATURES].describe().T[
    ["mean", "std", "min", "max"]
]

print(before_stats.to_string())


# ------------------------------------------------------------
# STATISTICS AFTER NORMALIZATION
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("STATISTICS AFTER NORMALIZATION")
print("=" * 70)

after_stats = train_normalized[
    TEMPORAL_FEATURES
].describe().T[
    ["mean", "std", "min", "max"]
]

print(after_stats.to_string())


# ------------------------------------------------------------
# SAVE DATASETS
# ------------------------------------------------------------

combined_path = os.path.join(
    OUTPUT_DIR,
    "temporal_normalized_combined.csv"
)

train_path = os.path.join(
    OUTPUT_DIR,
    "temporal_train.csv"
)

val_path = os.path.join(
    OUTPUT_DIR,
    "temporal_validation.csv"
)

test_path = os.path.join(
    OUTPUT_DIR,
    "temporal_test.csv"
)

scaler_path = os.path.join(
    OUTPUT_DIR,
    "temporal_scaler.joblib"
)

features_path = os.path.join(
    OUTPUT_DIR,
    "temporal_features.json"
)

stats_path = os.path.join(
    OUTPUT_DIR,
    "temporal_normalization_stats.json"
)


combined.to_csv(
    combined_path,
    index=False
)

train_normalized.to_csv(
    train_path,
    index=False
)

val_normalized.to_csv(
    val_path,
    index=False
)

test_normalized.to_csv(
    test_path,
    index=False
)

joblib.dump(
    scaler,
    scaler_path
)

with open(features_path, "w", encoding="utf-8") as f:
    json.dump(
        TEMPORAL_FEATURES,
        f,
        indent=2
    )


# ------------------------------------------------------------
# SAVE STATISTICS
# ------------------------------------------------------------

stats = {
    "input_records": int(len(df)),
    "temporal_records": int(len(temporal)),
    "train_records": int(len(train_normalized)),
    "validation_records": int(len(val_normalized)),
    "test_records": int(len(test_normalized)),
    "feature_count": len(TEMPORAL_FEATURES),
    "features": TEMPORAL_FEATURES,
    "scaler": "StandardScaler",
    "scaler_fit_on": "training_split_only",
    "random_state": 42,
    "before_normalization": before_stats.to_dict(
        orient="index"
    ),
    "after_normalization": after_stats.to_dict(
        orient="index"
    )
}

with open(
    stats_path,
    "w",
    encoding="utf-8"
) as f:
    json.dump(
        stats,
        f,
        indent=2,
        default=float
    )


# ------------------------------------------------------------
# FINAL CHECKS
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TEMPORAL DATASET PREPARATION COMPLETE")
print("=" * 70)

print(f"\nCombined dataset : {combined_path}")
print(f"Training dataset : {train_path}")
print(f"Validation       : {val_path}")
print(f"Test dataset     : {test_path}")
print(f"Scaler           : {scaler_path}")
print(f"Feature list     : {features_path}")
print(f"Statistics       : {stats_path}")

print("\nFinal shapes:")
print(f"  Combined   : {combined.shape}")
print(f"  Training   : {train_normalized.shape}")
print(f"  Validation : {val_normalized.shape}")
print(f"  Test       : {test_normalized.shape}")

print("\nNormalization check:")
print(
    f"  Training mean: "
    f"{train_normalized[TEMPORAL_FEATURES].values.mean():.6f}"
)

print(
    f"  Training std : "
    f"{train_normalized[TEMPORAL_FEATURES].values.std():.6f}"
)

print("\nReady for temporal model training.")