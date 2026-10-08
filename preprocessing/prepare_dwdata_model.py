"""
DarkWatch-XAI
DWData Model-Ready Dataset Preparation

Input:
    data/processed/dwdata_features.csv

Outputs:
    data/processed/dwdata_model_ready.csv
    reports/dwdata_model_feature_report.csv

Purpose:
    Convert the 87-feature DWData dataset into a clean model-ready
    feature dataset while preserving important intelligence/evidence
    fields.

IMPORTANT:
    The original dwdata_features.csv is never modified.
"""

from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parents[1]

INPUT_PATH = (
    PROJECT_DIR
    / "data"
    / "processed"
    / "dwdata_features.csv"
)

OUTPUT_PATH = (
    PROJECT_DIR
    / "data"
    / "processed"
    / "dwdata_model_ready.csv"
)

REPORT_PATH = (
    PROJECT_DIR
    / "reports"
    / "dwdata_model_feature_report.csv"
)

OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

REPORT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("DarkWatch-XAI - DWData Model-Ready Dataset Preparation")
print("=" * 70)

print("\nInput:")
print(INPUT_PATH)

if not INPUT_PATH.exists():
    raise FileNotFoundError(
        f"Input dataset not found:\n{INPUT_PATH}"
    )

df = pd.read_csv(
    INPUT_PATH,
    low_memory=False,
)

print(f"\nRows    : {len(df):,}")
print(f"Columns : {len(df.columns)}")


# ============================================================
# FEATURES TO REMOVE
# ============================================================

# These were identified as constant in the feature-selection analysis.
CONSTANT_FEATURES = {
    "onion_urls",
    "hashes",
    "has_vendor",
    "has_listing_name",
    "has_category",
    "category_parent_present",
    "onion_count",
    "hash_count",
    "has_onion",
    "has_hash",
}


# Redundant representations identified from correlation analysis.
# We retain the more useful/general representation in each group.

CORRELATED_REMOVE = {
    # has_price == has_numeric_price
    "has_numeric_price",

    # has_network_indicator == has_any_indicator
    "has_any_indicator",

    # domain presence is represented by domain_count
    "has_domain",

    # total_indicator_count already captures domain/IP/email counts
    # while individual counts are retained where useful.
    # Keep total_indicator_count.

    # text_has_email == email_count/has_email
    "text_has_email",
    "has_email",

    # ip_count ~= has_ip
    "has_ip",

    # word count and unique word count are highly correlated.
    # Keep unique-word information because it captures vocabulary
    # diversity rather than just length.
    "text_word_count",

    # snapshot_year and days_since_first_snapshot are highly correlated.
    # Keep days_since_first_snapshot because it represents temporal
    # distance from the beginning of the dataset.
    "snapshot_year",
}


# ============================================================
# EVIDENCE / CONTEXT FIELDS
# ============================================================

# These fields are intentionally preserved for intelligence analysis
# and dashboard evidence. They are not necessarily neural-network
# input features.

EVIDENCE_FIELDS = [
    "record_id",
    "snapshot_date",
    "marketplace",
    "section",
    "vendor_raw",
    "vendor",
    "listing_name_raw",
    "listing_name",
    "category_raw",
    "category_normalized",
    "category_parent",
    "category_subcategory",
    "price_raw",
    "currency",
    "domains",
    "ip_addresses",
    "emails",
    "source_file",
]


# ============================================================
# CANDIDATE MODEL FEATURES
# ============================================================

# Start with all engineered features.

engineered_features = [
    c
    for c in df.columns
    if c not in EVIDENCE_FIELDS
]


# Remove constants and deliberately redundant representations.

model_features = [
    c
    for c in engineered_features
    if c not in CONSTANT_FEATURES
    and c not in CORRELATED_REMOVE
]


# Keep selected useful original numerical attributes.

ORIGINAL_NUMERIC_FEATURES = [
    "price_value",
    "rating",
    "vendor_rating",
    "reputation",
    "sales",
    "sold",
    "views",
    "in_stock",
]


for feature in ORIGINAL_NUMERIC_FEATURES:

    if feature in df.columns:
        if feature not in model_features:
            model_features.append(feature)


# ============================================================
# MISSINGNESS HANDLING
# ============================================================

print("\nPreparing numerical features...")

numeric_model_features = [
    c
    for c in model_features
    if pd.api.types.is_numeric_dtype(df[c])
]

for feature in numeric_model_features:

    missing_before = int(
        df[feature].isna().sum()
    )

    if missing_before == 0:
        continue

    # Median imputation preserves all observations.
    median_value = df[feature].median()

    if pd.isna(median_value):
        median_value = 0.0

    df[feature] = (
        df[feature]
        .fillna(median_value)
    )


# ============================================================
# SANITY CHECKS
# ============================================================

print("\nRunning sanity checks...")

if df[model_features].isna().any().any():

    remaining_missing = (
        df[model_features]
        .isna()
        .sum()
    )

    remaining_missing = (
        remaining_missing[
            remaining_missing > 0
        ]
        .sort_values(
            ascending=False
        )
    )

    print(
        "\nWARNING: Some model features still contain missing values:"
    )

    print(
        remaining_missing.to_string()
    )


# Replace infinite numerical values.

df[model_features] = (
    df[model_features]
    .replace(
        [np.inf, -np.inf],
        np.nan,
    )
)


# Final median fill after infinity replacement.

for feature in numeric_model_features:

    if df[feature].isna().any():

        median_value = (
            df[feature]
            .median()
        )

        if pd.isna(median_value):
            median_value = 0.0

        df[feature] = (
            df[feature]
            .fillna(median_value)
        )


# ============================================================
# BUILD FINAL DATASET
# ============================================================

# Evidence/context comes first.
# Model features come after it.

final_columns = [
    c
    for c in EVIDENCE_FIELDS
    if c in df.columns
]

final_columns += [
    c
    for c in model_features
    if c not in final_columns
]

model_df = df[final_columns].copy()


# ============================================================
# REPORT
# ============================================================

report_rows = []

for feature in df.columns:

    if feature in CONSTANT_FEATURES:

        status = "REMOVED"
        reason = "CONSTANT"

    elif feature in CORRELATED_REMOVE:

        status = "REMOVED"
        reason = "REDUNDANT_CORRELATED_FEATURE"

    elif feature in EVIDENCE_FIELDS:

        status = "EVIDENCE_ONLY"
        reason = "PRESERVED_FOR_INTELLIGENCE_CONTEXT"

    elif feature in model_features:

        status = "MODEL_INPUT"
        reason = "SELECTED_MODEL_FEATURE"

    else:

        status = "NOT_SELECTED"
        reason = "NOT_SELECTED"

    report_rows.append(
        {
            "feature": feature,
            "status": status,
            "reason": reason,
            "dtype": str(
                df[feature].dtype
            ),
            "missing_before_imputation": int(
                df[feature].isna().sum()
            ),
            "unique_values": int(
                df[feature].nunique(
                    dropna=True
                )
            ),
        }
    )


report = pd.DataFrame(
    report_rows
)

report.to_csv(
    REPORT_PATH,
    index=False,
)


# ============================================================
# SAVE
# ============================================================

model_df.to_csv(
    OUTPUT_PATH,
    index=False,
)


# ============================================================
# FINAL VALIDATION
# ============================================================

print("\n" + "=" * 70)
print("MODEL-READY DATASET CREATED")
print("=" * 70)

print(
    f"Original columns     : {len(df.columns)}"
)

print(
    f"Evidence columns     : "
    f"{len([c for c in EVIDENCE_FIELDS if c in df.columns])}"
)

print(
    f"Model features       : "
    f"{len(model_features)}"
)

print(
    f"Final columns        : "
    f"{len(model_df.columns)}"
)

print(
    f"Rows                 : "
    f"{len(model_df):,}"
)

print(
    f"Duplicate rows       : "
    f"{model_df.duplicated().sum():,}"
)

print(
    f"Missing model values : "
    f"{model_df[model_features].isna().sum().sum():,}"
)

print(
    f"Infinite model values: "
    f"{np.isinf(
        model_df[model_features]
        .select_dtypes(include=np.number)
    ).sum().sum():,}"
)

print("\nModel features:")

for feature in model_features:
    print(f"  - {feature}")

print("\nOutput:")
print(OUTPUT_PATH)

print("\nFeature report:")
print(REPORT_PATH)

print("=" * 70)