from pathlib import Path
import pandas as pd
import numpy as np
import json

# ============================================================
# PATHS
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parents[2]

INPUT_DIR = PROJECT_DIR / "data" / "processed" / "dwdata_learning"
OUTPUT_DIR = PROJECT_DIR / "data" / "processed" / "training"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_FILE = INPUT_DIR / "train.csv"
VAL_FILE = INPUT_DIR / "validation.csv"
TEST_FILE = INPUT_DIR / "test.csv"

# ============================================================
# CONFIGURATION
# ============================================================

TEXT_COLUMN = "listing_name"
CATEGORY_COLUMN = "category_normalized"
VENDOR_COLUMN = "vendor"
MARKETPLACE_COLUMN = "marketplace"
DATE_COLUMN = "snapshot_date"

MIN_CATEGORY_SAMPLES = 100

# Broad/noisy categories are not useful as semantic targets.
EXCLUDED_CATEGORIES = {
    "other",
    "digital",
    "fraud",
}

# ============================================================
# LOAD DATA
# ============================================================

print("Loading datasets...")

train = pd.read_csv(TRAIN_FILE, low_memory=False)
validation = pd.read_csv(VAL_FILE, low_memory=False)
test = pd.read_csv(TEST_FILE, low_memory=False)

print(f"Train      : {len(train):,}")
print(f"Validation : {len(validation):,}")
print(f"Test       : {len(test):,}")

# ============================================================
# TEXT DATA
# ============================================================

def build_text(df):
    result = pd.DataFrame()

    result["record_id"] = df["record_id"].astype(str)

    result["text"] = (
        df[TEXT_COLUMN]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    result["category"] = (
        df[CATEGORY_COLUMN]
        .fillna("unknown")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    return result


text_train = build_text(train)
text_val = build_text(validation)
text_test = build_text(test)

# ============================================================
# SELECT VALID SEMANTIC CATEGORIES
# ============================================================

category_counts = text_train["category"].value_counts()

valid_categories = category_counts[
    (category_counts >= MIN_CATEGORY_SAMPLES)
    & (~category_counts.index.isin(EXCLUDED_CATEGORIES))
].index.tolist()

valid_categories = sorted(valid_categories)

print("\nSemantic categories:")
print(f"Categories retained: {len(valid_categories)}")

# Map everything outside selected categories to OTHER_SEMANTIC
def assign_semantic_target(df):
    df = df.copy()

    df["semantic_target"] = df["category"].where(
        df["category"].isin(valid_categories),
        "OTHER_SEMANTIC"
    )

    return df


text_train = assign_semantic_target(text_train)
text_val = assign_semantic_target(text_val)
text_test = assign_semantic_target(text_test)

# ============================================================
# LABEL ENCODING
# ============================================================

labels = sorted(text_train["semantic_target"].unique())

label_to_id = {
    label: idx
    for idx, label in enumerate(labels)
}

id_to_label = {
    idx: label
    for label, idx in label_to_id.items()
}

for df in [text_train, text_val, text_test]:
    df["label_id"] = (
        df["semantic_target"]
        .map(label_to_id)
        .fillna(label_to_id["OTHER_SEMANTIC"])
        .astype(int)
    )

# ============================================================
# SAVE TEXT DATA
# ============================================================

text_train.to_csv(
    OUTPUT_DIR / "text_train.csv",
    index=False
)

text_val.to_csv(
    OUTPUT_DIR / "text_validation.csv",
    index=False
)

text_test.to_csv(
    OUTPUT_DIR / "text_test.csv",
    index=False
)

with open(OUTPUT_DIR / "text_label_map.json", "w", encoding="utf-8") as f:
    json.dump(
        {
            "label_to_id": label_to_id,
            "id_to_label": id_to_label,
            "excluded_categories": sorted(EXCLUDED_CATEGORIES),
            "minimum_category_samples": MIN_CATEGORY_SAMPLES,
        },
        f,
        indent=2
    )

# ============================================================
# TABULAR DATA
# ============================================================

# Features selected from the previous DWData model-ready stage.
TABULAR_FEATURES = [
    "price_value",
    "rating",
    "vendor_rating",
    "reputation",
    "sales",
    "sold",
    "views",
    "in_stock",
    "has_price",
    "has_network_indicator",
    "snapshot_month",
    "snapshot_quarter",
    "snapshot_day_of_month",
    "snapshot_day_of_week",
    "snapshot_is_weekend",
    "days_since_first_snapshot",
    "text_char_count",
    "text_unique_word_count",
    "text_avg_word_length",
    "text_digit_count",
    "text_digit_ratio",
    "text_uppercase_count",
    "text_uppercase_ratio",
    "text_special_char_count",
    "text_has_url",
    "text_has_ip",
    "text_has_crypto_term",
    "text_has_malware_term",
    "text_has_credential_term",
    "text_has_exploit_term",
    "category_subcategory_present",
    "category_frequency",
    "vendor_listing_count",
    "vendor_category_count",
    "vendor_marketplace_count",
    "vendor_activity_days",
    "marketplace_listing_count",
    "marketplace_vendor_count",
    "price_log1p",
    "price_text_length",
    "currency_known",
    "is_crypto_currency",
    "price_is_zero",
    "domain_count",
    "ip_count",
    "email_count",
    "total_indicator_count",
    "network_indicator_density",
    "vendor_observation_number",
    "vendor_previous_observation_gap",
]

available_features = [
    col for col in TABULAR_FEATURES
    if col in train.columns
]

print(f"\nTabular features: {len(available_features)}")


def build_tabular(df):
    result = df[
        ["record_id"] + available_features
    ].copy()

    result["record_id"] = result["record_id"].astype(str)

    for col in available_features:
        result[col] = pd.to_numeric(
            result[col],
            errors="coerce"
        )

    result[available_features] = (
        result[available_features]
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0)
    )

    return result


tab_train = build_tabular(train)
tab_val = build_tabular(validation)
tab_test = build_tabular(test)

tab_train.to_csv(
    OUTPUT_DIR / "tabular_train.csv",
    index=False
)

tab_val.to_csv(
    OUTPUT_DIR / "tabular_validation.csv",
    index=False
)

tab_test.to_csv(
    OUTPUT_DIR / "tabular_test.csv",
    index=False
)

with open(OUTPUT_DIR / "tabular_features.json", "w", encoding="utf-8") as f:
    json.dump(
        available_features,
        f,
        indent=2
    )

# ============================================================
# TEMPORAL DATA
# ============================================================

TEMPORAL_COLUMNS = [
    "record_id",
    VENDOR_COLUMN,
    MARKETPLACE_COLUMN,
    DATE_COLUMN,
    "price_value",
    "vendor_observation_number",
    "vendor_previous_observation_gap",
    "vendor_listing_count",
    "vendor_category_count",
    "vendor_marketplace_count",
    "vendor_activity_days",
    "marketplace_listing_count",
    "marketplace_vendor_count",
    "total_indicator_count",
    "has_network_indicator",
    "text_has_malware_term",
    "text_has_credential_term",
    "text_has_exploit_term",
]

available_temporal = [
    col for col in TEMPORAL_COLUMNS
    if col in train.columns
]


def build_temporal(df):
    result = df[available_temporal].copy()

    result["record_id"] = result["record_id"].astype(str)

    if VENDOR_COLUMN in result.columns:
        result[VENDOR_COLUMN] = (
            result[VENDOR_COLUMN]
            .fillna("unknown")
            .astype(str)
        )

    if MARKETPLACE_COLUMN in result.columns:
        result[MARKETPLACE_COLUMN] = (
            result[MARKETPLACE_COLUMN]
            .fillna("unknown")
            .astype(str)
        )

    if DATE_COLUMN in result.columns:
        result[DATE_COLUMN] = pd.to_datetime(
            result[DATE_COLUMN],
            errors="coerce"
        )

    numeric_columns = [
        col for col in available_temporal
        if col not in {
            "record_id",
            VENDOR_COLUMN,
            MARKETPLACE_COLUMN,
            DATE_COLUMN,
        }
    ]

    for col in numeric_columns:
        result[col] = pd.to_numeric(
            result[col],
            errors="coerce"
        ).fillna(0)

    return result.sort_values(
        [VENDOR_COLUMN, DATE_COLUMN]
    )


temporal_train = build_temporal(train)
temporal_val = build_temporal(validation)
temporal_test = build_temporal(test)

# CSV is used for portability.
temporal_train.to_csv(
    OUTPUT_DIR / "temporal_train.csv",
    index=False
)

temporal_val.to_csv(
    OUTPUT_DIR / "temporal_validation.csv",
    index=False
)

temporal_test.to_csv(
    OUTPUT_DIR / "temporal_test.csv",
    index=False
)

# ============================================================
# SUMMARY
# ============================================================

summary = {
    "train_records": len(train),
    "validation_records": len(validation),
    "test_records": len(test),
    "semantic_categories": len(labels),
    "semantic_categories_excluding_other": len(valid_categories),
    "tabular_features": len(available_features),
    "temporal_features": len(available_temporal),
    "text_files": [
        "text_train.csv",
        "text_validation.csv",
        "text_test.csv",
        "text_label_map.json",
    ],
    "tabular_files": [
        "tabular_train.csv",
        "tabular_validation.csv",
        "tabular_test.csv",
        "tabular_features.json",
    ],
    "temporal_files": [
        "temporal_train.csv",
        "temporal_validation.csv",
        "temporal_test.csv",
    ],
}

with open(
    OUTPUT_DIR / "training_data_summary.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(summary, f, indent=2)

# ============================================================
# FINAL OUTPUT
# ============================================================

print("\n========================================")
print("TRAINING DATA PREPARATION COMPLETE")
print("========================================")

print(f"\nOutput directory:")
print(OUTPUT_DIR)

print("\nTEXT MODEL")
print(f"Train      : {len(text_train):,}")
print(f"Validation : {len(text_val):,}")
print(f"Test       : {len(text_test):,}")
print(f"Classes    : {len(labels)}")

print("\nTABULAR MODEL")
print(f"Features   : {len(available_features)}")

print("\nTEMPORAL MODEL")
print(f"Features   : {len(available_temporal)}")

print("\nFiles created successfully.")