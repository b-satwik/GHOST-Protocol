import os
import pandas as pd
import numpy as np


BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

XAI_DIR = os.path.join(BASE_DIR, "reports", "xai")
TRAINING_DIR = os.path.join(BASE_DIR, "reports", "training")

FUSION_FILE = os.path.join(
    TRAINING_DIR, "model_fusion_test.csv"
)

BEHAVIORAL_FILE = os.path.join(
    XAI_DIR, "behavioral_shap_cases.csv"
)

TEXT_CASES_FILE = os.path.join(
    XAI_DIR, "text_lime_cases.csv"
)

TEXT_TOKENS_FILE = os.path.join(
    XAI_DIR, "text_lime_tokens.csv"
)

TEMPORAL_CASES_FILE = os.path.join(
    XAI_DIR, "temporal_xai_cases.csv"
)

OUTPUT_FILE = os.path.join(
    XAI_DIR, "unified_xai_explanations.csv"
)

SUMMARY_FILE = os.path.join(
    XAI_DIR, "unified_xai_summary.csv"
)


def load_csv(path):
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Missing required file:\n{path}"
        )

    return pd.read_csv(path)


def find_importance_column(df):
    """
    Find a genuine numeric importance column.
    """

    preferred = [
        "importance",
        "weight",
        "lime_weight",
        "shap_value",
        "contribution",
        "score"
    ]

    for col in preferred:
        if col in df.columns:
            numeric = pd.to_numeric(
                df[col],
                errors="coerce"
            )

            if numeric.notna().any():
                return col

    return None


def find_token_column(df):
    preferred = [
        "token",
        "word",
        "feature",
        "term"
    ]

    for col in preferred:
        if col in df.columns:
            return col

    return None


print("=" * 60)
print("DARKWATCH-XAI UNIFIED EXPLANATION")
print("=" * 60)


# ============================================================
# LOAD
# ============================================================

fusion = load_csv(FUSION_FILE)
behavioral = load_csv(BEHAVIORAL_FILE)
text_cases = load_csv(TEXT_CASES_FILE)
text_tokens = load_csv(TEXT_TOKENS_FILE)
temporal = load_csv(TEMPORAL_CASES_FILE)


print(f"Fusion records     : {len(fusion):,}")
print(f"Behavioral cases   : {len(behavioral):,}")
print(f"Text cases         : {len(text_cases):,}")
print(f"Text token records : {len(text_tokens):,}")
print(f"Temporal cases     : {len(temporal):,}")


# ============================================================
# SELECT TOP 100 FUSION CASES
# ============================================================

if "fusion_score" in fusion.columns:

    selected = fusion.sort_values(
        "fusion_score",
        ascending=False
    ).head(100).copy()

elif "final_score" in fusion.columns:

    selected = fusion.sort_values(
        "final_score",
        ascending=False
    ).head(100).copy()

else:

    selected = fusion.head(100).copy()


selected = selected.reset_index(drop=True)

selected["unified_case_id"] = [
    f"UNIFIED_{i + 1:03d}"
    for i in range(len(selected))
]


print(
    f"Selected cases for unified explanation: "
    f"{len(selected)}"
)


# ============================================================
# FUSION INFORMATION
# ============================================================

fusion_columns = [
    "fusion_score",
    "fusion_band",
    "signal_agreement",
    "behavioral_signal",
    "temporal_signal",
    "semantic_signal",
    "semantic_confidence",
    "semantic_label"
]

available_fusion_columns = [
    c for c in fusion_columns
    if c in selected.columns
]

fusion_info = selected[
    ["unified_case_id"] + available_fusion_columns
].copy()


# ============================================================
# OUTPUT ROWS
# ============================================================

rows = []


# ============================================================
# BEHAVIORAL XAI
# ============================================================

print()
print("Processing behavioral explanations...")

behavioral_importance_col = find_importance_column(
    behavioral
)

print(
    "Behavioral importance column:",
    behavioral_importance_col
)


if behavioral_importance_col is not None:

    numeric_importance = pd.to_numeric(
        behavioral[behavioral_importance_col],
        errors="coerce"
    )

    # Use up to first 100 behavioral explanation cases.
    for i in range(min(100, len(behavioral))):

        value = numeric_importance.iloc[i]

        if pd.isna(value):
            continue

        case_id = f"UNIFIED_{i + 1:03d}"

        # Determine feature name.
        if "feature" in behavioral.columns:

            feature_name = str(
                behavioral.iloc[i]["feature"]
            )

        elif "feature_name" in behavioral.columns:

            feature_name = str(
                behavioral.iloc[i]["feature_name"]
            )

        else:

            feature_name = "behavioral_feature"

        rows.append({
            "unified_case_id": case_id,
            "explanation_source": "behavioral",
            "feature_or_token": feature_name,
            "importance": float(value)
        })

else:

    # Some versions of the behavioral explanation file
    # store each feature as a column instead of having
    # an explicit importance column.
    excluded = {
        "case_index",
        "case_id",
        "record_id",
        "index",
        "rank"
    }

    candidate_columns = [
        c for c in behavioral.columns
        if c not in excluded
    ]

    for i in range(min(100, len(behavioral))):

        case_id = f"UNIFIED_{i + 1:03d}"

        for feature in candidate_columns:

            value = pd.to_numeric(
                behavioral.iloc[i][feature],
                errors="coerce"
            )

            if pd.isna(value):
                continue

            rows.append({
                "unified_case_id": case_id,
                "explanation_source": "behavioral",
                "feature_or_token": feature,
                "importance": float(value)
            })


# ============================================================
# TEXT XAI
# ============================================================

print()
print("Processing text explanations...")

token_col = find_token_column(text_tokens)
text_importance_col = find_importance_column(
    text_tokens
)

print(
    "Text token column:",
    token_col
)

print(
    "Text importance column:",
    text_importance_col
)


if (
    token_col is not None
    and text_importance_col is not None
):

    text_values = pd.to_numeric(
        text_tokens[text_importance_col],
        errors="coerce"
    )

    for i in range(len(text_tokens)):

        value = text_values.iloc[i]

        if pd.isna(value):
            continue

        case_number = (
            (i % max(1, min(10, len(text_cases)))) + 1
        )

        rows.append({
            "unified_case_id":
                f"UNIFIED_{case_number:03d}",

            "explanation_source":
                "text",

            "feature_or_token":
                str(text_tokens.iloc[i][token_col]),

            "importance":
                float(value)
        })


# ============================================================
# TEMPORAL XAI
# ============================================================

print()
print("Processing temporal explanations...")

temporal_importance_col = find_importance_column(
    temporal
)

print(
    "Temporal importance column:",
    temporal_importance_col
)


if temporal_importance_col is not None:

    temporal_values = pd.to_numeric(
        temporal[temporal_importance_col],
        errors="coerce"
    )

    for i in range(min(100, len(temporal))):

        value = temporal_values.iloc[i]

        if pd.isna(value):
            continue

        if "feature" in temporal.columns:

            feature_name = str(
                temporal.iloc[i]["feature"]
            )

        elif "feature_name" in temporal.columns:

            feature_name = str(
                temporal.iloc[i]["feature_name"]
            )

        else:

            feature_name = "temporal_feature"

        rows.append({
            "unified_case_id":
                f"UNIFIED_{i + 1:03d}",

            "explanation_source":
                "temporal",

            "feature_or_token":
                feature_name,

            "importance":
                float(value)
        })


else:

    excluded = {
        "case_index",
        "case_id",
        "record_id",
        "index",
        "rank"
    }

    candidate_columns = [
        c for c in temporal.columns
        if c not in excluded
    ]

    for i in range(min(100, len(temporal))):

        case_id = f"UNIFIED_{i + 1:03d}"

        for feature in candidate_columns:

            value = pd.to_numeric(
                temporal.iloc[i][feature],
                errors="coerce"
            )

            if pd.isna(value):
                continue

            rows.append({
                "unified_case_id": case_id,
                "explanation_source": "temporal",
                "feature_or_token": feature,
                "importance": float(value)
            })


# ============================================================
# BUILD DATAFRAME
# ============================================================

if len(rows) == 0:

    raise RuntimeError(
        "No valid XAI explanation values were found."
    )


explanations = pd.DataFrame(rows)


# ============================================================
# ENSURE IMPORTANCE IS NUMERIC
# ============================================================

explanations["importance"] = pd.to_numeric(
    explanations["importance"],
    errors="coerce"
)

explanations = explanations[
    explanations["importance"].notna()
].copy()


# ============================================================
# ADD FUSION INFORMATION
# ============================================================

explanations = explanations.merge(
    fusion_info,
    on="unified_case_id",
    how="left"
)


# ============================================================
# SORT SAFELY
# ============================================================

explanations["abs_importance"] = (
    explanations["importance"].abs()
)

explanations = explanations.sort_values(
    [
        "unified_case_id",
        "abs_importance"
    ],
    ascending=[
        True,
        False
    ]
)

explanations = explanations.drop(
    columns=["abs_importance"]
)


# ============================================================
# SAVE
# ============================================================

explanations.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# SUMMARY
# ============================================================

summary_rows = []

for source in [
    "behavioral",
    "text",
    "temporal"
]:

    subset = explanations[
        explanations["explanation_source"] == source
    ]

    summary_rows.append({
        "explanation_source": source,
        "records": len(subset),
        "unique_cases":
            subset["unified_case_id"].nunique()
    })


summary = pd.DataFrame(summary_rows)

summary.to_csv(
    SUMMARY_FILE,
    index=False
)


# ============================================================
# FINAL REPORT
# ============================================================

print()
print("=" * 60)
print("UNIFIED XAI COMPLETE")
print("=" * 60)

print(
    f"Unified cases       : {len(selected):,}"
)

print(
    f"Explanation records : {len(explanations):,}"
)

print()
print("Explanation sources:")

for _, row in summary.iterrows():

    print(
        f"  {row['explanation_source']:12s}"
        f" : {int(row['records']):,} records"
        f" / {int(row['unique_cases']):,} cases"
    )

print()
print("Outputs:")
print(OUTPUT_FILE)
print(SUMMARY_FILE)

print()
print("Unified XAI stage completed.")