import os
import pandas as pd
import numpy as np


BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

TRAINING_DIR = os.path.join(
    BASE_DIR, "reports", "training"
)

XAI_DIR = os.path.join(
    BASE_DIR, "reports", "xai"
)

FUSION_FILE = os.path.join(
    TRAINING_DIR,
    "model_fusion_test.csv"
)

XAI_FILE = os.path.join(
    XAI_DIR,
    "unified_xai_explanations.csv"
)

OUTPUT_FILE = os.path.join(
    TRAINING_DIR,
    "intelligence_correlation.csv"
)

SUMMARY_FILE = os.path.join(
    TRAINING_DIR,
    "intelligence_correlation_summary.csv"
)


# ============================================================
# LOAD
# ============================================================

print("=" * 60)
print("DARKWATCH-XAI INTELLIGENCE CORRELATION")
print("=" * 60)

fusion = pd.read_csv(FUSION_FILE)
xai = pd.read_csv(XAI_FILE)

print(f"Fusion records : {len(fusion):,}")
print(f"XAI records    : {len(xai):,}")


# ============================================================
# NUMERIC SAFETY
# ============================================================

numeric_columns = [
    "behavioral_reconstruction_error",
    "temporal_reconstruction_error",
    "semantic_confidence",
    "fusion_score",
    "signal_count"
]

for col in numeric_columns:

    if col in fusion.columns:

        fusion[col] = pd.to_numeric(
            fusion[col],
            errors="coerce"
        )


# ============================================================
# SIGNAL DEFINITIONS
# ============================================================

def get_bool(value):

    if pd.isna(value):
        return False

    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in [
        "true",
        "1",
        "yes"
    ]


fusion["behavioral_active"] = (
    fusion["behavioral_signal"]
    .apply(get_bool)
)

fusion["temporal_active"] = (
    fusion["temporal_signal"]
    .apply(get_bool)
)


# Semantic signal:
# use confidence rather than inventing a crime label.

fusion["semantic_active"] = (
    fusion["semantic_confidence"]
    >= 0.70
)


# ============================================================
# CORRELATION TYPE
# ============================================================

def classify_correlation(row):

    behavioral = row["behavioral_active"]
    temporal = row["temporal_active"]
    semantic = row["semantic_active"]

    count = sum([
        behavioral,
        temporal,
        semantic
    ])

    if count == 3:
        return "THREE_SIGNAL_CORRELATION"

    if count == 2:
        return "TWO_SIGNAL_CORRELATION"

    if count == 1:
        return "SINGLE_SIGNAL"

    return "NO_STRONG_CORRELATION"


fusion["correlation_type"] = fusion.apply(
    classify_correlation,
    axis=1
)


# ============================================================
# INTELLIGENCE PRIORITY
# ============================================================

def priority(row):

    score = row["fusion_score"]

    if pd.isna(score):
        return "UNASSESSED"

    if score >= 0.80:
        return "HIGH"

    if score >= 0.60:
        return "ELEVATED"

    if score >= 0.30:
        return "MODERATE"

    return "LOW"


fusion["intelligence_priority"] = fusion.apply(
    priority,
    axis=1
)


# ============================================================
# EXPLANATION CORRELATION
# ============================================================

xai["importance"] = pd.to_numeric(
    xai["importance"],
    errors="coerce"
)

xai = xai[
    xai["importance"].notna()
].copy()


# Absolute importance for ranking.
xai["absolute_importance"] = (
    xai["importance"].abs()
)


# Top explanation per case.
top_xai = (
    xai.sort_values(
        [
            "unified_case_id",
            "absolute_importance"
        ],
        ascending=[True, False]
    )
    .groupby("unified_case_id")
    .head(5)
)


# Create compact explanation strings.
explanation_summary = (
    top_xai
    .groupby("unified_case_id")
    .apply(
        lambda group: " | ".join(
            (
                str(row["explanation_source"])
                + ":"
                + str(row["feature_or_token"])
            )
            for _, row in group.iterrows()
        )
    )
    .reset_index(
        name="top_xai_evidence"
    )
)


# ============================================================
# ATTACH XAI SUMMARY
# ============================================================

# XAI uses unified case IDs rather than record IDs.
# Therefore we preserve the XAI evidence as a separate
# evidence pool instead of falsely matching it to records.

if len(explanation_summary) > 0:

    top_global_explanations = (
        xai.sort_values(
            "absolute_importance",
            ascending=False
        )
        .head(20)
        .copy()
    )

    global_evidence = " | ".join(
        (
            str(row["explanation_source"])
            + ":"
            + str(row["feature_or_token"])
        )
        for _, row in top_global_explanations.iterrows()
    )

else:

    global_evidence = ""


# ============================================================
# INTELLIGENCE CASE ID
# ============================================================

fusion = fusion.reset_index(drop=True)

fusion["intelligence_case_id"] = [
    f"INTEL_{i + 1:05d}"
    for i in range(len(fusion))
]


# ============================================================
# ANALYST INTERPRETATION
# ============================================================

def interpretation(row):

    correlation = row["correlation_type"]
    priority_level = row["intelligence_priority"]

    semantic = row.get(
        "semantic_prediction",
        "UNKNOWN"
    )

    confidence = row.get(
        "semantic_confidence",
        np.nan
    )

    if correlation == "THREE_SIGNAL_CORRELATION":

        return (
            "Behavioral, temporal, and semantic "
            "signals are simultaneously active. "
            "Review the observation as a correlated "
            "intelligence case."
        )

    if correlation == "TWO_SIGNAL_CORRELATION":

        return (
            "Two model signals are simultaneously "
            "active. Review the observation and "
            "associated evidence."
        )

    if correlation == "SINGLE_SIGNAL":

        return (
            "One model signal is active. "
            "Additional evidence should be reviewed "
            "before escalation."
        )

    return (
        "No strong multi-signal correlation detected."
    )


fusion["analyst_interpretation"] = fusion.apply(
    interpretation,
    axis=1
)


# ============================================================
# FINAL CORRELATION DATASET
# ============================================================

output_columns = [
    "intelligence_case_id",
    "record_id",
    "category",
    "observation_index",
    "behavioral_reconstruction_error",
    "behavioral_signal",
    "behavioral_anomaly_95",
    "behavioral_anomaly_99",
    "temporal_reconstruction_error",
    "temporal_signal",
    "temporal_anomaly_95",
    "temporal_anomaly_99",
    "semantic_prediction",
    "semantic_confidence",
    "fusion_score",
    "signal_count",
    "signal_agreement",
    "fusion_band",
    "correlation_type",
    "intelligence_priority",
    "analyst_interpretation"
]

output_columns = [
    c for c in output_columns
    if c in fusion.columns
]

correlation = fusion[
    output_columns
].copy()


# ============================================================
# SORT BY INTELLIGENCE PRIORITY
# ============================================================

priority_order = {
    "HIGH": 0,
    "ELEVATED": 1,
    "MODERATE": 2,
    "LOW": 3,
    "UNASSESSED": 4
}

correlation["_priority_order"] = (
    correlation["intelligence_priority"]
    .map(priority_order)
    .fillna(99)
)

correlation = correlation.sort_values(
    [
        "_priority_order",
        "fusion_score"
    ],
    ascending=[
        True,
        False
    ]
)

correlation = correlation.drop(
    columns=["_priority_order"]
)


# ============================================================
# SAVE
# ============================================================

correlation.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# SUMMARY
# ============================================================

summary = (
    correlation[
        [
            "correlation_type",
            "intelligence_priority"
        ]
    ]
    .value_counts()
    .reset_index(
        name="observation_count"
    )
)

summary.to_csv(
    SUMMARY_FILE,
    index=False
)


# ============================================================
# GLOBAL XAI EVIDENCE
# ============================================================

global_xai_file = os.path.join(
    TRAINING_DIR,
    "intelligence_global_xai_evidence.txt"
)

with open(
    global_xai_file,
    "w",
    encoding="utf-8"
) as f:

    f.write(
        "DARKWATCH-XAI GLOBAL XAI EVIDENCE\n"
    )

    f.write("=" * 50 + "\n\n")

    f.write(
        global_evidence
    )

    f.write("\n")


# ============================================================
# REPORT
# ============================================================

print()
print("=" * 60)
print("INTELLIGENCE CORRELATION COMPLETE")
print("=" * 60)

print(
    f"Intelligence cases : {len(correlation):,}"
)

print()
print("Correlation types:")

print(
    correlation[
        "correlation_type"
    ].value_counts()
    .to_string()
)

print()
print("Intelligence priorities:")

print(
    correlation[
        "intelligence_priority"
    ].value_counts()
    .to_string()
)

print()
print("Outputs:")

print(OUTPUT_FILE)
print(SUMMARY_FILE)
print(global_xai_file)

print()
print(
    "NOTE: Semantic predictions represent model "
    "categories, not a crime/no-crime determination."
)

print(
    "NOTE: XAI evidence is preserved separately "
    "because the current XAI files do not contain "
    "a verified shared record identifier."
)