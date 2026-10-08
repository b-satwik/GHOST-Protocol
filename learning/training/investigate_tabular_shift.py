import os
import json
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler


# ============================================================
# DARKWATCH-XAI
# TABULAR DISTRIBUTION SHIFT INVESTIGATION
# ============================================================

BASE_DIR = r"C:\Users\buyya\Desktop\darkwatch"

DATA_DIR = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "training"
)

REPORT_DIR = os.path.join(
    BASE_DIR,
    "reports",
    "training"
)

os.makedirs(REPORT_DIR, exist_ok=True)


TRAIN_PATH = os.path.join(DATA_DIR, "tabular_train.csv")
VAL_PATH = os.path.join(DATA_DIR, "tabular_validation.csv")
TEST_PATH = os.path.join(DATA_DIR, "tabular_test.csv")

FEATURE_PATH = os.path.join(DATA_DIR, "tabular_features.json")


print("=" * 70)
print("DARKWATCH-XAI")
print("TABULAR DISTRIBUTION SHIFT INVESTIGATION")
print("=" * 70)


# ============================================================
# LOAD FEATURE LIST
# ============================================================

with open(FEATURE_PATH, "r", encoding="utf-8") as f:
    feature_data = json.load(f)


if isinstance(feature_data, dict):
    if "features" in feature_data:
        FEATURES = feature_data["features"]
    elif "tabular_features" in feature_data:
        FEATURES = feature_data["tabular_features"]
    else:
        FEATURES = list(feature_data.values())[0]
else:
    FEATURES = feature_data


print()
print(f"Features loaded : {len(FEATURES)}")


# ============================================================
# LOAD DATA
# ============================================================

print()
print("Loading datasets...")

train = pd.read_csv(TRAIN_PATH)
val = pd.read_csv(VAL_PATH)
test = pd.read_csv(TEST_PATH)

print(f"Train      : {len(train):,}")
print(f"Validation : {len(val):,}")
print(f"Test       : {len(test):,}")


# ============================================================
# CHECK FEATURES
# ============================================================

missing_train = [f for f in FEATURES if f not in train.columns]
missing_val = [f for f in FEATURES if f not in val.columns]
missing_test = [f for f in FEATURES if f not in test.columns]

if missing_train or missing_val or missing_test:

    print()
    print("ERROR: Missing features detected.")

    if missing_train:
        print("Train missing:", missing_train)

    if missing_val:
        print("Validation missing:", missing_val)

    if missing_test:
        print("Test missing:", missing_test)

    raise SystemExit(1)


# ============================================================
# NUMERIC CONVERSION
# ============================================================

train_x = train[FEATURES].apply(pd.to_numeric, errors="coerce")
val_x = val[FEATURES].apply(pd.to_numeric, errors="coerce")
test_x = test[FEATURES].apply(pd.to_numeric, errors="coerce")


# ============================================================
# FEATURE DISTRIBUTION ANALYSIS
# ============================================================

rows = []

for feature in FEATURES:

    tr = train_x[feature].replace([np.inf, -np.inf], np.nan).dropna()
    va = val_x[feature].replace([np.inf, -np.inf], np.nan).dropna()
    te = test_x[feature].replace([np.inf, -np.inf], np.nan).dropna()

    tr_mean = tr.mean()
    va_mean = va.mean()
    te_mean = te.mean()

    tr_std = tr.std()
    va_std = va.std()
    te_std = te.std()

    tr_median = tr.median()
    va_median = va.median()
    te_median = te.median()

    tr_min = tr.min()
    va_min = va.min()
    te_min = te.min()

    tr_max = tr.max()
    va_max = va.max()
    te_max = te.max()

    # Difference in means relative to training scale
    train_scale = max(abs(tr_std), 1e-9)

    val_shift = abs(va_mean - tr_mean) / train_scale
    test_shift = abs(te_mean - tr_mean) / train_scale

    # Difference in standard deviation
    std_ratio_val = va_std / max(tr_std, 1e-9)
    std_ratio_test = te_std / max(tr_std, 1e-9)

    # Missingness
    train_missing = train_x[feature].isna().mean()
    val_missing = val_x[feature].isna().mean()
    test_missing = test_x[feature].isna().mean()

    rows.append({
        "feature": feature,

        "train_mean": tr_mean,
        "validation_mean": va_mean,
        "test_mean": te_mean,

        "train_std": tr_std,
        "validation_std": va_std,
        "test_std": te_std,

        "train_median": tr_median,
        "validation_median": va_median,
        "test_median": te_median,

        "train_min": tr_min,
        "validation_min": va_min,
        "test_min": te_min,

        "train_max": tr_max,
        "validation_max": va_max,
        "test_max": te_max,

        "validation_mean_shift_sigma": val_shift,
        "test_mean_shift_sigma": test_shift,

        "validation_std_ratio": std_ratio_val,
        "test_std_ratio": std_ratio_test,

        "train_missing_pct": train_missing * 100,
        "validation_missing_pct": val_missing * 100,
        "test_missing_pct": test_missing * 100
    })


report = pd.DataFrame(rows)


# ============================================================
# IDENTIFY LARGE SHIFTS
# ============================================================

report["shift_score"] = (
    report["test_mean_shift_sigma"]
    + abs(np.log(
        np.maximum(report["test_std_ratio"], 1e-9)
    ))
)


report = report.sort_values(
    "shift_score",
    ascending=False
)


# ============================================================
# SAVE REPORT
# ============================================================

output_path = os.path.join(
    REPORT_DIR,
    "tabular_distribution_shift_report.csv"
)

report.to_csv(
    output_path,
    index=False
)


# ============================================================
# PRINT TOP SHIFTED FEATURES
# ============================================================

print()
print("=" * 70)
print("TOP FEATURES WITH TRAIN → TEST DISTRIBUTION SHIFT")
print("=" * 70)

display_columns = [
    "feature",
    "train_mean",
    "test_mean",
    "train_std",
    "test_std",
    "test_mean_shift_sigma",
    "test_std_ratio"
]

print(
    report[display_columns]
    .head(15)
    .to_string(index=False)
)


# ============================================================
# STANDARDIZED DISTRIBUTION CHECK
# ============================================================

print()
print("=" * 70)
print("STANDARDIZED TEST VALUES")
print("=" * 70)

scaler = StandardScaler()

train_clean = train_x.replace(
    [np.inf, -np.inf],
    np.nan
).fillna(0)

test_clean = test_x.replace(
    [np.inf, -np.inf],
    np.nan
).fillna(0)

scaler.fit(train_clean)

train_scaled = scaler.transform(train_clean)
test_scaled = scaler.transform(test_clean)


train_abs = np.mean(
    np.abs(train_scaled),
    axis=0
)

test_abs = np.mean(
    np.abs(test_scaled),
    axis=0
)

z_rows = []

for i, feature in enumerate(FEATURES):

    z_rows.append({
        "feature": feature,
        "train_mean_abs_z": train_abs[i],
        "test_mean_abs_z": test_abs[i],
        "increase": test_abs[i] - train_abs[i]
    })


z_report = pd.DataFrame(z_rows)

z_report = z_report.sort_values(
    "increase",
    ascending=False
)


z_output = os.path.join(
    REPORT_DIR,
    "tabular_standardized_shift_report.csv"
)

z_report.to_csv(
    z_output,
    index=False
)


print(
    z_report.head(15).to_string(index=False)
)


# ============================================================
# CHECK EXTREME TEST VALUES
# ============================================================

print()
print("=" * 70)
print("EXTREME TEST FEATURES")
print("=" * 70)

extreme_rows = []

for i, feature in enumerate(FEATURES):

    values = test_scaled[:, i]

    extreme_3 = np.mean(np.abs(values) > 3) * 100
    extreme_5 = np.mean(np.abs(values) > 5) * 100
    extreme_10 = np.mean(np.abs(values) > 10) * 100

    extreme_rows.append({
        "feature": feature,
        "test_abs_z_gt_3_pct": extreme_3,
        "test_abs_z_gt_5_pct": extreme_5,
        "test_abs_z_gt_10_pct": extreme_10
    })


extreme_report = pd.DataFrame(extreme_rows)

extreme_report["severity"] = (
    extreme_report["test_abs_z_gt_10_pct"] * 10
    + extreme_report["test_abs_z_gt_5_pct"] * 3
    + extreme_report["test_abs_z_gt_3_pct"]
)

extreme_report = extreme_report.sort_values(
    "severity",
    ascending=False
)


extreme_output = os.path.join(
    REPORT_DIR,
    "tabular_extreme_test_features.csv"
)

extreme_report.to_csv(
    extreme_output,
    index=False
)


print(
    extreme_report.head(15).to_string(index=False)
)


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 70)
print("INVESTIGATION COMPLETE")
print("=" * 70)

print()
print("Reports created:")

print(
    os.path.join(
        REPORT_DIR,
        "tabular_distribution_shift_report.csv"
    )
)

print(
    os.path.join(
        REPORT_DIR,
        "tabular_standardized_shift_report.csv"
    )
)

print(
    os.path.join(
        REPORT_DIR,
        "tabular_extreme_test_features.csv"
    )
)

print()
print("IMPORTANT:")
print("Do NOT retrain the model yet.")
print("First inspect the top shifted features above.")

print("=" * 70)