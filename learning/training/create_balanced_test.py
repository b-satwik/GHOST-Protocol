import os
import pandas as pd

# ============================================================
# PATHS
# ============================================================

BASE_DIR = r"C:\Users\buyya\Desktop\darkwatch"

INPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "training",
    "text_test.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "training",
    "text_test_balanced.csv"
)

# Number of samples per class
SAMPLES_PER_CLASS = 30

# ============================================================
# LOAD
# ============================================================

print("=" * 60)
print("CREATING BALANCED TEXT TEST SET")
print("=" * 60)

df = pd.read_csv(INPUT_FILE)

print(f"\nOriginal test records: {len(df):,}")
print(f"Number of classes: {df['label_id'].nunique()}")

# ============================================================
# SHOW ORIGINAL DISTRIBUTION
# ============================================================

print("\nOriginal distribution:")

print(
    df["label_id"]
    .value_counts()
    .sort_index()
    .to_string()
)

# ============================================================
# BALANCE
# ============================================================

balanced_parts = []

for label_id, group in df.groupby("label_id"):

    count = len(group)

    if count >= SAMPLES_PER_CLASS:

        sample = group.sample(
            n=SAMPLES_PER_CLASS,
            random_state=42
        )

    else:

        # If a class has fewer than 30 examples,
        # keep all available examples.
        sample = group.copy()

    balanced_parts.append(sample)

balanced_df = pd.concat(
    balanced_parts,
    ignore_index=True
)

# Shuffle
balanced_df = balanced_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

# ============================================================
# SAVE
# ============================================================

balanced_df.to_csv(
    OUTPUT_FILE,
    index=False
)

# ============================================================
# RESULTS
# ============================================================

print("\n" + "=" * 60)
print("BALANCED TEST SET")
print("=" * 60)

print(
    balanced_df["label_id"]
    .value_counts()
    .sort_index()
    .to_string()
)

print("\nTotal records:", len(balanced_df))

print("\nSaved to:")
print(OUTPUT_FILE)

print("\nDone.")