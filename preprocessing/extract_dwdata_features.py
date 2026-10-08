"""
DarkWatch-XAI
DWData Feature Extraction

Input:
    data/processed/dwdata_optimized.csv

Output:
    data/processed/dwdata_features.csv

Purpose:
    Add structured, behavioral, temporal, text, price, and
    network-indicator features without modifying the normalized dataset.
"""

from pathlib import Path
import re

import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parents[1]

INPUT_PATH = PROJECT_DIR / "data" / "processed" / "dwdata_optimized.csv"
OUTPUT_PATH = PROJECT_DIR / "data" / "processed" / "dwdata_features.csv"

REPORT_DIR = PROJECT_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_REPORT = REPORT_DIR / "dwdata_feature_report.csv"


# ============================================================
# KEYWORD GROUPS
# These are descriptive features, NOT labels.
# ============================================================

CRYPTO_TERMS = {
    "bitcoin",
    "btc",
    "monero",
    "xmr",
    "ethereum",
    "eth",
    "crypto",
    "cryptocurrency",
}

MALWARE_TERMS = {
    "malware",
    "ransomware",
    "trojan",
    "rat",
    "botnet",
    "stealer",
    "keylogger",
    "spyware",
    "rootkit",
    "backdoor",
    "worm",
}

CREDENTIAL_TERMS = {
    "credential",
    "credentials",
    "password",
    "passwords",
    "login",
    "logins",
    "account",
    "accounts",
    "cookie",
    "cookies",
    "token",
    "tokens",
    "ssn",
    "fullz",
}

EXPLOIT_TERMS = {
    "exploit",
    "exploits",
    "vulnerability",
    "vulnerabilities",
    "zero-day",
    "0day",
    "payload",
    "rce",
    "lfi",
    "rfi",
    "sql injection",
    "xss",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_text(value):
    """Convert a value to clean text."""
    if pd.isna(value):
        return ""
    return str(value).strip()


def contains_any_term(text, terms):
    """Return 1 if any keyword occurs in the text."""
    text = safe_text(text).lower()

    if not text:
        return 0

    for term in terms:
        if term in text:
            return 1

    return 0


def count_indicator_field(value):
    """
    Count indicators stored inside a field.

    Handles empty values and common separators.
    """
    if pd.isna(value):
        return 0

    value = str(value).strip()

    if not value:
        return 0

    parts = re.split(r"[;,|]\s*", value)

    parts = [
        part.strip()
        for part in parts
        if part.strip()
    ]

    return len(parts)


def safe_log1p(value):
    """Apply log1p safely to numeric price values."""
    if pd.isna(value):
        return np.nan

    try:
        value = float(value)

        if value < 0:
            return np.nan

        return np.log1p(value)

    except (TypeError, ValueError):
        return np.nan


# ============================================================
# START
# ============================================================

print("=" * 70)
print("DarkWatch-XAI - DWData Feature Extraction")
print("=" * 70)


# ============================================================
# CHECK INPUT
# ============================================================

if not INPUT_PATH.exists():
    raise FileNotFoundError(
        f"\nInput dataset not found:\n{INPUT_PATH}\n\n"
        "Make sure dwdata_optimized.csv exists."
    )


print(f"\nInput : {INPUT_PATH}")
print("Loading dataset...")


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv(
    INPUT_PATH,
    low_memory=False,
)

print(f"Rows loaded    : {len(df):,}")
print(f"Columns loaded : {len(df.columns)}")


# ============================================================
# COPY DATA
# Original normalized dataset remains untouched.
# ============================================================

features = df.copy()


# ============================================================
# 1. TEMPORAL FEATURES
# ============================================================

print("\n[1/7] Extracting temporal features...")


features["snapshot_date_dt"] = pd.to_datetime(
    features["snapshot_date"],
    errors="coerce",
)


features["snapshot_year"] = (
    features["snapshot_date_dt"]
    .dt.year
)


features["snapshot_month"] = (
    features["snapshot_date_dt"]
    .dt.month
)


features["snapshot_quarter"] = (
    features["snapshot_date_dt"]
    .dt.quarter
)


features["snapshot_day_of_month"] = (
    features["snapshot_date_dt"]
    .dt.day
)


features["snapshot_day_of_week"] = (
    features["snapshot_date_dt"]
    .dt.dayofweek
)


features["snapshot_is_weekend"] = (
    features["snapshot_day_of_week"]
    .isin([5, 6])
    .astype("int8")
)


first_date = features["snapshot_date_dt"].min()


features["days_since_first_snapshot"] = (
    features["snapshot_date_dt"] - first_date
).dt.days


# ============================================================
# 2. TEXT FEATURES
# ============================================================

print("[2/7] Extracting text features...")


text = (
    features["listing_name"]
    .fillna("")
    .astype(str)
)


features["text_char_count"] = (
    text.str.len()
    .astype("int32")
)


features["text_word_count"] = (
    text.str.findall(r"\b\w+\b")
    .str.len()
    .astype("int32")
)


features["text_unique_word_count"] = (
    text.str.lower()
    .str.findall(r"\b\w+\b")
    .apply(lambda words: len(set(words)))
    .astype("int32")
)


features["text_avg_word_length"] = (
    features["text_char_count"]
    /
    features["text_word_count"].replace(0, np.nan)
)


features["text_digit_count"] = (
    text.str.count(r"\d")
    .astype("int32")
)


features["text_digit_ratio"] = (
    features["text_digit_count"]
    /
    features["text_char_count"].replace(0, np.nan)
)


features["text_uppercase_count"] = (
    text.str.count(r"[A-Z]")
    .astype("int32")
)


features["text_uppercase_ratio"] = (
    features["text_uppercase_count"]
    /
    features["text_char_count"].replace(0, np.nan)
)


features["text_special_char_count"] = (
    text.str.count(r"[^A-Za-z0-9\s]")
    .astype("int32")
)


features["text_special_char_ratio"] = (
    features["text_special_char_count"]
    /
    features["text_char_count"].replace(0, np.nan)
)


features["text_has_url"] = (
    text.str.contains(
        r"https?://|www\.",
        case=False,
        regex=True,
        na=False,
    )
    .astype("int8")
)


features["text_has_email"] = (
    text.str.contains(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        case=False,
        regex=True,
        na=False,
    )
    .astype("int8")
)


features["text_has_ip"] = (
    text.str.contains(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        regex=True,
        na=False,
    )
    .astype("int8")
)


features["text_has_crypto_term"] = (
    text.apply(
        lambda x: contains_any_term(
            x,
            CRYPTO_TERMS
        )
    )
    .astype("int8")
)


features["text_has_malware_term"] = (
    text.apply(
        lambda x: contains_any_term(
            x,
            MALWARE_TERMS
        )
    )
    .astype("int8")
)


features["text_has_credential_term"] = (
    text.apply(
        lambda x: contains_any_term(
            x,
            CREDENTIAL_TERMS
        )
    )
    .astype("int8")
)


features["text_has_exploit_term"] = (
    text.apply(
        lambda x: contains_any_term(
            x,
            EXPLOIT_TERMS
        )
    )
    .astype("int8")
)


# ============================================================
# 3. CATEGORY FEATURES
# ============================================================

print("[3/7] Extracting category features...")


features["category_parent_present"] = (
    features["category_parent"]
    .fillna("")
    .astype(str)
    .str.strip()
    .ne("")
    .astype("int8")
)


features["category_subcategory_present"] = (
    features["category_subcategory"]
    .fillna("")
    .astype(str)
    .str.strip()
    .ne("")
    .astype("int8")
)


category_frequency = (
    features["category_normalized"]
    .fillna("UNKNOWN_CATEGORY")
    .value_counts()
)


features["category_frequency"] = (
    features["category_normalized"]
    .fillna("UNKNOWN_CATEGORY")
    .map(category_frequency)
    .fillna(0)
    .astype("int32")
)


# ============================================================
# 4. SELLER / MARKETPLACE FEATURES
# ============================================================

print("[4/7] Extracting seller and marketplace features...")


# ------------------------------------------------------------
# Vendor statistics
# ------------------------------------------------------------

features["vendor_listing_count"] = (
    features
    .groupby("vendor", dropna=False)["record_id"]
    .transform("size")
    .fillna(0)
    .astype("int32")
)


features["vendor_category_count"] = (
    features
    .groupby("vendor", dropna=False)["category_normalized"]
    .transform("nunique")
    .fillna(0)
    .astype("int16")
)


features["vendor_marketplace_count"] = (
    features
    .groupby("vendor", dropna=False)["marketplace"]
    .transform("nunique")
    .fillna(0)
    .astype("int16")
)


features["vendor_activity_days"] = (
    features
    .groupby("vendor", dropna=False)["snapshot_date_dt"]
    .transform("nunique")
    .fillna(0)
    .astype("int16")
)


# ------------------------------------------------------------
# Marketplace statistics
#
# dropna=False is important because 7,071 rows have
# missing marketplace values.
# ------------------------------------------------------------

features["marketplace_listing_count"] = (
    features
    .groupby("marketplace", dropna=False)["record_id"]
    .transform("size")
    .fillna(0)
    .astype("int32")
)


features["marketplace_vendor_count"] = (
    features
    .groupby("marketplace", dropna=False)["vendor"]
    .transform("nunique")
    .fillna(0)
    .astype("int32")
)


# ============================================================
# 5. PRICE FEATURES
# ============================================================

print("[5/7] Extracting price features...")


features["has_numeric_price"] = (
    features["price_value"]
    .notna()
    .astype("int8")
)


features["price_log1p"] = (
    features["price_value"]
    .apply(safe_log1p)
)


features["price_text_length"] = (
    features["price_raw"]
    .fillna("")
    .astype(str)
    .str.len()
    .astype("int16")
)


known_currencies = {
    "USD",
    "EUR",
    "GBP",
    "CAD",
    "AUD",
    "JPY",
}


features["currency_known"] = (
    features["currency"]
    .fillna("")
    .astype(str)
    .str.upper()
    .isin(known_currencies)
    .astype("int8")
)


crypto_currencies = {
    "BTC",
    "XMR",
    "ETH",
    "LTC",
    "BCH",
}


features["is_crypto_currency"] = (
    features["currency"]
    .fillna("")
    .astype(str)
    .str.upper()
    .isin(crypto_currencies)
    .astype("int8")
)


features["price_is_zero"] = (
    features["price_value"]
    .fillna(-1)
    .eq(0)
    .astype("int8")
)


# ============================================================
# 6. NETWORK / INDICATOR FEATURES
# ============================================================

print("[6/7] Extracting network indicator features...")


features["onion_count"] = (
    features["onion_urls"]
    .apply(count_indicator_field)
    .astype("int16")
)


features["domain_count"] = (
    features["domains"]
    .apply(count_indicator_field)
    .astype("int16")
)


features["ip_count"] = (
    features["ip_addresses"]
    .apply(count_indicator_field)
    .astype("int16")
)


features["email_count"] = (
    features["emails"]
    .apply(count_indicator_field)
    .astype("int16")
)


features["hash_count"] = (
    features["hashes"]
    .apply(count_indicator_field)
    .astype("int16")
)


features["has_domain"] = (
    features["domain_count"] > 0
).astype("int8")


features["has_ip"] = (
    features["ip_count"] > 0
).astype("int8")


features["has_email"] = (
    features["email_count"] > 0
).astype("int8")


features["has_onion"] = (
    features["onion_count"] > 0
).astype("int8")


features["has_hash"] = (
    features["hash_count"] > 0
).astype("int8")


features["total_indicator_count"] = (
    features[
        [
            "onion_count",
            "domain_count",
            "ip_count",
            "email_count",
            "hash_count",
        ]
    ]
    .sum(axis=1)
    .astype("int16")
)


features["network_indicator_density"] = (
    features["total_indicator_count"]
    /
    features["text_word_count"].replace(0, np.nan)
)


# ============================================================
# 7. SELLER TEMPORAL FEATURES
# ============================================================

print("[7/7] Extracting temporal seller behavior...")


features = features.sort_values(
    [
        "vendor",
        "snapshot_date_dt",
        "record_id",
    ]
).reset_index(drop=True)


features["vendor_observation_number"] = (
    features
    .groupby("vendor", dropna=False)
    .cumcount()
    .add(1)
    .astype("int32")
)


features["vendor_previous_observation_gap"] = (
    features
    .groupby("vendor", dropna=False)["snapshot_date_dt"]
    .diff()
    .dt.days
)


# Restore chronological ordering.

features = features.sort_values(
    [
        "snapshot_date_dt",
        "marketplace",
        "vendor",
        "record_id",
    ]
).reset_index(drop=True)


# ============================================================
# REMOVE INTERNAL DATETIME COLUMN
# ============================================================

features.drop(
    columns=["snapshot_date_dt"],
    inplace=True,
)


# ============================================================
# CLEAN INF VALUES
# ============================================================

features.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True,
)


# ============================================================
# SAVE FEATURE DATASET
# ============================================================

print("\nSaving feature dataset...")


features.to_csv(
    OUTPUT_PATH,
    index=False,
)


# ============================================================
# FEATURE REPORT
# ============================================================

original_columns = set(df.columns)


new_features = [
    column
    for column in features.columns
    if column not in original_columns
]


report_rows = []


for column in new_features:

    series = features[column]

    report_rows.append(
        {
            "feature": column,
            "dtype": str(series.dtype),
            "missing": int(series.isna().sum()),
            "missing_percentage": round(
                series.isna().mean() * 100,
                4,
            ),
            "unique_values": int(
                series.nunique(
                    dropna=True
                )
            ),
        }
    )


feature_report = pd.DataFrame(
    report_rows
)


feature_report.to_csv(
    FEATURE_REPORT,
    index=False,
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("FEATURE EXTRACTION COMPLETE")
print("=" * 70)

print(
    f"Input records       : {len(df):,}"
)

print(
    f"Output records      : {len(features):,}"
)

print(
    f"Original columns    : {len(original_columns)}"
)

print(
    f"New features        : {len(new_features)}"
)

print(
    f"Final columns       : {len(features.columns)}"
)

print("\nOutput:")
print(OUTPUT_PATH)

print("\nFeature report:")
print(FEATURE_REPORT)

print("\nNew features:")

for feature in new_features:
    print(f"  - {feature}")

print("=" * 70)