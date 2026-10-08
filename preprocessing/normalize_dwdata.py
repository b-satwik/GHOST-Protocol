from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "DWData-master"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORT_DIR = PROJECT_ROOT / "reports"

OUTPUT_FILE = PROCESSED_DIR / "dwdata_optimized.csv"
NORMALIZATION_REPORT = REPORT_DIR / "dwdata_normalization_report.csv"
SCHEMA_REPORT = REPORT_DIR / "dwdata_schema_mapping.csv"
CATEGORY_REPORT = REPORT_DIR / "dwdata_category_report.csv"
INDICATOR_REPORT = REPORT_DIR / "dwdata_indicator_report.csv"


# ============================================================
# OUTPUT COLUMNS
# ============================================================

CANONICAL_COLUMNS = [
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
    "price_value",
    "currency",

    "rating",
    "vendor_rating",
    "reputation",

    "sales",
    "sold",
    "views",
    "in_stock",

    "onion_urls",
    "domains",
    "ip_addresses",
    "emails",
    "hashes",

    "has_vendor",
    "has_listing_name",
    "has_category",
    "has_price",
    "has_network_indicator",
    "has_any_indicator",

    "source_file",
    "record_id",
]


# ============================================================
# COLUMN ALIASES
# ============================================================

COLUMN_ALIASES = {
    "vendor": "vendor",
    "seller": "vendor",
    "username": "vendor",
    "user": "vendor",

    "price": "price",
    "cost": "price",
    "amount": "price",

    "category": "category",
    "categories": "category",
    "cat": "category",

    "name": "name",
    "product": "name",
    "product_name": "name",
    "listing": "name",
    "listing_name": "name",
    "title": "name",

    "rating": "rating",
    "ratings": "rating",
    "score": "rating",

    "vendor_rating": "vendor_rating",
    "seller_rating": "vendor_rating",

    "rep": "reputation",
    "reputation": "reputation",

    "sales": "sales",
    "sale": "sales",

    "sold": "sold",

    "views": "views",
    "view": "views",

    "in-stock": "in_stock",
    "in_stock": "in_stock",
    "instock": "in_stock",
    "stock": "in_stock",

    "marketplace": "marketplace",
    "market": "marketplace",

    "section": "section",
}


# ============================================================
# BASIC CLEANING
# ============================================================

INVALID_TEXT = {
    "",
    "nan",
    "none",
    "null",
    "n/a",
    "na",
}


def clean_text(value) -> str:

    if value is None:
        return ""

    text = str(value).strip()

    if text.lower() in INVALID_TEXT:
        return ""

    text = re.sub(r"\s+", " ", text)

    return text.strip()


def normalize_column_name(name: str) -> str:

    name = clean_text(name).lower()

    name = name.replace("-", "_")
    name = name.replace(" ", "_")
    name = name.replace("/", "_")

    return COLUMN_ALIASES.get(name, name)


# ============================================================
# DATE / MARKETPLACE
# ============================================================

def parse_snapshot_date(path: Path) -> str:

    for part in path.parts:

        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", part):
            return part

    match = re.search(
        r"\d{4}-\d{2}-\d{2}",
        path.name
    )

    return match.group(0) if match else ""


def infer_marketplace(path: Path) -> str:

    parts = [p.lower() for p in path.parts]

    marketplaces = [
        "darkmarket",
        "torrez",
        "whitehouse",
        "darkode",
        "tor2door",
        "bohemia",
        "nemesis",
        "royal",
        "vicecity",
        "asap",
        "kingdom",
        "mgmgrand",
        "alphabay",
        "abacus",
        "darkmatter",
        "drughub",
    ]

    for marketplace in marketplaces:

        for part in parts:

            if marketplace in part:
                return marketplace

    return ""


# ============================================================
# FILE HASH
# ============================================================

def file_md5(path: Path) -> str:

    h = hashlib.md5()

    with path.open("rb") as f:

        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            h.update(chunk)

    return h.hexdigest()


# ============================================================
# NUMBER PARSING
# ============================================================

def parse_number(value):

    text = clean_text(value)

    if not text:
        return None

    text = text.replace(",", "")

    match = re.search(
        r"(-?\d+(?:\.\d+)?)\s*([KMB])?",
        text,
        re.IGNORECASE,
    )

    if not match:
        return None

    try:
        number = float(match.group(1))
    except ValueError:
        return None

    suffix = (match.group(2) or "").upper()

    multiplier = {
        "K": 1_000,
        "M": 1_000_000,
        "B": 1_000_000_000,
    }.get(suffix, 1)

    return number * multiplier


# ============================================================
# PRICE
# ============================================================

CURRENCY_PATTERNS = [
    (r"\busd\b", "USD"),
    (r"\$", "USD"),
    (r"\beur\b", "EUR"),
    (r"€", "EUR"),
    (r"\bgbp\b", "GBP"),
    (r"£", "GBP"),
    (r"\baud\b", "AUD"),
    (r"\bcad\b", "CAD"),
    (r"\bbtc\b", "BTC"),
    (r"\bbitcoin\b", "BTC"),
    (r"\beth\b", "ETH"),
]


def parse_price(value) -> Tuple[Optional[float], str]:

    text = clean_text(value)

    if not text:
        return None, "UNKNOWN"

    currency = "UNKNOWN"

    for pattern, code in CURRENCY_PATTERNS:

        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE
        ):
            currency = code
            break

    if currency == "UNKNOWN":

        code = re.search(
            r"\b[A-Z]{3}\b",
            text.upper()
        )

        if code:
            currency = code.group(0)

    return parse_number(text), currency


# ============================================================
# CATEGORY
# ============================================================

def normalize_category(value) -> str:

    text = clean_text(value)

    if not text:
        return ""

    text = text.lower()

    text = text.replace("»", ">")

    text = re.sub(
        r"\s*>\s*",
        " > ",
        text
    )

    text = re.sub(
        r"\s*/\s*",
        " / ",
        text
    )

    text = re.sub(
        r"\s*&\s*",
        " & ",
        text
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


def split_category(category: str):

    if not category:
        return "", ""

    if ">" in category:

        parts = [
            p.strip()
            for p in category.split(">")
            if p.strip()
        ]

        if len(parts) >= 2:

            return (
                parts[0],
                " > ".join(parts[1:])
            )

    return category, ""


# ============================================================
# INDICATORS
# ============================================================

ONION_RE = re.compile(
    r"\b[a-zA-Z0-9]{16,56}\.onion\b",
    re.IGNORECASE
)

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9-]+\.)+"
    r"(?:com|net|org|info|biz|io|ru|cn|de|uk|co|me|xyz|top|site)\b",
    re.IGNORECASE
)

HASH_RE = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
    r"|\b[a-fA-F0-9]{40}\b"
    r"|\b[a-fA-F0-9]{64}\b"
)


def extract(regex, text):

    if not text:
        return ""

    values = regex.findall(text)

    values = list(
        dict.fromkeys(values)
    )

    return ";".join(values)


# ============================================================
# HEADER DETECTION
# ============================================================

def looks_like_header(row):

    known = {
        "vendor",
        "seller",
        "price",
        "category",
        "name",
        "product",
        "product_name",
        "listing",
        "rating",
        "ratings",
        "vendor_rating",
        "rep",
        "reputation",
        "sales",
        "sold",
        "views",
        "in_stock",
        "marketplace",
        "section",
    }

    normalized = {
        normalize_column_name(x)
        for x in row
    }

    return len(normalized & known) >= 2


# ============================================================
# READ CSV
# ============================================================

def read_rows(path: Path):

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
        newline=""
    ) as f:

        reader = csv.reader(
            f,
            delimiter=",",
            quotechar='"',
            skipinitialspace=True
        )

        rows = []

        for row in reader:

            if not row:
                continue

            if all(
                not clean_text(x)
                for x in row
            ):
                continue

            rows.append(row)

    return rows


# ============================================================
# DARKODE SPECIAL HANDLING
# ============================================================

def repair_darkode_row(row):

    """
    Darkode 2021-05-12 contains two observed schemas.

    Normal:
        vendor | category | name | price | ratings

    Shifted:
        vendor | rating | category | name

    Example:
        goldapple | 1 | digital | new mexico drivers license psd template

    The shifted form has no price.
    """

    if len(row) == 5:

        return {
            "vendor": row[0],
            "category": row[1],
            "name": row[2],
            "price": row[3],
            "rating": row[4],
        }, "darkode_5col"

    if len(row) == 4:

        # For this specific Darkode snapshot,
        # rows after the normal section use:
        #
        # vendor | rating | category | name

        return {
            "vendor": row[0],
            "rating": row[1],
            "category": row[2],
            "name": row[3],
            "price": "",
        }, "darkode_4col_shifted"

    return None, "darkode_invalid"


# ============================================================
# WHITEHOUSE / DARKMARKET / TORREZ SPECIAL HANDLING
# ============================================================

def repair_combined_row(row):

    """
    Observed schemas:

    6 columns:
        marketplace
        section
        vendor
        category
        name
        price

    7 columns:
        marketplace
        section
        vendor
        category
        name
        price
        rating
    """

    if len(row) == 6:

        return {
            "marketplace": row[0],
            "section": row[1],
            "vendor": row[2],
            "category": row[3],
            "name": row[4],
            "price": row[5],
        }, "combined_6col"

    if len(row) == 7:

        return {
            "marketplace": row[0],
            "section": row[1],
            "vendor": row[2],
            "category": row[3],
            "name": row[4],
            "price": row[5],
            "rating": row[6],
        }, "combined_7col"

    return None, "combined_invalid"


# ============================================================
# STANDARD RECORD
# ============================================================

def standardize(
    record: Dict,
    snapshot_date: str,
    path: Path
):

    vendor_raw = clean_text(
        record.get("vendor")
    )

    name_raw = clean_text(
        record.get("name")
    )

    category_raw = clean_text(
        record.get("category")
    )

    price_raw = clean_text(
        record.get("price")
    )

    vendor = vendor_raw

    listing_name = name_raw

    category_normalized = normalize_category(
        category_raw
    )

    parent, subcategory = split_category(
        category_normalized
    )

    price_value, currency = parse_price(
        price_raw
    )

    rating = parse_number(
        record.get("rating")
    )

    vendor_rating = parse_number(
        record.get("vendor_rating")
    )

    reputation = parse_number(
        record.get("reputation")
    )

    sales = parse_number(
        record.get("sales")
    )

    sold = parse_number(
        record.get("sold")
    )

    views = parse_number(
        record.get("views")
    )

    in_stock = parse_number(
        record.get("in_stock")
    )

    marketplace = clean_text(
        record.get("marketplace")
    ).lower()

    if not marketplace:

        marketplace = infer_marketplace(
            path
        )

    section = clean_text(
        record.get("section")
    ).lower()

    combined_text = " ".join(
        x for x in [
            vendor,
            listing_name,
            category_normalized,
        ]
        if x
    )

    onion_urls = extract(
        ONION_RE,
        combined_text
    )

    domains = extract(
        DOMAIN_RE,
        combined_text
    )

    ip_addresses = extract(
        IP_RE,
        combined_text
    )

    emails = extract(
        EMAIL_RE,
        combined_text
    )

    hashes = extract(
        HASH_RE,
        combined_text
    )

    # --------------------------------------------------------
    # Stable record fingerprint
    # --------------------------------------------------------

    fingerprint = "|".join([
        snapshot_date,
        marketplace,
        section,
        vendor.lower(),
        listing_name.lower(),
        category_normalized,
        str(price_value),
        currency,
    ])

    record_id = hashlib.sha256(
        fingerprint.encode("utf-8")
    ).hexdigest()

    return {
        "snapshot_date": snapshot_date,
        "marketplace": marketplace,
        "section": section,

        "vendor_raw": vendor_raw,
        "vendor": vendor,

        "listing_name_raw": name_raw,
        "listing_name": listing_name,

        "category_raw": category_raw,
        "category_normalized": category_normalized,
        "category_parent": parent,
        "category_subcategory": subcategory,

        "price_raw": price_raw,
        "price_value": price_value,
        "currency": currency,

        "rating": rating,
        "vendor_rating": vendor_rating,
        "reputation": reputation,

        "sales": sales,
        "sold": sold,
        "views": views,
        "in_stock": in_stock,

        "onion_urls": onion_urls,
        "domains": domains,
        "ip_addresses": ip_addresses,
        "emails": emails,
        "hashes": hashes,

        "has_vendor": int(bool(vendor)),
        "has_listing_name": int(bool(listing_name)),
        "has_category": int(bool(category_normalized)),
        "has_price": int(price_value is not None),

        "has_network_indicator": int(
            bool(
                onion_urls
                or domains
                or ip_addresses
            )
        ),

        "has_any_indicator": int(
            bool(
                onion_urls
                or domains
                or ip_addresses
                or emails
                or hashes
            )
        ),

        "source_file": str(
            path.relative_to(PROJECT_ROOT)
        ),

        "record_id": record_id,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("DarkWatch-XAI | DWData Research Normalization")
    print("=" * 70)

    if not RAW_DIR.exists():

        raise FileNotFoundError(
            f"Dataset not found:\n{RAW_DIR}"
        )

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    files = sorted(
        RAW_DIR.rglob("*.csv")
    )

    print(
        f"\nCSV files discovered: {len(files)}"
    )

    records = []

    schema_logs = []

    stats = Counter()

    category_counter = Counter()
    indicator_counter = Counter()

    seen_hashes = {}

    # ========================================================
    # FILE LOOP
    # ========================================================

    for index, path in enumerate(
        files,
        start=1
    ):

        relative = path.relative_to(
            PROJECT_ROOT
        )

        print(
            f"[{index:>3}/{len(files)}] "
            f"{relative}"
        )

        stats["files_discovered"] += 1

        # ----------------------------------------------------
        # File duplicate detection
        # ----------------------------------------------------

        try:

            md5 = file_md5(path)

        except Exception as e:

            stats["file_errors"] += 1

            continue

        if md5 in seen_hashes:

            stats["duplicate_files"] += 1

            schema_logs.append({
                "file": str(relative),
                "status": "duplicate_file",
                "duplicate_of": seen_hashes[md5],
                "md5": md5,
            })

            continue

        seen_hashes[md5] = str(relative)

        # ----------------------------------------------------
        # Read
        # ----------------------------------------------------

        try:

            rows = read_rows(path)

        except Exception as e:

            stats["read_errors"] += 1

            schema_logs.append({
                "file": str(relative),
                "status": "read_error",
                "error": str(e),
            })

            continue

        if not rows:

            stats["empty_files"] += 1

            schema_logs.append({
                "file": str(relative),
                "status": "empty",
            })

            continue

        snapshot_date = parse_snapshot_date(
            path
        )

        filename = path.name.lower()

        # ====================================================
        # SPECIAL DARKODE FILE
        # ====================================================

        is_darkode_special = (
            "darkode-2021-05-12" in filename
        )

        # ====================================================
        # SPECIAL COMBINED FILE
        # ====================================================

        is_combined_special = (
            "whitehouse_darkmarket_torrez"
            in filename
        )

        # ====================================================
        # STANDARD HEADER
        # ====================================================

        first_row = rows[0]

        if (
            not is_darkode_special
            and not is_combined_special
            and looks_like_header(first_row)
        ):

            header = [
                normalize_column_name(x)
                for x in first_row
            ]

            data_rows = rows[1:]

            schema_type = "header_detected"

        elif is_darkode_special:

            header = None
            data_rows = rows

            schema_type = "darkode_special"

        elif is_combined_special:

            header = None
            data_rows = rows

            schema_type = "combined_marketplace_special"

        else:

            # ------------------------------------------------
            # Headerless inference
            # ------------------------------------------------

            width = len(first_row)

            data_rows = rows

            if width == 4:

                header = [
                    "vendor",
                    "category",
                    "name",
                    "price",
                ]

                schema_type = (
                    "inferred_4col"
                )

            elif width == 5:

                header = [
                    "vendor",
                    "price",
                    "category",
                    "name",
                    "rating",
                ]

                schema_type = (
                    "inferred_5col"
                )

            else:

                header = [
                    f"unknown_{i}"
                    for i in range(width)
                ]

                schema_type = (
                    f"unknown_{width}col"
                )

        schema_logs.append({
            "file": str(relative),
            "status": "processed",
            "schema_type": schema_type,
            "snapshot_date": snapshot_date,
            "column_count": (
                len(header)
                if header
                else "special"
            ),
            "columns": (
                "|".join(header)
                if header
                else ""
            ),
        })

        # ====================================================
        # ROW PROCESSING
        # ====================================================

        for line_number, row in enumerate(
            data_rows,
            start=2
        ):

            record = None
            row_schema = schema_type

            # ------------------------------------------------
            # Darkode
            # ------------------------------------------------

            if is_darkode_special:

                record, row_schema = (
                    repair_darkode_row(row)
                )

            # ------------------------------------------------
            # Combined marketplace
            # ------------------------------------------------

            elif is_combined_special:

                record, row_schema = (
                    repair_combined_row(row)
                )

            # ------------------------------------------------
            # Standard schemas
            # ------------------------------------------------

            else:

                expected = len(header)

                if len(row) != expected:

                    stats["malformed_rows"] += 1

                    continue

                record = dict(
                    zip(header, row)
                )

            if record is None:

                stats["malformed_rows"] += 1

                continue

            stats["rows_recovered"] += 1

            standardized = standardize(
                record,
                snapshot_date,
                path
            )

            # ------------------------------------------------
            # Ignore genuinely empty records
            # ------------------------------------------------

            if not (
                standardized["vendor"]
                or standardized["listing_name"]
                or standardized["category_normalized"]
            ):

                stats["empty_records"] += 1

                continue

            records.append(
                standardized
            )

            category_counter[
                standardized[
                    "category_normalized"
                ]
            ] += 1

            if standardized["onion_urls"]:
                indicator_counter[
                    "onion_urls"
                ] += 1

            if standardized["domains"]:
                indicator_counter[
                    "domains"
                ] += 1

            if standardized["ip_addresses"]:
                indicator_counter[
                    "ip_addresses"
                ] += 1

            if standardized["emails"]:
                indicator_counter[
                    "emails"
                ] += 1

            if standardized["hashes"]:
                indicator_counter[
                    "hashes"
                ] += 1

    # ========================================================
    # DATAFRAME
    # ========================================================

    print("\nBuilding optimized dataset...")

    df = pd.DataFrame(records)

    for col in CANONICAL_COLUMNS:

        if col not in df.columns:
            df[col] = ""

    df = df[
        CANONICAL_COLUMNS
    ]

    # ========================================================
    # DEDUPLICATION
    # ========================================================

    before = len(df)

    df = df.drop_duplicates(
        subset=[
            "snapshot_date",
            "marketplace",
            "section",
            "vendor",
            "listing_name",
            "category_normalized",
            "price_value",
            "currency",
        ],
        keep="first",
    )

    stats["duplicate_rows_removed"] = (
        before - len(df)
    )

    # ========================================================
    # TEMPORAL SORT
    # ========================================================

    df["_date"] = pd.to_datetime(
        df["snapshot_date"],
        errors="coerce"
    )

    df = df.sort_values(
        [
            "_date",
            "marketplace",
            "vendor",
            "listing_name",
        ],
        na_position="last"
    )

    df.drop(
        columns=["_date"],
        inplace=True
    )

    df.reset_index(
        drop=True,
        inplace=True
    )

    # ========================================================
    # TYPES
    # ========================================================

    numeric_columns = [
        "price_value",
        "rating",
        "vendor_rating",
        "reputation",
        "sales",
        "sold",
        "views",
        "in_stock",
    ]

    for col in numeric_columns:

        df[col] = pd.to_numeric(
            df[col],
            errors="coerce"
        )

    # ========================================================
    # SAVE
    # ========================================================

    df.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8"
    )

    # ========================================================
    # REPORT
    # ========================================================

    stats["output_rows"] = len(df)

    report = pd.DataFrame(
        [
            {
                "metric": k,
                "value": v
            }
            for k, v in sorted(
                stats.items()
            )
        ]
    )

    report.loc[len(report)] = [
        "unique_vendors",
        df["vendor"].replace(
            "", pd.NA
        ).nunique()
    ]

    report.loc[len(report)] = [
        "unique_marketplaces",
        df["marketplace"].replace(
            "", pd.NA
        ).nunique()
    ]

    report.loc[len(report)] = [
        "unique_categories",
        df["category_normalized"].replace(
            "", pd.NA
        ).nunique()
    ]

    report.loc[len(report)] = [
        "unique_listings",
        df["listing_name"].replace(
            "", pd.NA
        ).nunique()
    ]

    report.loc[len(report)] = [
        "snapshot_dates",
        df["snapshot_date"].replace(
            "", pd.NA
        ).nunique()
    ]

    report.to_csv(
        NORMALIZATION_REPORT,
        index=False
    )

    # ========================================================
    # SCHEMA REPORT
    # ========================================================

    pd.DataFrame(
        schema_logs
    ).to_csv(
        SCHEMA_REPORT,
        index=False
    )

    # ========================================================
    # CATEGORY REPORT
    # ========================================================

    pd.DataFrame(
        category_counter.items(),
        columns=[
            "category_normalized",
            "record_count",
        ],
    ).sort_values(
        "record_count",
        ascending=False
    ).to_csv(
        CATEGORY_REPORT,
        index=False
    )

    # ========================================================
    # INDICATOR REPORT
    # ========================================================

    pd.DataFrame(
        indicator_counter.items(),
        columns=[
            "indicator_type",
            "record_count",
        ],
    ).to_csv(
        INDICATOR_REPORT,
        index=False
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    print("\n" + "=" * 70)
    print("NORMALIZATION COMPLETE")
    print("=" * 70)

    print(
        f"\nFiles discovered       : "
        f"{stats['files_discovered']:,}"
    )

    print(
        f"Duplicate files        : "
        f"{stats['duplicate_files']:,}"
    )

    print(
        f"Rows recovered         : "
        f"{stats['rows_recovered']:,}"
    )

    print(
        f"Malformed rows         : "
        f"{stats['malformed_rows']:,}"
    )

    print(
        f"Duplicate rows removed : "
        f"{stats['duplicate_rows_removed']:,}"
    )

    print(
        f"Final records          : "
        f"{len(df):,}"
    )

    print(
        f"Vendors                : "
        f"{df['vendor'].replace('', pd.NA).nunique():,}"
    )

    print(
        f"Marketplaces           : "
        f"{df['marketplace'].replace('', pd.NA).nunique():,}"
    )

    print(
        f"Categories             : "
        f"{df['category_normalized'].replace('', pd.NA).nunique():,}"
    )

    print(
        f"Listings               : "
        f"{df['listing_name'].replace('', pd.NA).nunique():,}"
    )

    print(
        f"Snapshot dates         : "
        f"{df['snapshot_date'].replace('', pd.NA).nunique():,}"
    )

    print("\nOutput:")
    print(OUTPUT_FILE)

    print("\nReports:")
    print(NORMALIZATION_REPORT)
    print(SCHEMA_REPORT)
    print(CATEGORY_REPORT)
    print(INDICATOR_REPORT)

    print("=" * 70)


if __name__ == "__main__":
    main()