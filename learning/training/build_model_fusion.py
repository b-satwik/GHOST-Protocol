import os
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib

from torch.utils.data import DataLoader, TensorDataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification


# ============================================================
# CONFIG
# ============================================================

PROJECT_DIR = r"C:\Users\buyya\Desktop\darkwatch"

DATA_DIR = os.path.join(
    PROJECT_DIR, "data", "processed", "training"
)

REPORT_DIR = os.path.join(
    PROJECT_DIR, "reports", "training"
)

TABULAR_DIR = os.path.join(
    PROJECT_DIR, "models", "dwdata_tabular_model"
)

TEMPORAL_DIR = os.path.join(
    PROJECT_DIR, "models", "dwdata_temporal_model"
)

TEXT_DIR = os.path.join(
    PROJECT_DIR, "models", "dwdata_text_model"
)


# ============================================================
# FILES
# ============================================================

TABULAR_TEST = os.path.join(
    DATA_DIR, "tabular_test.csv"
)

TABULAR_MODEL = os.path.join(
    TABULAR_DIR, "model.pt"
)

TABULAR_FEATURES = os.path.join(
    TABULAR_DIR, "features.json"
)

TABULAR_SCALER = os.path.join(
    TABULAR_DIR, "scaler.joblib"
)

TEMPORAL_TEST = os.path.join(
    DATA_DIR, "temporal_test.csv"
)

TEMPORAL_MODEL = os.path.join(
    TEMPORAL_DIR, "temporal_autoencoder.pt"
)

TEMPORAL_FEATURES = os.path.join(
    TEMPORAL_DIR, "temporal_features.json"
)

TEMPORAL_SCALER = os.path.join(
    TEMPORAL_DIR, "temporal_scaler.npz"
)

TEXT_TEST = os.path.join(
    DATA_DIR, "text_test.csv"
)

TEXT_LABEL_MAP = os.path.join(
    DATA_DIR, "text_label_map.json"
)

TEXT_MODEL = TEXT_DIR

TEMPORAL_SCORES = os.path.join(
    REPORT_DIR,
    "temporal_test_scores.csv"
)

OUTPUT_FILE = os.path.join(
    REPORT_DIR,
    "model_fusion_test.csv"
)

SUMMARY_FILE = os.path.join(
    REPORT_DIR,
    "model_fusion_summary.json"
)


# ============================================================
# DEVICE
# ============================================================

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

print("=" * 70)
print("DARKWATCH-XAI MODEL FUSION")
print("=" * 70)

print(f"\nDevice: {DEVICE}")


# ============================================================
# VERIFY FILES
# ============================================================

required_files = [
    TABULAR_TEST,
    TABULAR_MODEL,
    TABULAR_FEATURES,
    TABULAR_SCALER,
    TEMPORAL_TEST,
    TEMPORAL_MODEL,
    TEMPORAL_FEATURES,
    TEMPORAL_SCALER,
    TEXT_TEST,
    TEXT_LABEL_MAP,
]

for path in required_files:

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"\nRequired file does not exist:\n{path}"
        )

print("\nAll required files found.")


# ============================================================
# AUTOENCODER
# ============================================================

class Autoencoder(nn.Module):

    def __init__(
        self,
        input_dim,
        hidden1,
        hidden2,
        latent_dim
    ):

        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden1),
            nn.ReLU(),
            nn.Linear(hidden1, hidden2),
            nn.ReLU(),
            nn.Linear(hidden2, latent_dim)
        )

        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden2),
            nn.ReLU(),
            nn.Linear(hidden2, hidden1),
            nn.ReLU(),
            nn.Linear(hidden1, input_dim)
        )

    def forward(self, x):

        latent = self.encoder(x)

        reconstructed = self.decoder(latent)

        return reconstructed, latent


# ============================================================
# LOAD SAVED AUTOENCODER
# ============================================================

def load_autoencoder(model_path):

    checkpoint = torch.load(
        model_path,
        map_location=DEVICE,
        weights_only=False
    )

    if not isinstance(checkpoint, dict):

        raise ValueError(
            f"Unexpected checkpoint format:\n{model_path}"
        )

    state = checkpoint["model_state_dict"]

    input_dim = int(
        checkpoint["input_dim"]
    )

    hidden1 = (
        state["encoder.0.weight"].shape[0]
    )

    hidden2 = (
        state["encoder.2.weight"].shape[0]
    )

    latent_dim = (
        state["encoder.4.weight"].shape[0]
    )

    model = Autoencoder(
        input_dim=input_dim,
        hidden1=hidden1,
        hidden2=hidden2,
        latent_dim=latent_dim
    )

    model.load_state_dict(state)

    model.to(DEVICE)
    model.eval()

    print(
        f"Loaded model: "
        f"input={input_dim}, "
        f"hidden1={hidden1}, "
        f"hidden2={hidden2}, "
        f"latent={latent_dim}"
    )

    return model, checkpoint


# ============================================================
# 1. BEHAVIORAL MODEL
# ============================================================

print("\n" + "=" * 70)
print("1. BEHAVIORAL MODEL")
print("=" * 70)

tabular_df = pd.read_csv(
    TABULAR_TEST
)

with open(
    TABULAR_FEATURES,
    "r",
    encoding="utf-8"
) as f:

    tabular_meta = json.load(f)

behavioral_features = (
    tabular_meta["behavioral_features"]
)

print(
    f"Test records: {len(tabular_df):,}"
)

print(
    f"Behavioral features: "
    f"{len(behavioral_features)}"
)

missing = [
    feature
    for feature in behavioral_features
    if feature not in tabular_df.columns
]

if missing:

    raise ValueError(
        "Missing behavioral features:\n"
        + "\n".join(missing)
    )

tabular_scaler = joblib.load(
    TABULAR_SCALER
)

X_tabular = (
    tabular_df[
        behavioral_features
    ]
    .replace(
        [np.inf, -np.inf],
        np.nan
    )
    .fillna(0)
)

X_tabular_scaled = (
    tabular_scaler
    .transform(X_tabular)
    .astype(np.float32)
)

tabular_model, tabular_checkpoint = (
    load_autoencoder(
        TABULAR_MODEL
    )
)

saved_input_dim = int(
    tabular_checkpoint["input_dim"]
)

if saved_input_dim != len(
    behavioral_features
):

    raise ValueError(
        "\nTabular feature/model mismatch.\n"
        f"Model input dimension: "
        f"{saved_input_dim}\n"
        f"Behavioral features: "
        f"{len(behavioral_features)}"
    )

tabular_tensor = torch.tensor(
    X_tabular_scaled,
    dtype=torch.float32
)

tabular_loader = DataLoader(
    TensorDataset(tabular_tensor),
    batch_size=512,
    shuffle=False
)

behavioral_errors = []

with torch.no_grad():

    for batch in tabular_loader:

        x = batch[0].to(DEVICE)

        reconstructed, _ = (
            tabular_model(x)
        )

        error = torch.mean(
            (reconstructed - x) ** 2,
            dim=1
        )

        behavioral_errors.extend(
            error.cpu().numpy()
        )

behavioral_errors = np.asarray(
    behavioral_errors
)

print(
    f"Behavioral scores: "
    f"{len(behavioral_errors):,}"
)


# ============================================================
# 2. TEMPORAL MODEL
# ============================================================

print("\n" + "=" * 70)
print("2. TEMPORAL MODEL")
print("=" * 70)

temporal_df = pd.read_csv(
    TEMPORAL_TEST
)

with open(
    TEMPORAL_FEATURES,
    "r",
    encoding="utf-8"
) as f:

    temporal_features = json.load(f)

print(
    f"Temporal records: "
    f"{len(temporal_df):,}"
)

print(
    f"Temporal features: "
    f"{len(temporal_features)}"
)

if os.path.exists(
    TEMPORAL_SCORES
):

    print(
        "\nLoading existing temporal scores..."
    )

    temporal_scores_df = pd.read_csv(
        TEMPORAL_SCORES
    )

    possible_columns = [
        "temporal_reconstruction_error",
        "reconstruction_error",
        "error"
    ]

    temporal_column = None

    for column in possible_columns:

        if column in temporal_scores_df.columns:

            temporal_column = column
            break

    if temporal_column is None:

        raise ValueError(
            "Temporal reconstruction "
            "error column not found.\n"
            f"Available columns: "
            f"{list(temporal_scores_df.columns)}"
        )

    temporal_errors = (
        temporal_scores_df[
            temporal_column
        ]
        .astype(float)
        .values
    )

else:

    print(
        "\nTemporal score file not found."
    )

    print(
        "Calculating temporal scores..."
    )

    temporal_scaler_data = np.load(
        TEMPORAL_SCALER
    )

    temporal_mean = (
        temporal_scaler_data["mean"]
    )

    temporal_scale = (
        temporal_scaler_data["scale"]
    )

    missing = [
        feature
        for feature in temporal_features
        if feature not in temporal_df.columns
    ]

    if missing:

        raise ValueError(
            "Missing temporal features:\n"
            + "\n".join(missing)
        )

    X_temporal = (
        temporal_df[
            temporal_features
        ]
        .replace(
            [np.inf, -np.inf],
            np.nan
        )
        .fillna(0)
        .values
        .astype(np.float32)
    )

    X_temporal_scaled = (
        X_temporal - temporal_mean
    ) / temporal_scale

    temporal_model, temporal_checkpoint = (
        load_autoencoder(
            TEMPORAL_MODEL
        )
    )

    saved_input_dim = int(
        temporal_checkpoint["input_dim"]
    )

    if saved_input_dim != len(
        temporal_features
    ):

        raise ValueError(
            "\nTemporal feature/model mismatch.\n"
            f"Model input dimension: "
            f"{saved_input_dim}\n"
            f"Temporal features: "
            f"{len(temporal_features)}"
        )

    temporal_tensor = torch.tensor(
        X_temporal_scaled,
        dtype=torch.float32
    )

    temporal_loader = DataLoader(
        TensorDataset(temporal_tensor),
        batch_size=512,
        shuffle=False
    )

    temporal_errors = []

    with torch.no_grad():

        for batch in temporal_loader:

            x = batch[0].to(DEVICE)

            reconstructed, _ = (
                temporal_model(x)
            )

            error = torch.mean(
                (reconstructed - x) ** 2,
                dim=1
            )

            temporal_errors.extend(
                error.cpu().numpy()
            )

    temporal_errors = np.asarray(
        temporal_errors
    )

print(
    f"Temporal scores: "
    f"{len(temporal_errors):,}"
)


# ============================================================
# 3. SEMANTIC TEXT MODEL
# ============================================================

print("\n" + "=" * 70)
print("3. SEMANTIC TEXT MODEL")
print("=" * 70)

text_df = pd.read_csv(
    TEXT_TEST
)

print(
    f"Text records: "
    f"{len(text_df):,}"
)

with open(
    TEXT_LABEL_MAP,
    "r",
    encoding="utf-8"
) as f:

    label_map = json.load(f)


# ------------------------------------------------------------
# CORRECT LABEL MAP FORMAT
# ------------------------------------------------------------

if "id_to_label" not in label_map:

    raise ValueError(
        "text_label_map.json does not contain "
        "'id_to_label'."
    )


id_to_label = {
    int(key): value
    for key, value in
    label_map["id_to_label"].items()
}


print(
    f"Semantic classes: "
    f"{len(id_to_label)}"
)


# ============================================================
# TEXT COLUMN
# ============================================================

text_candidates = [
    "text",
    "listing_text",
    "listing_name",
    "name",
    "description"
]

text_column = None

for column in text_candidates:

    if column in text_df.columns:

        text_column = column
        break

if text_column is None:

    raise ValueError(
        "\nNo supported text column found.\n"
        f"Available columns:\n"
        f"{list(text_df.columns)}"
    )

print(
    f"Text column: {text_column}"
)

texts = (
    text_df[
        text_column
    ]
    .fillna("")
    .astype(str)
    .tolist()
)


# ============================================================
# LOAD TEXT MODEL
# ============================================================

tokenizer = AutoTokenizer.from_pretrained(
    TEXT_MODEL
)

text_model = (
    AutoModelForSequenceClassification
    .from_pretrained(
        TEXT_MODEL
    )
)

text_model.to(DEVICE)
text_model.eval()


# ============================================================
# TEXT INFERENCE
# ============================================================

semantic_predictions = []
semantic_confidences = []

TEXT_BATCH_SIZE = 32

print(
    "\nGenerating semantic predictions..."
)

for start in range(
    0,
    len(texts),
    TEXT_BATCH_SIZE
):

    batch_texts = texts[
        start:
        start + TEXT_BATCH_SIZE
    ]

    encoded = tokenizer(
        batch_texts,
        padding=True,
        truncation=True,
        max_length=96,
        return_tensors="pt"
    )

    encoded = {
        key: value.to(DEVICE)
        for key, value in encoded.items()
    }

    with torch.no_grad():

        outputs = text_model(
            **encoded
        )

        probabilities = torch.softmax(
            outputs.logits,
            dim=1
        )

        confidence, prediction = (
            torch.max(
                probabilities,
                dim=1
            )
        )

    semantic_predictions.extend(
        prediction.cpu().numpy()
    )

    semantic_confidences.extend(
        confidence.cpu().numpy()
    )

    processed = min(
        start + TEXT_BATCH_SIZE,
        len(texts)
    )

    if (
        processed % 1000 < TEXT_BATCH_SIZE
        or processed == len(texts)
    ):

        print(
            f"  {processed:,}/"
            f"{len(texts):,}"
        )

semantic_predictions = np.asarray(
    semantic_predictions
)

semantic_confidences = np.asarray(
    semantic_confidences
)

semantic_labels = np.array([

    id_to_label.get(
        int(prediction),
        "UNKNOWN"
    )

    for prediction
    in semantic_predictions

])


# ============================================================
# ALIGNMENT CHECK
# ============================================================

print("\n" + "=" * 70)
print("ALIGNMENT CHECK")
print("=" * 70)

n_text = len(text_df)
n_tabular = len(behavioral_errors)
n_temporal = len(temporal_errors)

print(
    f"Text      : {n_text:,}"
)

print(
    f"Behavioral: {n_tabular:,}"
)

print(
    f"Temporal  : {n_temporal:,}"
)

if not (
    n_text ==
    n_tabular ==
    n_temporal
):

    raise ValueError(
        "\nDataset alignment failed."
    )

print(
    "\nAll three models aligned."
)


# ============================================================
# NORMALIZE ANOMALY SIGNALS
# ============================================================

def normalize_error(values):

    p95 = np.percentile(
        values,
        95
    )

    p99 = np.percentile(
        values,
        99
    )

    if p99 <= p95:

        return np.zeros(
            len(values)
        )

    normalized = (
        values - p95
    ) / (
        p99 - p95
    )

    return np.clip(
        normalized,
        0,
        1
    )


behavioral_signal = normalize_error(
    behavioral_errors
)

temporal_signal = normalize_error(
    temporal_errors
)


# ============================================================
# THRESHOLDS
# ============================================================

behavioral_threshold_95 = (
    np.percentile(
        behavioral_errors,
        95
    )
)

behavioral_threshold_99 = (
    np.percentile(
        behavioral_errors,
        99
    )
)

temporal_threshold_95 = (
    np.percentile(
        temporal_errors,
        95
    )
)

temporal_threshold_99 = (
    np.percentile(
        temporal_errors,
        99
    )
)


behavioral_anomaly_95 = (
    behavioral_errors >
    behavioral_threshold_95
).astype(int)

behavioral_anomaly_99 = (
    behavioral_errors >
    behavioral_threshold_99
).astype(int)

temporal_anomaly_95 = (
    temporal_errors >
    temporal_threshold_95
).astype(int)

temporal_anomaly_99 = (
    temporal_errors >
    temporal_threshold_99
).astype(int)


# ============================================================
# FUSION
# ============================================================

BEHAVIORAL_WEIGHT = 0.40
TEMPORAL_WEIGHT = 0.35
SEMANTIC_WEIGHT = 0.25

fusion_score = (

    behavioral_signal *
    BEHAVIORAL_WEIGHT

    +

    temporal_signal *
    TEMPORAL_WEIGHT

    +

    semantic_confidences *
    SEMANTIC_WEIGHT
)

fusion_score = np.clip(
    fusion_score,
    0,
    1
)


# ============================================================
# SIGNAL AGREEMENT
# ============================================================

semantic_strong = (
    semantic_confidences >= 0.70
).astype(int)

signal_count = (
    behavioral_anomaly_95
    +
    temporal_anomaly_95
    +
    semantic_strong
)

signal_agreement = np.where(

    signal_count >= 3,

    "THREE_SIGNAL",

    np.where(

        signal_count == 2,

        "TWO_SIGNAL",

        np.where(

            signal_count == 1,

            "SINGLE_SIGNAL",

            "NO_STRONG_SIGNAL"
        )
    )
)


# ============================================================
# FUSION BANDS
# ============================================================

def fusion_band(score):

    if score >= 0.80:

        return "HIGH"

    if score >= 0.60:

        return "ELEVATED"

    if score >= 0.30:

        return "MODERATE"

    return "LOW"


fusion_bands = np.array([

    fusion_band(score)

    for score in fusion_score

])


# ============================================================
# OUTPUT DATAFRAME
# ============================================================

fusion_df = pd.DataFrame({

    "observation_index":
        np.arange(n_text),

    "behavioral_reconstruction_error":
        behavioral_errors,

    "behavioral_signal":
        behavioral_signal,

    "behavioral_anomaly_95":
        behavioral_anomaly_95,

    "behavioral_anomaly_99":
        behavioral_anomaly_99,

    "temporal_reconstruction_error":
        temporal_errors,

    "temporal_signal":
        temporal_signal,

    "temporal_anomaly_95":
        temporal_anomaly_95,

    "temporal_anomaly_99":
        temporal_anomaly_99,

    "semantic_prediction_id":
        semantic_predictions,

    "semantic_prediction":
        semantic_labels,

    "semantic_confidence":
        semantic_confidences,

    "fusion_score":
        fusion_score,

    "signal_count":
        signal_count,

    "signal_agreement":
        signal_agreement,

    "fusion_band":
        fusion_bands
})


# ============================================================
# PRESERVE IDENTIFIERS
# ============================================================

identifier_columns = [
    "record_id",
    "snapshot_date",
    "vendor",
    "marketplace",
    "category",
    "listing_name"
]

for column in reversed(
    identifier_columns
):

    if column in text_df.columns:

        fusion_df.insert(
            0,
            column,
            text_df[column].values
        )


# ============================================================
# SAVE
# ============================================================

fusion_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# SUMMARY
# ============================================================

summary = {

    "records": int(n_text),

    "behavioral_features":
        len(behavioral_features),

    "temporal_features":
        len(temporal_features),

    "semantic_classes":
        len(id_to_label),

    "behavioral_weight":
        BEHAVIORAL_WEIGHT,

    "temporal_weight":
        TEMPORAL_WEIGHT,

    "semantic_weight":
        SEMANTIC_WEIGHT,

    "behavioral_threshold_95":
        float(
            behavioral_threshold_95
        ),

    "behavioral_threshold_99":
        float(
            behavioral_threshold_99
        ),

    "temporal_threshold_95":
        float(
            temporal_threshold_95
        ),

    "temporal_threshold_99":
        float(
            temporal_threshold_99
        ),

    "behavioral_anomalies_95":
        int(
            behavioral_anomaly_95.sum()
        ),

    "behavioral_anomalies_99":
        int(
            behavioral_anomaly_99.sum()
        ),

    "temporal_anomalies_95":
        int(
            temporal_anomaly_95.sum()
        ),

    "temporal_anomalies_99":
        int(
            temporal_anomaly_99.sum()
        ),

    "semantic_confidence_mean":
        float(
            semantic_confidences.mean()
        ),

    "semantic_confidence_median":
        float(
            np.median(
                semantic_confidences
            )
        ),

    "two_or_more_signals":
        int(
            np.sum(
                signal_count >= 2
            )
        ),

    "three_signal_cases":
        int(
            np.sum(
                signal_count >= 3
            )
        ),

    "mean_fusion_score":
        float(
            fusion_score.mean()
        ),

    "median_fusion_score":
        float(
            np.median(
                fusion_score
            )
        ),

    "fusion_band_counts": {

        str(key): int(value)

        for key, value in
        pd.Series(
            fusion_bands
        )
        .value_counts()
        .to_dict()
        .items()
    }
}


with open(
    SUMMARY_FILE,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        summary,
        f,
        indent=4
    )


# ============================================================
# FINAL REPORT
# ============================================================

print("\n" + "=" * 70)
print("MODEL FUSION COMPLETE")
print("=" * 70)

print(
    f"\nObservations fused: "
    f"{n_text:,}"
)

print(
    f"Behavioral anomalies @95%: "
    f"{behavioral_anomaly_95.sum():,}"
)

print(
    f"Temporal anomalies @95%: "
    f"{temporal_anomaly_95.sum():,}"
)

print(
    f"Mean semantic confidence: "
    f"{semantic_confidences.mean():.4f}"
)

print(
    f"\nTwo-or-more signals: "
    f"{np.sum(signal_count >= 2):,}"
)

print(
    f"Three-signal cases: "
    f"{np.sum(signal_count >= 3):,}"
)

print(
    f"\nMean fusion score: "
    f"{fusion_score.mean():.4f}"
)

print(
    f"Median fusion score: "
    f"{np.median(fusion_score):.4f}"
)

print("\nFusion bands:")

for band, count in (
    pd.Series(
        fusion_bands
    )
    .value_counts()
    .items()
):

    print(
        f"  {band:<12}: {count:,}"
    )

print(
    f"\nSaved:\n"
    f"{OUTPUT_FILE}"
)

print(
    f"\nSummary:\n"
    f"{SUMMARY_FILE}"
)

print(
    "\nFusion stage completed."
)