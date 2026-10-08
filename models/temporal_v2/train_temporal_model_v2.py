import os
import json
import random

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset


# ============================================================
# DARKWATCH-XAI
# TEMPORAL AUTOENCODER V2
# NORMALIZED DATASET
# ============================================================

print("=" * 70)
print("DARKWATCH-XAI TEMPORAL MODEL V2")
print("NORMALIZED TEMPORAL AUTOENCODER")
print("=" * 70)


# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = "data/processed/training/temporal_v2"

TRAIN_PATH = os.path.join(
    DATA_DIR,
    "temporal_train.csv"
)

VAL_PATH = os.path.join(
    DATA_DIR,
    "temporal_validation.csv"
)

TEST_PATH = os.path.join(
    DATA_DIR,
    "temporal_test.csv"
)

FEATURE_PATH = os.path.join(
    DATA_DIR,
    "temporal_features.json"
)

MODEL_DIR = "models/dwdata_temporal_model"

REPORT_DIR = "reports/training"

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


# Reproducibility
SEED = 42

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)


# CPU-safe configuration
DEVICE = torch.device("cpu")

BATCH_SIZE = 256

EPOCHS = 30

LEARNING_RATE = 0.001

WEIGHT_DECAY = 1e-5

PATIENCE = 5


print(f"\nDevice: {DEVICE}")


# ============================================================
# LOAD FEATURE LIST
# ============================================================

with open(
    FEATURE_PATH,
    "r",
    encoding="utf-8"
) as f:
    FEATURES = json.load(f)


INPUT_DIM = len(FEATURES)

print(f"Temporal features: {INPUT_DIM}")

print("\nFeatures:")
for i, feature in enumerate(FEATURES, 1):
    print(f"  {i:2d}. {feature}")


# ============================================================
# LOAD DATA
# ============================================================

print("\n" + "=" * 70)
print("LOADING DATA")
print("=" * 70)

train_df = pd.read_csv(TRAIN_PATH)
val_df = pd.read_csv(VAL_PATH)
test_df = pd.read_csv(TEST_PATH)

print(f"Training   : {len(train_df):,}")
print(f"Validation : {len(val_df):,}")
print(f"Test       : {len(test_df):,}")


# ============================================================
# VALIDATE COLUMNS
# ============================================================

for name, df in [
    ("train", train_df),
    ("validation", val_df),
    ("test", test_df)
]:
    missing = [
        f for f in FEATURES
        if f not in df.columns
    ]

    if missing:
        raise ValueError(
            f"{name} dataset missing features: {missing}"
        )


# ============================================================
# NUMERIC MATRICES
# ============================================================

X_train = train_df[FEATURES].astype(np.float32).values

X_val = val_df[FEATURES].astype(np.float32).values

X_test = test_df[FEATURES].astype(np.float32).values


# Safety checks

for name, X in [
    ("train", X_train),
    ("validation", X_val),
    ("test", X_test)
]:

    if np.isnan(X).any():
        raise ValueError(
            f"NaN values found in {name} dataset."
        )

    if np.isinf(X).any():
        raise ValueError(
            f"Infinite values found in {name} dataset."
        )


print("\nData matrices:")
print(f"  Train: {X_train.shape}")
print(f"  Val  : {X_val.shape}")
print(f"  Test : {X_test.shape}")


# ============================================================
# TORCH DATASETS
# ============================================================

train_tensor = torch.tensor(
    X_train,
    dtype=torch.float32
)

val_tensor = torch.tensor(
    X_val,
    dtype=torch.float32
)

test_tensor = torch.tensor(
    X_test,
    dtype=torch.float32
)


train_dataset = TensorDataset(train_tensor)

val_dataset = TensorDataset(val_tensor)

test_dataset = TensorDataset(test_tensor)


train_loader = DataLoader(
    train_dataset,
    batch_size=BATCH_SIZE,
    shuffle=True,
    num_workers=0
)

val_loader = DataLoader(
    val_dataset,
    batch_size=BATCH_SIZE,
    shuffle=False,
    num_workers=0
)

test_loader = DataLoader(
    test_dataset,
    batch_size=BATCH_SIZE,
    shuffle=False,
    num_workers=0
)


# ============================================================
# MODEL
# ============================================================

class TemporalAutoencoder(nn.Module):

    def __init__(self, input_dim):

        super().__init__()

        hidden1 = 32
        hidden2 = 16
        latent = 8

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden1),
            nn.ReLU(),

            nn.Linear(hidden1, hidden2),
            nn.ReLU(),

            nn.Linear(hidden2, latent)
        )

        self.decoder = nn.Sequential(
            nn.Linear(latent, hidden2),
            nn.ReLU(),

            nn.Linear(hidden2, hidden1),
            nn.ReLU(),

            nn.Linear(hidden1, input_dim)
        )

    def forward(self, x):

        latent = self.encoder(x)

        reconstruction = self.decoder(latent)

        return reconstruction


model = TemporalAutoencoder(INPUT_DIM).to(DEVICE)

print("\n" + "=" * 70)
print("MODEL")
print("=" * 70)

print(
    f"Architecture: "
    f"{INPUT_DIM} → 32 → 16 → 8 → 16 → 32 → {INPUT_DIM}"
)


# ============================================================
# LOSS / OPTIMIZER
# ============================================================

criterion = nn.MSELoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE,
    weight_decay=WEIGHT_DECAY
)


# ============================================================
# VALIDATION FUNCTION
# ============================================================

def evaluate_loss(model, loader):

    model.eval()

    total_loss = 0.0

    total_samples = 0

    with torch.no_grad():

        for (batch,) in loader:

            batch = batch.to(DEVICE)

            reconstruction = model(batch)

            loss = criterion(
                reconstruction,
                batch
            )

            batch_size = batch.size(0)

            total_loss += (
                loss.item() * batch_size
            )

            total_samples += batch_size

    return total_loss / total_samples


# ============================================================
# TRAINING
# ============================================================

print("\n" + "=" * 70)
print("TRAINING")
print("=" * 70)

best_val_loss = float("inf")

best_epoch = 0

patience_counter = 0

history = []


for epoch in range(1, EPOCHS + 1):

    model.train()

    running_loss = 0.0

    sample_count = 0

    for (batch,) in train_loader:

        batch = batch.to(DEVICE)

        optimizer.zero_grad()

        reconstruction = model(batch)

        loss = criterion(
            reconstruction,
            batch
        )

        loss.backward()

        optimizer.step()

        batch_size = batch.size(0)

        running_loss += (
            loss.item() * batch_size
        )

        sample_count += batch_size


    train_loss = (
        running_loss / sample_count
    )

    val_loss = evaluate_loss(
        model,
        val_loader
    )

    history.append({
        "epoch": epoch,
        "train_loss": train_loss,
        "validation_loss": val_loss
    })

    print(
        f"Epoch {epoch:02d}/{EPOCHS} | "
        f"Train Loss: {train_loss:.6f} | "
        f"Val Loss: {val_loss:.6f}"
    )


    # --------------------------------------------------------
    # BEST MODEL
    # --------------------------------------------------------

    if val_loss < best_val_loss:

        best_val_loss = val_loss

        best_epoch = epoch

        patience_counter = 0

        torch.save(
            {
                "model_state_dict": model.state_dict(),
                "input_dim": INPUT_DIM,
                "feature_columns": FEATURES,
                "best_validation_loss": best_val_loss,
                "architecture": [
                    INPUT_DIM,
                    32,
                    16,
                    8,
                    16,
                    32,
                    INPUT_DIM
                ]
            },
            os.path.join(
                MODEL_DIR,
                "temporal_autoencoder_v2.pt"
            )
        )

    else:

        patience_counter += 1

        if patience_counter >= PATIENCE:

            print(
                f"\nEarly stopping at epoch {epoch}."
            )

            break


# ============================================================
# LOAD BEST MODEL
# ============================================================

print("\n" + "=" * 70)
print("LOADING BEST MODEL")
print("=" * 70)

checkpoint_path = os.path.join(
    MODEL_DIR,
    "temporal_autoencoder_v2.pt"
)

checkpoint = torch.load(
    checkpoint_path,
    map_location=DEVICE,
    weights_only=False
)

model.load_state_dict(
    checkpoint["model_state_dict"]
)

model.eval()

print(f"Best epoch       : {best_epoch}")

print(
    f"Best validation loss: "
    f"{best_val_loss:.8f}"
)


# ============================================================
# RECONSTRUCTION ERRORS
# ============================================================

def reconstruction_errors(model, X):

    tensor = torch.tensor(
        X,
        dtype=torch.float32
    )

    loader = DataLoader(
        TensorDataset(tensor),
        batch_size=BATCH_SIZE,
        shuffle=False
    )

    errors = []

    with torch.no_grad():

        for (batch,) in loader:

            batch = batch.to(DEVICE)

            reconstruction = model(batch)

            batch_errors = torch.mean(
                (batch - reconstruction) ** 2,
                dim=1
            )

            errors.extend(
                batch_errors.cpu().numpy()
            )

    return np.asarray(errors)


print("\n" + "=" * 70)
print("EVALUATION")
print("=" * 70)

train_errors = reconstruction_errors(
    model,
    X_train
)

val_errors = reconstruction_errors(
    model,
    X_val
)

test_errors = reconstruction_errors(
    model,
    X_test
)


# ============================================================
# THRESHOLDS
# ============================================================

threshold_95 = np.percentile(
    train_errors,
    95
)

threshold_99 = np.percentile(
    train_errors,
    99
)

threshold_995 = np.percentile(
    train_errors,
    99.5
)


# ============================================================
# METRICS
# ============================================================

def describe_errors(name, errors):

    print(f"\n{name}")

    print(
        f"  Mean   : {np.mean(errors):.8f}"
    )

    print(
        f"  Median : {np.median(errors):.8f}"
    )

    print(
        f"  Std    : {np.std(errors):.8f}"
    )

    print(
        f"  P95    : {np.percentile(errors, 95):.8f}"
    )

    print(
        f"  P99    : {np.percentile(errors, 99):.8f}"
    )

    print(
        f"  Max    : {np.max(errors):.8f}"
    )


describe_errors(
    "TRAINING RECONSTRUCTION ERROR",
    train_errors
)

describe_errors(
    "VALIDATION RECONSTRUCTION ERROR",
    val_errors
)

describe_errors(
    "TEST RECONSTRUCTION ERROR",
    test_errors
)


# ============================================================
# ANOMALY RATES
# ============================================================

print("\n" + "=" * 70)
print("ANOMALY RATES")
print("=" * 70)


def anomaly_rate(errors, threshold):

    return (
        np.mean(errors >= threshold) * 100
    )


for name, errors in [
    ("Training", train_errors),
    ("Validation", val_errors),
    ("Test", test_errors)
]:

    print(f"\n{name}:")

    print(
        f"  @95% threshold : "
        f"{anomaly_rate(errors, threshold_95):.3f}%"
    )

    print(
        f"  @99% threshold : "
        f"{anomaly_rate(errors, threshold_99):.3f}%"
    )

    print(
        f"  @99.5% threshold: "
        f"{anomaly_rate(errors, threshold_995):.3f}%"
    )


# ============================================================
# SAVE TEST SCORES
# ============================================================

test_results = pd.DataFrame({
    "record_id": test_df["record_id"].values,
    "temporal_reconstruction_error": test_errors,
    "temporal_anomaly_95": (
        test_errors >= threshold_95
    ).astype(int),
    "temporal_anomaly_99": (
        test_errors >= threshold_99
    ).astype(int),
    "temporal_anomaly_995": (
        test_errors >= threshold_995
    ).astype(int)
})


test_scores_path = os.path.join(
    REPORT_DIR,
    "temporal_model_v2_test_scores.csv"
)

test_results.to_csv(
    test_scores_path,
    index=False
)


# ============================================================
# SAVE TRAINING HISTORY
# ============================================================

history_path = os.path.join(
    REPORT_DIR,
    "temporal_model_v2_training_history.csv"
)

pd.DataFrame(history).to_csv(
    history_path,
    index=False
)


# ============================================================
# SAVE SUMMARY
# ============================================================

summary = {

    "model": "TemporalAutoencoder",

    "version": "v2",

    "input_dim": INPUT_DIM,

    "features": FEATURES,

    "architecture": [
        INPUT_DIM,
        32,
        16,
        8,
        16,
        32,
        INPUT_DIM
    ],

    "train_records": len(train_df),

    "validation_records": len(val_df),

    "test_records": len(test_df),

    "best_epoch": best_epoch,

    "best_validation_loss": float(
        best_val_loss
    ),

    "train_mean_error": float(
        np.mean(train_errors)
    ),

    "train_median_error": float(
        np.median(train_errors)
    ),

    "validation_mean_error": float(
        np.mean(val_errors)
    ),

    "validation_median_error": float(
        np.median(val_errors)
    ),

    "test_mean_error": float(
        np.mean(test_errors)
    ),

    "test_median_error": float(
        np.median(test_errors)
    ),

    "threshold_95": float(
        threshold_95
    ),

    "threshold_99": float(
        threshold_99
    ),

    "threshold_995": float(
        threshold_995
    ),

    "test_anomaly_rate_95": float(
        anomaly_rate(
            test_errors,
            threshold_95
        )
    ),

    "test_anomaly_rate_99": float(
        anomaly_rate(
            test_errors,
            threshold_99
        )
    ),

    "test_anomaly_rate_995": float(
        anomaly_rate(
            test_errors,
            threshold_995
        )
    )
}


summary_path = os.path.join(
    REPORT_DIR,
    "temporal_model_v2_summary.json"
)

with open(
    summary_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        summary,
        f,
        indent=2
    )


# ============================================================
# FINAL
# ============================================================

print("\n" + "=" * 70)
print("TEMPORAL MODEL V2 COMPLETE")
print("=" * 70)

print(
    f"\nBest validation loss : "
    f"{best_val_loss:.8f}"
)

print(
    f"Test mean error      : "
    f"{np.mean(test_errors):.8f}"
)

print(
    f"Test median error    : "
    f"{np.median(test_errors):.8f}"
)

print(
    f"\n95% threshold  : "
    f"{threshold_95:.8f}"
)

print(
    f"99% threshold  : "
    f"{threshold_99:.8f}"
)

print(
    f"99.5% threshold: "
    f"{threshold_995:.8f}"
)

print("\nSaved:")

print(
    f"  Model   : {checkpoint_path}"
)

print(
    f"  Scores  : {test_scores_path}"
)

print(
    f"  History : {history_path}"
)

print(
    f"  Summary : {summary_path}"
)

print("\nTemporal model is ready for evaluation/fusion.")
