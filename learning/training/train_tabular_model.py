import os
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.preprocessing import StandardScaler
import joblib


# ============================================================
# DARKWATCH-XAI
# TABULAR BEHAVIORAL AUTOENCODER
# CORRECTED VERSION
# ============================================================

BASE_DIR = r"C:\Users\buyya\Desktop\darkwatch"

DATA_DIR = os.path.join(BASE_DIR, "data", "processed", "training")
MODEL_DIR = os.path.join(BASE_DIR, "models", "dwdata_tabular_model")
REPORT_DIR = os.path.join(BASE_DIR, "reports", "training")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

TRAIN_PATH = os.path.join(DATA_DIR, "tabular_train.csv")
VAL_PATH = os.path.join(DATA_DIR, "tabular_validation.csv")
TEST_PATH = os.path.join(DATA_DIR, "tabular_test.csv")
FEATURE_PATH = os.path.join(DATA_DIR, "tabular_features.json")


# ============================================================
# CONFIGURATION
# ============================================================

BATCH_SIZE = 512
EPOCHS = 30
LEARNING_RATE = 1e-3
PATIENCE = 6

RANDOM_SEED = 42

torch.manual_seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ============================================================
# TEMPORAL FEATURES
# ============================================================
# These are deliberately excluded from the behavioral
# autoencoder because the chronological train/test split
# naturally creates large temporal distribution shifts.
#
# Temporal information will be handled by the separate
# temporal model later.

TEMPORAL_FEATURES = {
    "snapshot_month",
    "snapshot_quarter",
    "snapshot_day_of_month",
    "snapshot_day_of_week",
    "snapshot_is_weekend",
    "days_since_first_snapshot",
    "vendor_observation_number",
    "vendor_previous_observation_gap",
}


# ============================================================
# LOAD FEATURE LIST
# ============================================================

with open(FEATURE_PATH, "r", encoding="utf-8") as f:
    feature_data = json.load(f)

if isinstance(feature_data, dict):

    if "features" in feature_data:
        ALL_FEATURES = feature_data["features"]

    elif "tabular_features" in feature_data:
        ALL_FEATURES = feature_data["tabular_features"]

    else:
        ALL_FEATURES = list(feature_data.values())[0]

else:
    ALL_FEATURES = feature_data


print("=" * 70)
print("DARKWATCH-XAI")
print("TABULAR BEHAVIORAL AUTOENCODER")
print("=" * 70)

print()
print("Device :", DEVICE)


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
# REMOVE TEMPORAL FEATURES
# ============================================================

BEHAVIORAL_FEATURES = [
    f for f in ALL_FEATURES
    if f not in TEMPORAL_FEATURES
]

print()
print("Original features :", len(ALL_FEATURES))
print("Temporal removed  :", len(ALL_FEATURES) - len(BEHAVIORAL_FEATURES))
print("Behavioral input  :", len(BEHAVIORAL_FEATURES))


print()
print("Removed temporal features:")

for feature in sorted(TEMPORAL_FEATURES):

    if feature in ALL_FEATURES:
        print("  -", feature)


# ============================================================
# NUMERIC CONVERSION
# ============================================================

train_x = train[BEHAVIORAL_FEATURES].apply(
    pd.to_numeric,
    errors="coerce"
)

val_x = val[BEHAVIORAL_FEATURES].apply(
    pd.to_numeric,
    errors="coerce"
)

test_x = test[BEHAVIORAL_FEATURES].apply(
    pd.to_numeric,
    errors="coerce"
)


# ============================================================
# CLEAN INVALID VALUES
# ============================================================

train_x = train_x.replace([np.inf, -np.inf], np.nan)
val_x = val_x.replace([np.inf, -np.inf], np.nan)
test_x = test_x.replace([np.inf, -np.inf], np.nan)


# Fill using TRAIN medians only
train_medians = train_x.median()

train_x = train_x.fillna(train_medians)
val_x = val_x.fillna(train_medians)
test_x = test_x.fillna(train_medians)


# ============================================================
# REMOVE CONSTANT / NEAR-CONSTANT FEATURES
# ============================================================

feature_variance = train_x.var()

usable_features = [
    feature
    for feature in BEHAVIORAL_FEATURES
    if np.isfinite(feature_variance[feature])
    and feature_variance[feature] > 1e-12
]

removed_features = [
    feature
    for feature in BEHAVIORAL_FEATURES
    if feature not in usable_features
]


print()
print("Constant / near-constant features removed:",
      len(removed_features))

for feature in removed_features:
    print("  -", feature)


train_x = train_x[usable_features]
val_x = val_x[usable_features]
test_x = test_x[usable_features]


# ============================================================
# SCALE
# ============================================================

print()
print("Fitting scaler...")

scaler = StandardScaler()

train_scaled = scaler.fit_transform(train_x)
val_scaled = scaler.transform(val_x)
test_scaled = scaler.transform(test_x)


# ============================================================
# AUTOENCODER
# ============================================================

class TabularAutoencoder(nn.Module):

    def __init__(self, input_dim):

        super().__init__()

        hidden1 = max(32, input_dim * 2)
        hidden2 = max(16, input_dim)
        latent = max(8, input_dim // 2)

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

        z = self.encoder(x)

        reconstruction = self.decoder(z)

        return reconstruction


# ============================================================
# DATA LOADERS
# ============================================================

train_tensor = torch.tensor(
    train_scaled,
    dtype=torch.float32
)

val_tensor = torch.tensor(
    val_scaled,
    dtype=torch.float32
)

test_tensor = torch.tensor(
    test_scaled,
    dtype=torch.float32
)


train_loader = DataLoader(
    TensorDataset(train_tensor),
    batch_size=BATCH_SIZE,
    shuffle=True
)

val_loader = DataLoader(
    TensorDataset(val_tensor),
    batch_size=BATCH_SIZE,
    shuffle=False
)


# ============================================================
# MODEL
# ============================================================

model = TabularAutoencoder(
    input_dim=len(usable_features)
).to(DEVICE)

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE
)

criterion = nn.MSELoss()


# ============================================================
# TRAINING
# ============================================================

print()
print("=" * 70)
print("STARTING CORRECTED TABULAR AUTOENCODER TRAINING")
print("=" * 70)

best_val_loss = float("inf")
best_state = None

history = []

patience_counter = 0


for epoch in range(1, EPOCHS + 1):

    model.train()

    train_loss = 0.0
    train_count = 0

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

        train_loss += loss.item() * len(batch)
        train_count += len(batch)


    train_loss /= train_count


    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    model.eval()

    val_loss = 0.0
    val_count = 0

    with torch.no_grad():

        for (batch,) in val_loader:

            batch = batch.to(DEVICE)

            reconstruction = model(batch)

            loss = criterion(
                reconstruction,
                batch
            )

            val_loss += loss.item() * len(batch)
            val_count += len(batch)


    val_loss /= val_count


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


    if val_loss < best_val_loss:

        best_val_loss = val_loss

        best_state = {
            key: value.detach().cpu().clone()
            for key, value in model.state_dict().items()
        }

        patience_counter = 0

    else:

        patience_counter += 1

        if patience_counter >= PATIENCE:

            print()
            print(
                f"Early stopping at epoch {epoch}"
            )

            break


# ============================================================
# RESTORE BEST MODEL
# ============================================================

model.load_state_dict(best_state)
model.eval()


# ============================================================
# RECONSTRUCTION ERROR FUNCTION
# ============================================================

def reconstruction_errors(data_array):

    tensor = torch.tensor(
        data_array,
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
                (reconstruction - batch) ** 2,
                dim=1
            )

            errors.extend(
                batch_errors.cpu().numpy()
            )

    return np.asarray(errors)


# ============================================================
# CALCULATE ERRORS
# ============================================================

print()
print("Calculating reconstruction errors...")

train_errors = reconstruction_errors(train_scaled)
val_errors = reconstruction_errors(val_scaled)
test_errors = reconstruction_errors(test_scaled)


# ============================================================
# THRESHOLDS
# ============================================================
#
# Thresholds are calculated from TRAINING behavior.
#
# We report them, but we do NOT interpret every future
# distribution shift as malicious activity.
# ============================================================

threshold_95 = np.percentile(
    train_errors,
    95
)

threshold_99 = np.percentile(
    train_errors,
    99
)


# ============================================================
# TEST SCORES
# ============================================================

test_anomaly_95 = test_errors > threshold_95
test_anomaly_99 = test_errors > threshold_99


# ============================================================
# SAVE MODEL
# ============================================================

model_path = os.path.join(
    MODEL_DIR,
    "model.pt"
)

torch.save(
    {
        "model_state_dict": model.state_dict(),
        "input_dim": len(usable_features),
        "features": usable_features
    },
    model_path
)


# ============================================================
# SAVE SCALER
# ============================================================

joblib.dump(
    scaler,
    os.path.join(
        MODEL_DIR,
        "scaler.joblib"
    )
)


# ============================================================
# SAVE FEATURES
# ============================================================

with open(
    os.path.join(
        MODEL_DIR,
        "features.json"
    ),
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        {
            "all_features": ALL_FEATURES,
            "temporal_features_removed": sorted(
                list(TEMPORAL_FEATURES)
            ),
            "behavioral_features": usable_features,
            "constant_features_removed": removed_features
        },
        f,
        indent=2
    )


# ============================================================
# SAVE TEST ANOMALY SCORES
# ============================================================

test_output = pd.DataFrame({
    "reconstruction_error": test_errors,
    "anomaly_95": test_anomaly_95.astype(int),
    "anomaly_99": test_anomaly_99.astype(int)
})

if "record_id" in test.columns:
    test_output.insert(
        0,
        "record_id",
        test["record_id"].values
    )

if "snapshot_date" in test.columns:
    test_output["snapshot_date"] = (
        test["snapshot_date"].values
    )

test_output.to_csv(
    os.path.join(
        REPORT_DIR,
        "tabular_test_anomaly_scores.csv"
    ),
    index=False
)


# ============================================================
# SAVE TRAINING HISTORY
# ============================================================

with open(
    os.path.join(
        REPORT_DIR,
        "tabular_training_history.json"
    ),
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        history,
        f,
        indent=2
    )


# ============================================================
# SAVE METRICS
# ============================================================

metrics = {
    "input_features": len(usable_features),
    "original_features": len(ALL_FEATURES),
    "temporal_features_removed": len(
        [f for f in TEMPORAL_FEATURES if f in ALL_FEATURES]
    ),
    "constant_features_removed": len(
        removed_features
    ),

    "best_validation_loss": float(
        best_val_loss
    ),

    "train_reconstruction_mean": float(
        train_errors.mean()
    ),

    "validation_reconstruction_mean": float(
        val_errors.mean()
    ),

    "test_reconstruction_mean": float(
        test_errors.mean()
    ),

    "test_reconstruction_median": float(
        np.median(test_errors)
    ),

    "threshold_95": float(
        threshold_95
    ),

    "threshold_99": float(
        threshold_99
    ),

    "test_anomalies_95": int(
        test_anomaly_95.sum()
    ),

    "test_anomalies_95_pct": float(
        test_anomaly_95.mean() * 100
    ),

    "test_anomalies_99": int(
        test_anomaly_99.sum()
    ),

    "test_anomalies_99_pct": float(
        test_anomaly_99.mean() * 100
    )
}


with open(
    os.path.join(
        REPORT_DIR,
        "tabular_model_metrics.json"
    ),
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        metrics,
        f,
        indent=2
    )


# ============================================================
# FINAL OUTPUT
# ============================================================

print()
print("=" * 70)
print("CORRECTED TABULAR MODEL TRAINING COMPLETE")
print("=" * 70)

print()
print(f"Original features           : {len(ALL_FEATURES)}")
print(f"Behavioral features         : {len(usable_features)}")
print(f"Temporal features removed   : {len([f for f in TEMPORAL_FEATURES if f in ALL_FEATURES])}")
print(f"Constant features removed   : {len(removed_features)}")

print()
print(f"Best validation loss        : {best_val_loss:.6f}")

print()
print(f"Train reconstruction mean   : {train_errors.mean():.6f}")
print(f"Validation reconstruction   : {val_errors.mean():.6f}")
print(f"Test reconstruction mean    : {test_errors.mean():.6f}")
print(f"Test reconstruction median  : {np.median(test_errors):.6f}")

print()
print(f"95% anomaly threshold       : {threshold_95:.6f}")
print(f"99% anomaly threshold       : {threshold_99:.6f}")

print()
print(
    f"Test anomalies @95%        : "
    f"{test_anomaly_95.sum():,} "
    f"({test_anomaly_95.mean() * 100:.2f}%)"
)

print(
    f"Test anomalies @99%        : "
    f"{test_anomaly_99.sum():,} "
    f"({test_anomaly_99.mean() * 100:.2f}%)"
)

print()
print("Model:")
print(MODEL_DIR)

print()
print("Reports:")
print(REPORT_DIR)

print()
print("=" * 70)