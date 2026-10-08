import os
import json
import copy
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error

# ============================================================
# CONFIG
# ============================================================

PROJECT_DIR = r"C:\Users\buyya\Desktop\darkwatch"

DATA_DIR = os.path.join(
    PROJECT_DIR,
    "data",
    "processed",
    "training"
)

MODEL_DIR = os.path.join(
    PROJECT_DIR,
    "models",
    "dwdata_temporal_model"
)

REPORT_DIR = os.path.join(
    PROJECT_DIR,
    "reports",
    "training"
)

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

TRAIN_FILE = os.path.join(DATA_DIR, "temporal_train.csv")
VAL_FILE = os.path.join(DATA_DIR, "temporal_validation.csv")
TEST_FILE = os.path.join(DATA_DIR, "temporal_test.csv")

SEED = 42

BATCH_SIZE = 512
EPOCHS = 40
LEARNING_RATE = 1e-3
PATIENCE = 7

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ============================================================
# REPRODUCIBILITY
# ============================================================

np.random.seed(SEED)
torch.manual_seed(SEED)

if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 60)
print("DARKWATCH-XAI TEMPORAL MODEL")
print("=" * 60)

print(f"\nDevice: {DEVICE}")
print("\nLoading temporal datasets...")

train_df = pd.read_csv(TRAIN_FILE)
val_df = pd.read_csv(VAL_FILE)
test_df = pd.read_csv(TEST_FILE)

print(f"Train      : {len(train_df):,}")
print(f"Validation : {len(val_df):,}")
print(f"Test       : {len(test_df):,}")


# ============================================================
# IDENTIFY FEATURES
# ============================================================

# Remove identifiers / non-feature columns.
NON_FEATURE_COLUMNS = {
    "record_id",
    "snapshot_date",
    "vendor",
    "marketplace",
    "category",
    "listing_name"
}

feature_columns = [
    c for c in train_df.columns
    if c not in NON_FEATURE_COLUMNS
    and pd.api.types.is_numeric_dtype(train_df[c])
]

if not feature_columns:
    raise RuntimeError("No numeric temporal features were found.")

print(f"\nTemporal features: {len(feature_columns)}")
print("\nFeatures:")

for feature in feature_columns:
    print(f"  - {feature}")


# ============================================================
# ALIGN DATASETS
# ============================================================

missing_val = [
    c for c in feature_columns
    if c not in val_df.columns
]

missing_test = [
    c for c in feature_columns
    if c not in test_df.columns
]

if missing_val:
    raise RuntimeError(
        f"Validation dataset is missing features: {missing_val}"
    )

if missing_test:
    raise RuntimeError(
        f"Test dataset is missing features: {missing_test}"
    )


X_train = train_df[feature_columns].copy()
X_val = val_df[feature_columns].copy()
X_test = test_df[feature_columns].copy()


# ============================================================
# CLEAN NUMERIC VALUES
# ============================================================

X_train = X_train.replace([np.inf, -np.inf], np.nan)
X_val = X_val.replace([np.inf, -np.inf], np.nan)
X_test = X_test.replace([np.inf, -np.inf], np.nan)

train_medians = X_train.median()

X_train = X_train.fillna(train_medians)
X_val = X_val.fillna(train_medians)
X_test = X_test.fillna(train_medians)


# ============================================================
# SCALE USING TRAIN ONLY
# ============================================================

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_val_scaled = scaler.transform(X_val)
X_test_scaled = scaler.transform(X_test)

X_train_scaled = X_train_scaled.astype(np.float32)
X_val_scaled = X_val_scaled.astype(np.float32)
X_test_scaled = X_test_scaled.astype(np.float32)


# ============================================================
# DATA LOADERS
# ============================================================

train_tensor = torch.tensor(X_train_scaled)
val_tensor = torch.tensor(X_val_scaled)
test_tensor = torch.tensor(X_test_scaled)

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

test_loader = DataLoader(
    TensorDataset(test_tensor),
    batch_size=BATCH_SIZE,
    shuffle=False
)


# ============================================================
# TEMPORAL AUTOENCODER
# ============================================================

class TemporalAutoencoder(nn.Module):

    def __init__(self, input_dim):
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),

            nn.Linear(32, 16),
            nn.ReLU(),

            nn.Linear(16, 8)
        )

        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),

            nn.Linear(16, 32),
            nn.ReLU(),

            nn.Linear(32, input_dim)
        )

    def forward(self, x):
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)

        return reconstructed, latent


input_dim = len(feature_columns)

model = TemporalAutoencoder(input_dim).to(DEVICE)

criterion = nn.MSELoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE
)


# ============================================================
# TRAINING
# ============================================================

print("\n" + "=" * 60)
print("TRAINING TEMPORAL AUTOENCODER")
print("=" * 60)

best_val_loss = float("inf")
best_state = None
patience_counter = 0

history = []

for epoch in range(1, EPOCHS + 1):

    # --------------------------------------------------------
    # TRAIN
    # --------------------------------------------------------

    model.train()

    train_loss = 0.0
    train_count = 0

    for batch in train_loader:

        x = batch[0].to(DEVICE)

        optimizer.zero_grad()

        reconstructed, _ = model(x)

        loss = criterion(reconstructed, x)

        loss.backward()

        optimizer.step()

        batch_size = x.size(0)

        train_loss += loss.item() * batch_size
        train_count += batch_size

    train_loss /= train_count


    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    model.eval()

    val_loss = 0.0
    val_count = 0

    with torch.no_grad():

        for batch in val_loader:

            x = batch[0].to(DEVICE)

            reconstructed, _ = model(x)

            loss = criterion(reconstructed, x)

            batch_size = x.size(0)

            val_loss += loss.item() * batch_size
            val_count += batch_size

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


    # --------------------------------------------------------
    # EARLY STOPPING
    # --------------------------------------------------------

    if val_loss < best_val_loss:

        best_val_loss = val_loss

        best_state = copy.deepcopy(
            model.state_dict()
        )

        patience_counter = 0

    else:

        patience_counter += 1

        if patience_counter >= PATIENCE:

            print(
                f"\nEarly stopping at epoch {epoch}"
            )

            break


# ============================================================
# RESTORE BEST MODEL
# ============================================================

if best_state is None:
    raise RuntimeError("No valid model state was saved.")

model.load_state_dict(best_state)
model.eval()


# ============================================================
# RECONSTRUCTION ERROR FUNCTION
# ============================================================

def reconstruction_errors(model, loader):

    errors = []

    with torch.no_grad():

        for batch in loader:

            x = batch[0].to(DEVICE)

            reconstructed, _ = model(x)

            batch_errors = torch.mean(
                (reconstructed - x) ** 2,
                dim=1
            )

            errors.extend(
                batch_errors.cpu().numpy()
            )

    return np.asarray(errors)


# ============================================================
# EVALUATION
# ============================================================

print("\n" + "=" * 60)
print("TEMPORAL MODEL EVALUATION")
print("=" * 60)

train_errors = reconstruction_errors(
    model,
    train_loader
)

val_errors = reconstruction_errors(
    model,
    val_loader
)

test_errors = reconstruction_errors(
    model,
    test_loader
)

train_mean = float(np.mean(train_errors))
val_mean = float(np.mean(val_errors))

test_mean = float(np.mean(test_errors))
test_median = float(np.median(test_errors))

threshold_95 = float(
    np.percentile(train_errors, 95)
)

threshold_99 = float(
    np.percentile(train_errors, 99)
)

test_anomalies_95 = int(
    np.sum(test_errors > threshold_95)
)

test_anomalies_99 = int(
    np.sum(test_errors > threshold_99)
)

test_anomaly_rate_95 = (
    test_anomalies_95 / len(test_errors)
)

test_anomaly_rate_99 = (
    test_anomalies_99 / len(test_errors)
)

print(
    f"\nBest validation loss : "
    f"{best_val_loss:.6f}"
)

print(
    f"\nTrain reconstruction mean : "
    f"{train_mean:.6f}"
)

print(
    f"Validation reconstruction mean : "
    f"{val_mean:.6f}"
)

print(
    f"Test reconstruction mean : "
    f"{test_mean:.6f}"
)

print(
    f"Test reconstruction median : "
    f"{test_median:.6f}"
)

print(
    f"\n95% temporal threshold : "
    f"{threshold_95:.6f}"
)

print(
    f"99% temporal threshold : "
    f"{threshold_99:.6f}"
)

print(
    f"\nTest temporal anomalies @95% : "
    f"{test_anomalies_95:,} "
    f"({test_anomaly_rate_95 * 100:.2f}%)"
)

print(
    f"Test temporal anomalies @99% : "
    f"{test_anomalies_99:,} "
    f"({test_anomaly_rate_99 * 100:.2f}%)"
)


# ============================================================
# SAVE MODEL
# ============================================================

model_path = os.path.join(
    MODEL_DIR,
    "temporal_autoencoder.pt"
)

torch.save(
    {
        "model_state_dict": model.state_dict(),
        "input_dim": input_dim,
        "feature_columns": feature_columns,
        "best_validation_loss": best_val_loss
    },
    model_path
)


# ============================================================
# SAVE SCALER
# ============================================================

scaler_path = os.path.join(
    MODEL_DIR,
    "temporal_scaler.npz"
)

np.savez(
    scaler_path,
    mean=scaler.mean_,
    scale=scaler.scale_,
    feature_columns=np.array(
        feature_columns,
        dtype=object
    )
)


# ============================================================
# SAVE TRAINING HISTORY
# ============================================================

history_path = os.path.join(
    REPORT_DIR,
    "temporal_training_history.csv"
)

pd.DataFrame(history).to_csv(
    history_path,
    index=False
)


# ============================================================
# SAVE TEMPORAL SCORES
# ============================================================

scores_path = os.path.join(
    REPORT_DIR,
    "temporal_test_scores.csv"
)

score_df = pd.DataFrame({
    "temporal_reconstruction_error": test_errors,
    "temporal_anomaly_95": (
        test_errors > threshold_95
    ).astype(int),
    "temporal_anomaly_99": (
        test_errors > threshold_99
    ).astype(int)
})

score_df.to_csv(
    scores_path,
    index=False
)


# ============================================================
# SAVE METRICS
# ============================================================

metrics = {
    "model": "TemporalAutoencoder",

    "device": str(DEVICE),

    "input_features": input_dim,

    "feature_columns": feature_columns,

    "train_records": len(train_df),
    "validation_records": len(val_df),
    "test_records": len(test_df),

    "best_validation_loss": best_val_loss,

    "train_reconstruction_mean": train_mean,
    "validation_reconstruction_mean": val_mean,

    "test_reconstruction_mean": test_mean,
    "test_reconstruction_median": test_median,

    "threshold_95": threshold_95,
    "threshold_99": threshold_99,

    "test_anomalies_95": test_anomalies_95,
    "test_anomaly_rate_95": test_anomaly_rate_95,

    "test_anomalies_99": test_anomalies_99,
    "test_anomaly_rate_99": test_anomaly_rate_99
}

metrics_path = os.path.join(
    REPORT_DIR,
    "temporal_model_metrics.json"
)

with open(
    metrics_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        metrics,
        f,
        indent=4
    )


# ============================================================
# SAVE FEATURE LIST
# ============================================================

feature_path = os.path.join(
    MODEL_DIR,
    "temporal_features.json"
)

with open(
    feature_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        feature_columns,
        f,
        indent=4
    )


# ============================================================
# COMPLETE
# ============================================================

print("\n" + "=" * 60)
print("TEMPORAL MODEL TRAINING COMPLETE")
print("=" * 60)

print(
    f"\nModel saved to:\n{MODEL_DIR}"
)

print(
    f"\nMetrics saved to:\n{metrics_path}"
)

print(
    f"\nScores saved to:\n{scores_path}"
)

print(
    "\nNext stage: model fusion + intelligence correlation."
)