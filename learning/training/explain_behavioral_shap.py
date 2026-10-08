import os
import json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib


# ============================================================
# DARKWATCH-XAI
# Behavioral Autoencoder XAI
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
    "dwdata_tabular_model"
)

REPORT_DIR = os.path.join(
    PROJECT_DIR,
    "reports",
    "xai"
)

FUSION_FILE = os.path.join(
    PROJECT_DIR,
    "reports",
    "training",
    "model_fusion_test.csv"
)

TABULAR_TEST = os.path.join(
    DATA_DIR,
    "tabular_test.csv"
)

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "model.pt"
)

FEATURE_FILE = os.path.join(
    MODEL_DIR,
    "features.json"
)

SCALER_FILE = os.path.join(
    MODEL_DIR,
    "scaler.joblib"
)

SUMMARY_FILE = os.path.join(
    REPORT_DIR,
    "behavioral_shap_summary.csv"
)

CASES_FILE = os.path.join(
    REPORT_DIR,
    "behavioral_shap_cases.csv"
)

IMPORTANCE_FILE = os.path.join(
    REPORT_DIR,
    "behavioral_feature_importance.csv"
)

TOP_CASES = 100


# ============================================================
# SETUP
# ============================================================

os.makedirs(
    REPORT_DIR,
    exist_ok=True
)

DEVICE = torch.device(
    "cuda" if torch.cuda.is_available()
    else "cpu"
)

print("=" * 70)
print("DARKWATCH-XAI BEHAVIORAL EXPLANATION")
print("=" * 70)

print(f"\nDevice: {DEVICE}")


# ============================================================
# VERIFY FILES
# ============================================================

required_files = [
    FUSION_FILE,
    TABULAR_TEST,
    MODEL_FILE,
    FEATURE_FILE,
    SCALER_FILE
]

for path in required_files:

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"\nRequired file not found:\n{path}"
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
            nn.Linear(
                input_dim,
                hidden1
            ),
            nn.ReLU(),

            nn.Linear(
                hidden1,
                hidden2
            ),
            nn.ReLU(),

            nn.Linear(
                hidden2,
                latent_dim
            )
        )

        self.decoder = nn.Sequential(
            nn.Linear(
                latent_dim,
                hidden2
            ),
            nn.ReLU(),

            nn.Linear(
                hidden2,
                hidden1
            ),
            nn.ReLU(),

            nn.Linear(
                hidden1,
                input_dim
            )
        )

    def forward(self, x):

        latent = self.encoder(x)

        reconstructed = self.decoder(
            latent
        )

        return reconstructed, latent


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading behavioral model...")

checkpoint = torch.load(
    MODEL_FILE,
    map_location=DEVICE,
    weights_only=False
)

state = checkpoint[
    "model_state_dict"
]

input_dim = int(
    checkpoint["input_dim"]
)

hidden1 = state[
    "encoder.0.weight"
].shape[0]

hidden2 = state[
    "encoder.2.weight"
].shape[0]

latent_dim = state[
    "encoder.4.weight"
].shape[0]

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
    f"Input features : {input_dim}"
)

print(
    f"Architecture   : "
    f"{input_dim} → "
    f"{hidden1} → "
    f"{hidden2} → "
    f"{latent_dim}"
)


# ============================================================
# LOAD FEATURE DEFINITIONS
# ============================================================

with open(
    FEATURE_FILE,
    "r",
    encoding="utf-8"
) as f:

    feature_meta = json.load(f)

behavioral_features = (
    feature_meta[
        "behavioral_features"
    ]
)

print(
    f"Behavioral features: "
    f"{len(behavioral_features)}"
)

if len(behavioral_features) != input_dim:

    raise ValueError(
        "\nFeature/model mismatch:\n"
        f"Model input: {input_dim}\n"
        f"Features: {len(behavioral_features)}"
    )


# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading test data...")

tabular_df = pd.read_csv(
    TABULAR_TEST
)

fusion_df = pd.read_csv(
    FUSION_FILE
)

print(
    f"Tabular records: "
    f"{len(tabular_df):,}"
)

print(
    f"Fusion records: "
    f"{len(fusion_df):,}"
)

if len(tabular_df) != len(
    fusion_df
):

    raise ValueError(
        "\nFusion and tabular test "
        "datasets have different lengths."
    )


# ============================================================
# LOAD SCALER
# ============================================================

scaler = joblib.load(
    SCALER_FILE
)

X = (
    tabular_df[
        behavioral_features
    ]
    .replace(
        [np.inf, -np.inf],
        np.nan
    )
    .fillna(0)
)

X_scaled = scaler.transform(
    X
).astype(
    np.float32
)


# ============================================================
# FIND TOP FUSION CASES
# ============================================================

if "fusion_score" not in fusion_df.columns:

    raise ValueError(
        "fusion_score column missing "
        "from model_fusion_test.csv"
    )

top_indices = (
    fusion_df[
        "fusion_score"
    ]
    .astype(float)
    .nlargest(
        min(
            TOP_CASES,
            len(fusion_df)
        )
    )
    .index
    .tolist()
)

print(
    f"\nSelected top "
    f"{len(top_indices)} "
    f"fusion cases for explanation."
)


# ============================================================
# MODEL RECONSTRUCTION
# ============================================================

print("\nCalculating feature-level reconstruction errors...")

X_tensor = torch.tensor(
    X_scaled,
    dtype=torch.float32
)

all_errors = []

BATCH_SIZE = 512

with torch.no_grad():

    for start in range(
        0,
        len(X_tensor),
        BATCH_SIZE
    ):

        batch = X_tensor[
            start:
            start + BATCH_SIZE
        ].to(DEVICE)

        reconstructed, _ = (
            model(batch)
        )

        errors = (
            reconstructed - batch
        ) ** 2

        all_errors.append(
            errors.cpu().numpy()
        )

all_errors = np.vstack(
    all_errors
)

print(
    f"Error matrix: "
    f"{all_errors.shape}"
)


# ============================================================
# RECONSTRUCTION ERROR VALIDATION
# ============================================================

row_errors = (
    all_errors.mean(
        axis=1
    )
)

print(
    f"\nMean reconstruction error: "
    f"{row_errors.mean():.6f}"
)

print(
    f"Median reconstruction error: "
    f"{np.median(row_errors):.6f}"
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

global_importance = (
    all_errors.mean(
        axis=0
    )
)

importance_df = pd.DataFrame({

    "feature":
        behavioral_features,

    "mean_squared_reconstruction_error":
        global_importance
})

importance_df[
    "importance_rank"
] = (
    importance_df[
        "mean_squared_reconstruction_error"
    ]
    .rank(
        ascending=False,
        method="min"
    )
    .astype(int)
)

importance_df = (
    importance_df
    .sort_values(
        "mean_squared_reconstruction_error",
        ascending=False
    )
)

importance_df.to_csv(
    IMPORTANCE_FILE,
    index=False
)


# ============================================================
# CREATE CASE EXPLANATIONS
# ============================================================

case_rows = []

for rank, index in enumerate(
    top_indices,
    start=1
):

    case_errors = (
        all_errors[index]
    )

    case_values = (
        X.iloc[index]
        .values
    )

    case_scaled = (
        X_scaled[index]
    )

    order = np.argsort(
        case_errors
    )[::-1]

    top_features = order[:10]

    fusion_row = (
        fusion_df.iloc[index]
    )

    for feature_rank, feature_idx in enumerate(
        top_features,
        start=1
    ):

        feature = (
            behavioral_features[
                feature_idx
            ]
        )

        original_value = (
            case_values[
                feature_idx
            ]
        )

        scaled_value = (
            case_scaled[
                feature_idx
            ]
        )

        error = (
            case_errors[
                feature_idx
            ]
        )

        case_rows.append({

            "case_rank":
                rank,

            "test_index":
                index,

            "feature_rank":
                feature_rank,

            "feature":
                feature,

            "feature_value":
                original_value,

            "scaled_value":
                scaled_value,

            "feature_reconstruction_error":
                float(error),

            "feature_error_share":
                float(
                    error /
                    (
                        case_errors.sum()
                        + 1e-12
                    )
                ),

            "total_behavioral_error":
                float(
                    row_errors[index]
                ),

            "fusion_score":
                float(
                    fusion_row[
                        "fusion_score"
                    ]
                ),

            "fusion_band":
                fusion_row.get(
                    "fusion_band",
                    ""
                ),

            "signal_agreement":
                fusion_row.get(
                    "signal_agreement",
                    ""
                ),

            "semantic_prediction":
                fusion_row.get(
                    "semantic_prediction",
                    ""
                ),

            "semantic_confidence":
                float(
                    fusion_row.get(
                        "semantic_confidence",
                        0
                    )
                )
        })


cases_df = pd.DataFrame(
    case_rows
)

cases_df.to_csv(
    CASES_FILE,
    index=False
)


# ============================================================
# CASE SUMMARY
# ============================================================

summary_rows = []

for rank, index in enumerate(
    top_indices,
    start=1
):

    case_errors = (
        all_errors[index]
    )

    order = np.argsort(
        case_errors
    )[::-1]

    top5 = order[:5]

    top_feature_names = [
        behavioral_features[i]
        for i in top5
    ]

    fusion_row = (
        fusion_df.iloc[index]
    )

    summary_rows.append({

        "case_rank":
            rank,

        "test_index":
            index,

        "record_id":
            fusion_row.get(
                "record_id",
                ""
            ),

        "snapshot_date":
            fusion_row.get(
                "snapshot_date",
                ""
            ),

        "vendor":
            fusion_row.get(
                "vendor",
                ""
            ),

        "marketplace":
            fusion_row.get(
                "marketplace",
                ""
            ),

        "category":
            fusion_row.get(
                "category",
                ""
            ),

        "fusion_score":
            float(
                fusion_row[
                    "fusion_score"
                ]
            ),

        "fusion_band":
            fusion_row.get(
                "fusion_band",
                ""
            ),

        "signal_agreement":
            fusion_row.get(
                "signal_agreement",
                ""
            ),

        "behavioral_error":
            float(
                row_errors[index]
            ),

        "semantic_prediction":
            fusion_row.get(
                "semantic_prediction",
                ""
            ),

        "semantic_confidence":
            float(
                fusion_row.get(
                    "semantic_confidence",
                    0
                )
            ),

        "top_feature_1":
            top_feature_names[0],

        "top_feature_2":
            top_feature_names[1],

        "top_feature_3":
            top_feature_names[2],

        "top_feature_4":
            top_feature_names[3],

        "top_feature_5":
            top_feature_names[4]
    })


summary_df = pd.DataFrame(
    summary_rows
)

summary_df.to_csv(
    SUMMARY_FILE,
    index=False
)


# ============================================================
# FINAL OUTPUT
# ============================================================

print("\n" + "=" * 70)
print("BEHAVIORAL XAI COMPLETE")
print("=" * 70)

print(
    f"\nCases explained: "
    f"{len(top_indices)}"
)

print(
    "\nTop global behavioral features:"
)

for _, row in (
    importance_df.head(10)
    .iterrows()
):

    print(
        f"  {row['importance_rank']:>2}. "
        f"{row['feature']:<35} "
        f"{row['mean_squared_reconstruction_error']:.6f}"
    )

print(
    "\nSaved:"
)

print(
    f"  {IMPORTANCE_FILE}"
)

print(
    f"  {CASES_FILE}"
)

print(
    f"  {SUMMARY_FILE}"
)

print(
    "\nBehavioral XAI stage completed."
)