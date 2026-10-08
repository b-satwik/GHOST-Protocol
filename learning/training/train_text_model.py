from pathlib import Path
import json
import numpy as np
import pandas as pd
import torch

from torch.utils.data import DataLoader, Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    DataCollatorWithPadding,
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support


# ============================================================
# PATHS
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_DIR / "data" / "processed" / "training"
MODEL_DIR = PROJECT_DIR / "models" / "dwdata_text_model"
REPORT_DIR = PROJECT_DIR / "reports" / "training"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# CPU TEST CONFIG
# ============================================================

MODEL_NAME = "distilbert-base-uncased"

# Small CPU experiment
MAX_TRAIN_SAMPLES = 5000
MAX_VAL_SAMPLES = 1000
MAX_TEST_SAMPLES = 1000

MAX_LENGTH = 96

TRAIN_BATCH_SIZE = 4
EVAL_BATCH_SIZE = 8

EPOCHS = 1
LEARNING_RATE = 2e-5

SEED = 42

torch.manual_seed(SEED)
np.random.seed(SEED)


# ============================================================
# DEVICE
# ============================================================

DEVICE = torch.device("cpu")

print("=" * 60)
print("DARKWATCH-XAI TEXT MODEL")
print("CPU PROTOTYPE TRAINING")
print("=" * 60)

print("Device : CPU")
print("This is a small prototype run.")
print("Full training should later run on a GPU.")


# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading datasets...")

train_df = pd.read_csv(
    DATA_DIR / "text_train.csv",
    low_memory=False
)

val_df = pd.read_csv(
    DATA_DIR / "text_validation.csv",
    low_memory=False
)

test_df = pd.read_csv(
    DATA_DIR / "text_test.csv",
    low_memory=False
)

print(f"Original train      : {len(train_df):,}")
print(f"Original validation : {len(val_df):,}")
print(f"Original test       : {len(test_df):,}")


# ============================================================
# SAMPLE DATA
# ============================================================

train_df = train_df.sample(
    n=min(MAX_TRAIN_SAMPLES, len(train_df)),
    random_state=SEED
).reset_index(drop=True)

val_df = val_df.sample(
    n=min(MAX_VAL_SAMPLES, len(val_df)),
    random_state=SEED
).reset_index(drop=True)

test_df = test_df.sample(
    n=min(MAX_TEST_SAMPLES, len(test_df)),
    random_state=SEED
).reset_index(drop=True)

print("\nPrototype dataset:")
print(f"Train      : {len(train_df):,}")
print(f"Validation : {len(val_df):,}")
print(f"Test       : {len(test_df):,}")


# ============================================================
# LABEL MAP
# ============================================================

with open(
    DATA_DIR / "text_label_map.json",
    "r",
    encoding="utf-8"
) as f:
    label_info = json.load(f)

label_to_id = {
    k: int(v)
    for k, v in label_info["label_to_id"].items()
}

id_to_label = {
    int(k): v
    for k, v in label_info["id_to_label"].items()
}

NUM_LABELS = len(label_to_id)

print(f"Classes    : {NUM_LABELS}")


# ============================================================
# CLEAN
# ============================================================

def clean(df):

    df = df.copy()

    df["text"] = (
        df["text"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    df["label_id"] = (
        pd.to_numeric(
            df["label_id"],
            errors="coerce"
        )
        .fillna(0)
        .astype(int)
    )

    return df[
        ["text", "label_id"]
    ]


train_df = clean(train_df)
val_df = clean(val_df)
test_df = clean(test_df)


# ============================================================
# TOKENIZER
# ============================================================

print("\nLoading tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME
)


# ============================================================
# DATASET
# ============================================================

class TextDataset(Dataset):

    def __init__(
        self,
        dataframe
    ):

        self.texts = dataframe[
            "text"
        ].tolist()

        self.labels = dataframe[
            "label_id"
        ].tolist()

    def __len__(self):

        return len(self.texts)

    def __getitem__(self, index):

        encoding = tokenizer(
            self.texts[index],
            truncation=True,
            max_length=MAX_LENGTH,
            padding=False,
            return_tensors="pt"
        )

        item = {
            key: value.squeeze(0)
            for key, value in encoding.items()
        }

        item["labels"] = torch.tensor(
            self.labels[index],
            dtype=torch.long
        )

        return item


train_dataset = TextDataset(train_df)
val_dataset = TextDataset(val_df)
test_dataset = TextDataset(test_df)


# ============================================================
# COLLATOR
# ============================================================

collator = DataCollatorWithPadding(
    tokenizer=tokenizer
)


def collate_fn(batch):

    labels = torch.stack(
        [
            item.pop("labels")
            for item in batch
        ]
    )

    batch = collator(batch)

    batch["labels"] = labels

    return batch


# ============================================================
# DATALOADERS
# ============================================================

train_loader = DataLoader(
    train_dataset,
    batch_size=TRAIN_BATCH_SIZE,
    shuffle=True,
    collate_fn=collate_fn,
    num_workers=0
)

val_loader = DataLoader(
    val_dataset,
    batch_size=EVAL_BATCH_SIZE,
    shuffle=False,
    collate_fn=collate_fn,
    num_workers=0
)

test_loader = DataLoader(
    test_dataset,
    batch_size=EVAL_BATCH_SIZE,
    shuffle=False,
    collate_fn=collate_fn,
    num_workers=0
)


# ============================================================
# MODEL
# ============================================================

print("\nLoading DistilBERT...")

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=NUM_LABELS,
    id2label=id_to_label,
    label2id=label_to_id
)

model.to(DEVICE)


# ============================================================
# OPTIMIZER
# ============================================================

optimizer = torch.optim.AdamW(
    model.parameters(),
    lr=LEARNING_RATE
)


# ============================================================
# LOSS
# ============================================================

loss_function = torch.nn.CrossEntropyLoss()


# ============================================================
# EVALUATION
# ============================================================

def evaluate(loader):

    model.eval()

    predictions = []
    labels_all = []

    total_loss = 0

    with torch.no_grad():

        for batch in loader:

            input_ids = batch[
                "input_ids"
            ].to(DEVICE)

            attention_mask = batch[
                "attention_mask"
            ].to(DEVICE)

            labels = batch[
                "labels"
            ].to(DEVICE)

            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask
            )

            loss = loss_function(
                outputs.logits,
                labels
            )

            total_loss += loss.item()

            pred = torch.argmax(
                outputs.logits,
                dim=-1
            )

            predictions.extend(
                pred.cpu().numpy()
            )

            labels_all.extend(
                labels.cpu().numpy()
            )

    accuracy = accuracy_score(
        labels_all,
        predictions
    )

    precision, recall, f1, _ = (
        precision_recall_fscore_support(
            labels_all,
            predictions,
            average="weighted",
            zero_division=0
        )
    )

    return {
        "loss": total_loss / len(loader),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }


# ============================================================
# TRAIN
# ============================================================

print("\n")
print("=" * 60)
print("STARTING TRAINING")
print("=" * 60)

best_f1 = -1

for epoch in range(EPOCHS):

    model.train()

    running_loss = 0

    for step, batch in enumerate(
        train_loader,
        start=1
    ):

        input_ids = batch[
            "input_ids"
        ].to(DEVICE)

        attention_mask = batch[
            "attention_mask"
        ].to(DEVICE)

        labels = batch[
            "labels"
        ].to(DEVICE)

        optimizer.zero_grad()

        outputs = model(
            input_ids=input_ids,
            attention_mask=attention_mask
        )

        loss = loss_function(
            outputs.logits,
            labels
        )

        loss.backward()

        optimizer.step()

        running_loss += loss.item()

        if step % 100 == 0:

            print(
                f"Epoch {epoch + 1} "
                f"| Step {step}/{len(train_loader)} "
                f"| Loss "
                f"{running_loss / step:.4f}"
            )

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    metrics = evaluate(
        val_loader
    )

    print("\nValidation")

    print(
        f"Loss      : {metrics['loss']:.4f}"
    )

    print(
        f"Accuracy  : {metrics['accuracy']:.4f}"
    )

    print(
        f"Precision : {metrics['precision']:.4f}"
    )

    print(
        f"Recall    : {metrics['recall']:.4f}"
    )

    print(
        f"F1        : {metrics['f1']:.4f}"
    )

    if metrics["f1"] > best_f1:

        best_f1 = metrics["f1"]

        print("\nSaving best model...")

        model.save_pretrained(
            MODEL_DIR
        )

        tokenizer.save_pretrained(
            MODEL_DIR
        )


# ============================================================
# TEST
# ============================================================

print("\n")
print("=" * 60)
print("FINAL TEST")
print("=" * 60)

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_DIR
)

model.to(DEVICE)

test_metrics = evaluate(
    test_loader
)

print(
    f"Accuracy  : {test_metrics['accuracy']:.4f}"
)

print(
    f"Precision : {test_metrics['precision']:.4f}"
)

print(
    f"Recall    : {test_metrics['recall']:.4f}"
)

print(
    f"F1        : {test_metrics['f1']:.4f}"
)


# ============================================================
# SAVE REPORT
# ============================================================

report = {
    "model": MODEL_NAME,
    "device": "cpu",
    "train_samples": len(train_df),
    "validation_samples": len(val_df),
    "test_samples": len(test_df),
    "classes": NUM_LABELS,
    "epochs": EPOCHS,
    "test_metrics": test_metrics
}

with open(
    REPORT_DIR / "text_model_metrics.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        report,
        f,
        indent=2,
        default=float
    )


print("\n")
print("=" * 60)
print("TEXT MODEL TRAINING COMPLETE")
print("=" * 60)

print("\nModel:")
print(MODEL_DIR)

print("\nReport:")
print(
    REPORT_DIR /
    "text_model_metrics.json"
)