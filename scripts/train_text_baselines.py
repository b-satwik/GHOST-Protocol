#!/usr/bin/env python3
"""
DarkWatch Text Baselines Training & Evaluation
----------------------------------------------
Trains research-quality baseline text models:
1. TF-IDF + Logistic Regression (darkwatch_text_tfidf_lr)
2. TF-IDF + Linear SVM (darkwatch_text_tfidf_svm)
3. TF-IDF + XGBoost (darkwatch_text_tfidf_xgb)

Tasks:
- Task A: DWData 29-class Activity Classification
- Task B: CySecED Dark 36-class Event Classification

Outputs saved to:
- models/text_unified/baselines/
- results/text_unified/baselines/
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNIFIED_JSONL = os.path.join(PROJECT_ROOT, "data", "unified", "darkwatch_unified_text.jsonl")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "text_unified", "baselines")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results", "text_unified", "baselines")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

def load_data():
    print("[1/4] Loading unified dataset for baseline training...")
    records = []
    with open(UNIFIED_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    df = pd.DataFrame(records)
    print(f"Total unified records loaded: {len(df)}")
    return df

def compute_metrics(y_true, y_pred, labels):
    acc = float(accuracy_score(y_true, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    
    report_dict = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    
    return {
        "accuracy": acc,
        "macro_precision": float(p_macro),
        "macro_recall": float(r_macro),
        "macro_f1": float(f1_macro),
        "weighted_precision": float(p_weighted),
        "weighted_recall": float(r_weighted),
        "weighted_f1": float(f1_weighted),
        "classification_report": report_dict,
        "confusion_matrix": cm,
        "labels": [str(l) for l in labels]
    }

def train_and_eval_task(task_name, df_task, label_col, vectorizer, labels):
    print(f"\n==========================================")
    print(f"  Task: {task_name} ({len(labels)} classes)")
    print(f"==========================================")
    
    train_df = df_task[df_task["original_split"] == "train"].copy()
    val_df = df_task[df_task["original_split"] == "validation"].copy()
    test_df = df_task[df_task["original_split"] == "test"].copy()
    
    print(f"Splits -> Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")
    
    X_train_text = train_df["text"].fillna("").values
    y_train = train_df[label_col].values
    
    X_val_text = val_df["text"].fillna("").values
    y_val = val_df[label_col].values
    
    X_test_text = test_df["text"].fillna("").values
    y_test = test_df[label_col].values
    
    print("Fitting TF-IDF Vectorizer...")
    X_train_vec = vectorizer.fit_transform(X_train_text)
    X_val_vec = vectorizer.transform(X_val_text)
    X_test_vec = vectorizer.transform(X_test_text)
    print(f"TF-IDF shape: {X_train_vec.shape}")
    
    label_to_idx = {l: i for i, l in enumerate(labels)}
    y_train_idx = np.array([label_to_idx[l] for l in y_train])
    y_val_idx = np.array([label_to_idx[l] for l in y_val])
    y_test_idx = np.array([label_to_idx[l] for l in y_test])
    numeric_labels = list(range(len(labels)))
    
    # 1. Logistic Regression
    print("\n--- Model 1: Logistic Regression ---")
    lr = LogisticRegression(max_iter=300, class_weight="balanced", n_jobs=-1, random_state=42)
    lr.fit(X_train_vec, y_train_idx)
    
    val_preds_lr = lr.predict(X_val_vec)
    test_preds_lr = lr.predict(X_test_vec)
    
    val_metrics_lr = compute_metrics(y_val_idx, val_preds_lr, numeric_labels)
    test_metrics_lr = compute_metrics(y_test_idx, test_preds_lr, numeric_labels)
    
    print(f"LR [{task_name}] Val Acc: {val_metrics_lr['accuracy']:.4f} | Val Macro F1: {val_metrics_lr['macro_f1']:.4f} | Val Weighted F1: {val_metrics_lr['weighted_f1']:.4f}")
    print(f"LR [{task_name}] Test Acc: {test_metrics_lr['accuracy']:.4f} | Test Macro F1: {test_metrics_lr['macro_f1']:.4f} | Test Weighted F1: {test_metrics_lr['weighted_f1']:.4f}")
    
    joblib.dump(lr, os.path.join(MODELS_DIR, f"{task_name.lower()}_tfidf_lr.joblib"))
    
    # 2. Linear SVM
    print("\n--- Model 2: Linear SVM ---")
    svm = LinearSVC(class_weight="balanced", random_state=42, max_iter=2000)
    svm.fit(X_train_vec, y_train_idx)
    
    val_preds_svm = svm.predict(X_val_vec)
    test_preds_svm = svm.predict(X_test_vec)
    
    val_metrics_svm = compute_metrics(y_val_idx, val_preds_svm, numeric_labels)
    test_metrics_svm = compute_metrics(y_test_idx, test_preds_svm, numeric_labels)
    
    print(f"SVM [{task_name}] Val Acc: {val_metrics_svm['accuracy']:.4f} | Val Macro F1: {val_metrics_svm['macro_f1']:.4f} | Val Weighted F1: {val_metrics_svm['weighted_f1']:.4f}")
    print(f"SVM [{task_name}] Test Acc: {test_metrics_svm['accuracy']:.4f} | Test Macro F1: {test_metrics_svm['macro_f1']:.4f} | Test Weighted F1: {test_metrics_svm['weighted_f1']:.4f}")
    
    joblib.dump(svm, os.path.join(MODELS_DIR, f"{task_name.lower()}_tfidf_svm.joblib"))
    
    # 3. XGBoost
    print("\n--- Model 3: XGBoost Classifier ---")
    unique_train_classes = np.unique(y_train_idx)
    xgb_num_class = len(unique_train_classes)
    train_class_map = {c: idx for idx, c in enumerate(unique_train_classes)}
    y_train_xgb = np.array([train_class_map[c] for c in y_train_idx])
    
    xgb_clf = xgb.XGBClassifier(
        n_estimators=30,
        max_depth=4,
        learning_rate=0.1,
        n_jobs=-1,
        random_state=42,
        tree_method="hist",
        objective="multi:softprob",
        num_class=xgb_num_class
    )
    xgb_clf.fit(X_train_vec, y_train_xgb)
    
    # Predict and map back
    val_preds_xgb_raw = xgb_clf.predict(X_val_vec)
    test_preds_xgb_raw = xgb_clf.predict(X_test_vec)
    val_preds_xgb = np.array([unique_train_classes[p] for p in val_preds_xgb_raw])
    test_preds_xgb = np.array([unique_train_classes[p] for p in test_preds_xgb_raw])
    
    val_metrics_xgb = compute_metrics(y_val_idx, val_preds_xgb, numeric_labels)
    test_metrics_xgb = compute_metrics(y_test_idx, test_preds_xgb, numeric_labels)
    
    print(f"XGB [{task_name}] Val Acc: {val_metrics_xgb['accuracy']:.4f} | Val Macro F1: {val_metrics_xgb['macro_f1']:.4f} | Val Weighted F1: {val_metrics_xgb['weighted_f1']:.4f}")
    print(f"XGB [{task_name}] Test Acc: {test_metrics_xgb['accuracy']:.4f} | Test Macro F1: {test_metrics_xgb['macro_f1']:.4f} | Test Weighted F1: {test_metrics_xgb['weighted_f1']:.4f}")
    
    joblib.dump(xgb_clf, os.path.join(MODELS_DIR, f"{task_name.lower()}_tfidf_xgb.joblib"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, f"{task_name.lower()}_vectorizer.joblib"))
    
    results = {
        "task_name": task_name,
        "class_labels": [str(l) for l in labels],
        "models": {
            "darkwatch_text_tfidf_lr": {
                "val_metrics": val_metrics_lr,
                "test_metrics": test_metrics_lr
            },
            "darkwatch_text_tfidf_svm": {
                "val_metrics": val_metrics_svm,
                "test_metrics": test_metrics_svm
            },
            "darkwatch_text_tfidf_xgb": {
                "val_metrics": val_metrics_xgb,
                "test_metrics": test_metrics_xgb
            }
        }
    }
    
    results_path = os.path.join(RESULTS_DIR, f"{task_name.lower()}_baselines_results.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nSaved baseline results to {results_path}")
    return results

def main():
    df = load_data()
    
    # Task A: DWData Activity Classification
    df_dw = df[(df["source_dataset"] == "DWData") & (df["activity_label"].notna())].copy()
    dw_labels = sorted(df_dw["activity_label"].unique().tolist())
    dw_vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1,2), sublinear_tf=True)
    task_a_res = train_and_eval_task("TaskA_DWData_Activity", df_dw, "activity_label", dw_vectorizer, dw_labels)
    
    # Task B: CySecED Dark Event Classification
    df_dark = df[(df["source_dataset"] == "CYSECED_DARK") & (df["event_label"].notna())].copy()
    dark_labels = sorted(df_dark["event_label"].unique().tolist())
    dark_vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1,2), sublinear_tf=True)
    task_b_res = train_and_eval_task("TaskB_CySecED_Event", df_dark, "event_label", dark_vectorizer, dark_labels)

if __name__ == "__main__":
    main()
