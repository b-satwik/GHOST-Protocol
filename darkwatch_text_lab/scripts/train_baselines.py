#!/usr/bin/env python3
"""
DarkWatch Text Lab - Baselines Training Script
----------------------------------------------
Trains TF-IDF + Logistic Regression, Linear SVM, and XGBoost models
for Task A (DWData Activity) and Task B (CySecED Event).
Saves metrics and confusion matrices.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support

def get_lab_dirs(base_dir=None):
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return {
        "base": base_dir,
        "unified": os.path.join(base_dir, "data", "unified"),
        "models": os.path.join(base_dir, "models", "baselines"),
        "metrics": os.path.join(base_dir, "results", "metrics"),
        "confusion": os.path.join(base_dir, "results", "confusion_matrices")
    }

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
        "confusion_matrix": cm
    }

def train_baseline_models(task_name, df_task, label_col, vectorizer, labels, dirs):
    print(f"\nTraining Baselines for {task_name} ({len(labels)} classes)...")
    train_df = df_task[df_task["original_split"] == "train"].copy()
    val_df = df_task[df_task["original_split"] == "validation"].copy()
    test_df = df_task[df_task["original_split"] == "test"].copy()
    
    X_train_text = train_df["text"].fillna("").values
    y_train = train_df[label_col].values
    X_val_text = val_df["text"].fillna("").values
    y_val = val_df[label_col].values
    X_test_text = test_df["text"].fillna("").values
    y_test = test_df[label_col].values
    
    X_train_vec = vectorizer.fit_transform(X_train_text)
    X_val_vec = vectorizer.transform(X_val_text)
    X_test_vec = vectorizer.transform(X_test_text)
    
    label_to_idx = {l: i for i, l in enumerate(labels)}
    y_train_idx = np.array([label_to_idx[l] for l in y_train])
    y_val_idx = np.array([label_to_idx[l] for l in y_val])
    y_test_idx = np.array([label_to_idx[l] for l in y_test])
    numeric_labels = list(range(len(labels)))
    
    results = {}
    
    # 1. Logistic Regression
    print("  Fitting Logistic Regression...")
    lr = LogisticRegression(max_iter=300, class_weight="balanced", random_state=42)
    lr.fit(X_train_vec, y_train_idx)
    val_preds_lr = lr.predict(X_val_vec)
    test_preds_lr = lr.predict(X_test_vec)
    
    results["darkwatch_text_tfidf_lr"] = {
        "val_metrics": compute_metrics(y_val_idx, val_preds_lr, numeric_labels),
        "test_metrics": compute_metrics(y_test_idx, test_preds_lr, numeric_labels)
    }
    joblib.dump(lr, os.path.join(dirs["models"], f"{task_name.lower()}_tfidf_lr.joblib"))
    
    # 2. Linear SVM
    print("  Fitting Linear SVM...")
    svm = LinearSVC(class_weight="balanced", random_state=42, max_iter=2000)
    svm.fit(X_train_vec, y_train_idx)
    val_preds_svm = svm.predict(X_val_vec)
    test_preds_svm = svm.predict(X_test_vec)
    
    results["darkwatch_text_tfidf_svm"] = {
        "val_metrics": compute_metrics(y_val_idx, val_preds_svm, numeric_labels),
        "test_metrics": compute_metrics(y_test_idx, test_preds_svm, numeric_labels)
    }
    joblib.dump(svm, os.path.join(dirs["models"], f"{task_name.lower()}_tfidf_svm.joblib"))
    
    # 3. XGBoost
    print("  Fitting XGBoost...")
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
    val_preds_xgb_raw = xgb_clf.predict(X_val_vec)
    test_preds_xgb_raw = xgb_clf.predict(X_test_vec)
    val_preds_xgb = np.array([unique_train_classes[p] for p in val_preds_xgb_raw])
    test_preds_xgb = np.array([unique_train_classes[p] for p in test_preds_xgb_raw])
    
    results["darkwatch_text_tfidf_xgb"] = {
        "val_metrics": compute_metrics(y_val_idx, val_preds_xgb, numeric_labels),
        "test_metrics": compute_metrics(y_test_idx, test_preds_xgb, numeric_labels)
    }
    joblib.dump(xgb_clf, os.path.join(dirs["models"], f"{task_name.lower()}_tfidf_xgb.joblib"))
    joblib.dump(vectorizer, os.path.join(dirs["models"], f"{task_name.lower()}_vectorizer.joblib"))
    
    # Save outputs
    metrics_file = os.path.join(dirs["metrics"], f"{task_name.lower()}_baselines.json")
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump({"task": task_name, "labels": [str(l) for l in labels], "models": results}, f, indent=2)
        
    print(f"Saved baseline metrics to {metrics_file}")
    return results

def main(lab_base_dir=None):
    dirs = get_lab_dirs(lab_base_dir)
    unified_file = os.path.join(dirs["unified"], "darkwatch_unified_text.jsonl")
    
    records = []
    with open(unified_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    df = pd.DataFrame(records)
    
    # Task A
    df_dw = df[(df["source_dataset"] == "DWData") & (df["activity_label"].notna())].copy()
    dw_labels = sorted(df_dw["activity_label"].unique().tolist())
    dw_vec = TfidfVectorizer(max_features=5000, ngram_range=(1,2), sublinear_tf=True)
    res_a = train_baseline_models("TaskA_Activity", df_dw, "activity_label", dw_vec, dw_labels, dirs)
    
    # Task B
    df_dark = df[(df["source_dataset"] == "CYSECED_DARK") & (df["event_label"].notna())].copy()
    dark_labels = sorted(df_dark["event_label"].unique().tolist())
    dark_vec = TfidfVectorizer(max_features=5000, ngram_range=(1,2), sublinear_tf=True)
    res_b = train_baseline_models("TaskB_Event", df_dark, "event_label", dark_vec, dark_labels, dirs)

if __name__ == "__main__":
    main()
