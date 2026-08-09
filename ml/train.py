"""
train.py
========
End-to-end model training script for PhishGuard.

1. Loads raw dataset from data/phishing_urls.csv.
2. Extracts 25 URL features using ml.feature_extractor.FeatureExtractor.
3. Splits data into Train (70%), Validation (15%), and Test (15%) sets.
4. Trains Logistic Regression, Random Forest, and XGBoost models.
5. Evaluates model performance (Accuracy, Precision, Recall, F1-score, ROC-AUC).
6. Selects and serializes the best model to models/phishing_model.joblib.

Usage:
    python ml/train.py
"""

import json
import os
import sys
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Ensure root path is accessible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.feature_extractor import FeatureExtractor


def main():
    print("=" * 60)
    print("[PhishGuard] Model Training & Pipeline Execution")
    print("=" * 60)

    data_path = os.path.join("data", "phishing_urls.csv")
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at '{data_path}'. Please download it first.")
        sys.exit(1)

    print(f"Loading dataset from '{data_path}'...")
    df = pd.read_csv(data_path)
    print(f"   Dataset shape: {df.shape}")

    # Standardize URL and label columns
    url_col = "URL" if "URL" in df.columns else df.columns[0]
    label_col = "label" if "label" in df.columns else df.columns[-1]

    # Sample if dataset is very large for fast training iteration (e.g. 50,000 URLs)
    if len(df) > 50000:
        print("   Sampling 50,000 URLs for efficient training iteration...")
        df = df.sample(n=50000, random_state=42).reset_index(drop=True)

    print(f"Extracting 25 features for {len(df)} URLs using FeatureExtractor...")
    extractor = FeatureExtractor()
    start_time = time.time()

    feature_rows = []
    urls = df[url_col].values
    for i, url in enumerate(urls):
        try:
            feats = extractor.extract_as_list(str(url))
            feature_rows.append(feats)
        except Exception:
            # Fallback for malformed URLs in raw dataset
            feature_rows.append([0] * len(FeatureExtractor.FEATURE_NAMES))

        if (i + 1) % 10000 == 0:
            print(f"   Processed {i + 1}/{len(df)} URLs...")

    duration = time.time() - start_time
    print(f"Feature extraction complete in {duration:.2f}s!")

    X = np.array(feature_rows)
    y = df[label_col].values

    # Stratified Train (70%) / Validation (15%) / Test (15%)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"\nData Splits:")
    print(f"   Train set:      {X_train.shape[0]} samples")
    print(f"   Validation set: {X_val.shape[0]} samples")
    print(f"   Test set:       {X_test.shape[0]} samples")

    # Models to evaluate
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1),
        "XGBoost": XGBClassifier(n_estimators=150, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1),
    }

    best_model_name = None
    best_model = None
    best_f1 = -1.0
    results = {}

    print("\nTraining & Evaluating Candidate Models:")
    print("-" * 60)

    for name, model in models.items():
        print(f"   Training {name}...")
        t0 = time.time()
        model.fit(X_train, y_train)
        fit_time = time.time() - t0

        # Evaluate on validation set
        y_val_pred = model.predict(X_val)
        y_val_proba = model.predict_proba(X_val)[:, 1] if hasattr(model, "predict_proba") else y_val_pred

        acc = accuracy_score(y_val, y_val_pred)
        prec = precision_score(y_val, y_val_pred, zero_division=0)
        rec = recall_score(y_val, y_val_pred, zero_division=0)
        f1 = f1_score(y_val, y_val_pred, zero_division=0)
        auc = roc_auc_score(y_val, y_val_proba)

        results[name] = {
            "Accuracy": round(acc, 4),
            "Precision": round(prec, 4),
            "Recall": round(rec, 4),
            "F1-Score": round(f1, 4),
            "ROC-AUC": round(auc, 4),
            "Train_Time_s": round(fit_time, 2),
        }

        print(f"   -> {name} | F1: {f1:.4f} | Accuracy: {acc:.4f} | Recall: {rec:.4f} | Time: {fit_time:.2f}s")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = model

    print("-" * 60)
    print(f"Winning Model: {best_model_name} (Validation F1-Score: {best_f1:.4f})")

    # Evaluate Winner on Held-out Test Set
    print("\nEvaluating Winning Model on Held-out Test Set...")
    y_test_pred = best_model.predict(X_test)
    y_test_proba = best_model.predict_proba(X_test)[:, 1]

    test_acc = accuracy_score(y_test, y_test_pred)
    test_prec = precision_score(y_test, y_test_pred, zero_division=0)
    test_rec = recall_score(y_test, y_test_pred, zero_division=0)
    test_f1 = f1_score(y_test, y_test_pred, zero_division=0)
    test_auc = roc_auc_score(y_test, y_test_proba)

    print(f"   Test Set Accuracy:  {test_acc:.4f}")
    print(f"   Test Set Precision: {test_prec:.4f}")
    print(f"   Test Set Recall:    {test_rec:.4f}")
    print(f"   Test Set F1-Score:  {test_f1:.4f}")
    print(f"   Test Set ROC-AUC:   {test_auc:.4f}")

    # Save artifacts
    os.makedirs("models", exist_ok=True)
    model_output_path = os.path.join("models", "phishing_model.joblib")
    joblib.dump(best_model, model_output_path)
    print(f"\nSerialized model saved to '{model_output_path}'")

    feature_names_path = os.path.join("models", "feature_names.json")
    with open(feature_names_path, "w") as f:
        json.dump(FeatureExtractor.FEATURE_NAMES, f, indent=2)

    metadata_path = os.path.join("models", "model_metadata.json")
    metadata = {
        "model_type": best_model_name,
        "training_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "test_metrics": {
            "accuracy": round(test_acc, 4),
            "precision": round(test_prec, 4),
            "recall": round(test_rec, 4),
            "f1_score": round(test_f1, 4),
            "roc_auc": round(test_auc, 4),
        },
        "all_model_comparison": results,
    }
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata saved to '{metadata_path}'")
    print("\nTraining Pipeline Successfully Executed!")


if __name__ == "__main__":
    main()
