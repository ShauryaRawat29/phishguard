"""
train.py
========
End-to-end model training script for PhishGuard.

1. Loads raw dataset from data/phishing_urls.csv.
2. Extracts 33 URL features using ml.feature_extractor.FeatureExtractor.
3. Splits data into Train (70%), Validation (15%), and Test (15%) sets, then
   carves a calibration split out of the training set.
4. Trains Logistic Regression, Random Forest, and XGBoost models.
5. Evaluates model performance (Accuracy, Precision, Recall, F1-score, ROC-AUC).
6. Selects and serializes the best model to models/phishing_model.joblib.
7. Fits an isotonic probability calibrator (models/calibrator.joblib) so the
   deployed confidence values are well-calibrated, and reports before/after
   Brier score and log loss on the held-out test set.

Usage:
    python ml/train.py
"""

import argparse
import json
import os
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, train_test_split
from xgboost import XGBClassifier

# Ensure root path is accessible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.feature_extractor import FeatureExtractor


def main():
    print("=" * 60)
    print("[PhishGuard] Model Training & Pipeline Execution")
    print("=" * 60)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--samples",
        type=int,
        default=None,
        help="Max URLs to train on (default: use the full dataset)",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=os.path.join("data", "phishing_urls.csv"),
        help="Path to the (url, label) training CSV (default: data/phishing_urls.csv)",
    )
    parser.add_argument(
        "--tune",
        action="store_true",
        help="Run XGBoost hyperparameter search (GridSearchCV) before training",
    )
    parser.add_argument(
        "--tune-samples",
        type=int,
        default=30000,
        help="Max URLs to use for hyperparameter search (default: 30000)",
    )
    args = parser.parse_args()

    data_path = args.dataset
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at '{data_path}'. Please download it first.")
        sys.exit(1)

    print(f"Loading dataset from '{data_path}'...")
    df = pd.read_csv(data_path)
    print(f"   Dataset shape: {df.shape}")

    # Standardize URL and label columns
    url_col = "URL" if "URL" in df.columns else df.columns[0]
    label_col = "label" if "label" in df.columns else df.columns[-1]

    # Optionally cap the number of URLs used for training. With no cap, the
    # full dataset (~235k URLs) is used for maximum model quality.
    if args.samples is not None and len(df) > args.samples:
        print(f"   Sampling {args.samples} URLs (--samples flag)...")
        df = df.sample(n=args.samples, random_state=42).reset_index(drop=True)

    print(f"Extracting 33 features for {len(df)} URLs using FeatureExtractor...")
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
    raw_y = df[label_col].values

    # In PhiUSIIL dataset: label 0 = Phishing, label 1 = Legitimate.
    # Convert target so: y = 1 (PHISHING), y = 0 (LEGITIMATE)
    y = (raw_y == 0).astype(int)
    print(f"Target distribution: Phishing (1)={np.sum(y == 1)}, Legitimate (0)={np.sum(y == 0)}")

    # Stratified Train (70%) / Validation (15%) / Test (15%)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    # Carve a calibration split out of the training set. The calibration
    # targets must be data the winning model has NOT seen, otherwise the
    # fitted probabilities would be overconfident and the calibration skewed.
    X_train, X_cal, y_train, y_cal = train_test_split(
        X_train, y_train, test_size=0.20, random_state=42, stratify=y_train
    )

    print("\nData Splits:")
    print(f"   Train set:        {X_train.shape[0]} samples")
    print(f"   Calibration set:  {X_cal.shape[0]} samples")
    print(f"   Validation set:   {X_val.shape[0]} samples")
    print(f"   Test set:         {X_test.shape[0]} samples")

    # Optional XGBoost hyperparameter search on a capped sample of the
    # training set (keeps grid search fast while spanning the class balance).
    # Default XGBoost params are the established GridSearchCV best (Phase 8):
    # learning_rate=0.05, max_depth=6, n_estimators=200. Baking them in as
    # defaults keeps `python ml/train.py` and `scripts/rebuild_model.py` (which
    # does not pass --tune) reproducing the production model. Re-tune with
    # --tune if the dataset changes materially.
    xgb_params = {"n_estimators": 200, "max_depth": 6, "learning_rate": 0.05}
    if args.tune:
        print("\nRunning XGBoost hyperparameter search (GridSearchCV)...")
        tune_df = df.sample(n=min(args.tune_samples, len(df)), random_state=42)
        tune_X = np.array([extractor.extract_as_list(str(u)) for u in tune_df[url_col].values])
        tune_y = (tune_df[label_col].values == 0).astype(int)
        param_grid = {
            "max_depth": [4, 6, 8],
            "n_estimators": [100, 200],
            "learning_rate": [0.05, 0.1],
        }
        grid = GridSearchCV(
            XGBClassifier(random_state=42, n_jobs=-1),
            param_grid=param_grid,
            cv=3,
            scoring="f1",
            n_jobs=-1,
            verbose=1,
        )
        grid.fit(tune_X, tune_y)
        xgb_params = grid.best_params_
        print(f"   Best XGBoost params: {xgb_params}")
        print(f"   Best CV F1: {grid.best_score_:.4f}")

    # Models to evaluate
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=15, random_state=42, n_jobs=-1
        ),
        "XGBoost": XGBClassifier(random_state=42, n_jobs=-1, **xgb_params),
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
        y_val_proba = (
            model.predict_proba(X_val)[:, 1] if hasattr(model, "predict_proba") else y_val_pred
        )

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

        print(
            f"   -> {name} | F1: {f1:.4f} | Accuracy: {acc:.4f} | Recall: {rec:.4f} | Time: {fit_time:.2f}s"
        )

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

    # Probability calibration: fit a monotonic isotonic transform mapping raw
    # model scores -> calibrated phishing probabilities. The transform is
    # fitted on the held-out calibration split (never the test set).
    print("\nFitting isotonic probability calibration...")
    cal_scores = best_model.predict_proba(X_cal)[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(cal_scores, y_cal)

    # Evaluate the calibrated probabilities on the test set: Brier score and
    # log loss should drop (better calibration) while ranking is preserved
    # (isotonic is monotonic, so AUC is unchanged).
    y_test_proba_cal = calibrator.predict(y_test_proba)
    y_test_proba_cal = np.clip(y_test_proba_cal, 0.0, 1.0)
    y_test_pred_cal = (y_test_proba_cal >= 0.5).astype(int)

    raw_brier = brier_score_loss(y_test, y_test_proba)
    cal_brier = brier_score_loss(y_test, y_test_proba_cal)
    raw_ll = log_loss(y_test, y_test_proba)
    cal_ll = log_loss(y_test, y_test_proba_cal)
    cal_acc = accuracy_score(y_test, y_test_pred_cal)
    cal_f1 = f1_score(y_test, y_test_pred_cal, zero_division=0)

    print(f"   Brier score        raw={raw_brier:.4f} -> calibrated={cal_brier:.4f}")
    print(f"   Log loss           raw={raw_ll:.4f} -> calibrated={cal_ll:.4f}")
    print(f"   Calibrated test accuracy: {cal_acc:.4f} | F1: {cal_f1:.4f}")

    # Save artifacts
    os.makedirs("models", exist_ok=True)
    model_output_path = os.path.join("models", "phishing_model.joblib")
    joblib.dump(best_model, model_output_path)
    print(f"\nSerialized model saved to '{model_output_path}'")

    calibrator_path = os.path.join("models", "calibrator.joblib")
    joblib.dump(calibrator, calibrator_path)
    print(f"Serialized calibrator saved to '{calibrator_path}'")

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
        "calibration": {
            "method": "isotonic",
            "calibration_split": int(X_cal.shape[0]),
            "brier_score": {
                "raw": round(raw_brier, 4),
                "calibrated": round(cal_brier, 4),
            },
            "log_loss": {
                "raw": round(raw_ll, 4),
                "calibrated": round(cal_ll, 4),
            },
            "test_accuracy_calibrated": round(cal_acc, 4),
            "test_f1_calibrated": round(cal_f1, 4),
        },
        "all_model_comparison": results,
    }
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata saved to '{metadata_path}'")
    print("\nTraining Pipeline Successfully Executed!")


if __name__ == "__main__":
    main()
