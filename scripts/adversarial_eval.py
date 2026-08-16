"""
adversarial_eval.py
===================
Evaluate PhishGuard's robustness against common URL obfuscation tricks that
attackers use to evade detection.

Applies deterministic perturbations to a sample of real phishing and
legitimate URLs, then measures how often the model still flags the phishing
URLs (evasion rate) and whether perturbing legitimate URLs causes false
positives.

Usage:
    python scripts/adversarial_eval.py                 # default: 2000 samples
    python scripts/adversarial_eval.py --samples 5000  # more samples

Requires:
    - A trained model at models/phishing_model.joblib
    - The dataset at data/phishing_urls.csv
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.feature_extractor import FeatureExtractor

MODEL_PATH = os.path.join("models", "phishing_model.joblib")
DATA_PATH = os.path.join("data", "phishing_urls.csv")

# Perturbations that mimic real attacker evasion. Each is a pure string
# transform — no network access.
LEET_MAP = {"o": "0", "i": "1", "a": "4", "e": "3", "l": "1"}
SUSPICIOUS_PATH_TOKEN = "/secure-login"
BENIGN_SUBDOMAIN = "webmail."


def _perturb_leet(url: str) -> str:
    """Replace look-alike letters in the second-level domain (e.g. o->0)."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if ":" in host:
        host, _, port = host.partition(":")
        port = ":" + port
    else:
        port = ""
    parts = host.split(".")
    if len(parts) >= 2:
        sld = parts[-2]
        parts[-2] = "".join(LEET_MAP.get(ch, ch) for ch in sld)
    new_host = ".".join(parts) + port
    return parsed._replace(netloc=new_host).geturl()


def _perturb_hex_encode(url: str) -> str:
    """Percent-encode the first letter of the second-level domain."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if ":" in host:
        host, _, port = host.partition(":")
        port = ":" + port
    else:
        port = ""
    parts = host.split(".")
    if len(parts) >= 2 and parts[-2]:
        sld = parts[-2]
        parts[-2] = "%" + format(ord(sld[0]), "02x") + sld[1:]
    new_host = ".".join(parts) + port
    return parsed._replace(netloc=new_host).geturl()


def _perturb_token_padding(url: str) -> str:
    """Append a suspicious 'secure-login' token to the path."""
    parsed = urlparse(url)
    path = parsed.path if parsed.path.endswith("/") else parsed.path + "/"
    return parsed._replace(path=path + SUSPICIOUS_PATH_TOKEN.lstrip("/")).geturl()


def _perturb_benign_subdomain(url: str) -> str:
    """Prefix the host with a benign-looking subdomain."""
    parsed = urlparse(url)
    return parsed._replace(netloc=BENIGN_SUBDOMAIN + parsed.netloc).geturl()


PERTURBATIONS: dict[str, object] = {
    "leet_sld": _perturb_leet,
    "hex_encoded_sld": _perturb_hex_encode,
    "suspicious_token_padding": _perturb_token_padding,
    "benign_subdomain_prefix": _perturb_benign_subdomain,
}


def _load_dataset(n_samples: int) -> tuple[pd.DataFrame, str, str]:
    df = pd.read_csv(DATA_PATH)
    url_col = "URL" if "URL" in df.columns else df.columns[0]
    label_col = "label" if "label" in df.columns else df.columns[-1]
    df = df[[url_col, label_col]].dropna()
    if len(df) > n_samples:
        df = df.sample(n=n_samples, random_state=42)
    return df.reset_index(drop=True), url_col, label_col


def _evaluate(model, extractor: FeatureExtractor, urls: list[str], y: np.ndarray) -> dict:
    """Return metrics on a set of (url, label) pairs; y=1 means phishing."""
    if not urls:
        return {
            "accuracy": float("nan"),
            "precision": float("nan"),
            "recall": float("nan"),
            "f1": float("nan"),
            "n": 0,
        }
    X = np.array([extractor.extract_as_list(u) for u in urls])
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)

    tp = int(np.sum((pred == 1) & (y == 1)))
    fp = int(np.sum((pred == 1) & (y == 0)))
    fn = int(np.sum((pred == 0) & (y == 1)))
    tn = int(np.sum((pred == 0) & (y == 0)))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "n": len(urls),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=2000, help="URLs sampled per class")
    args = parser.parse_args()

    if not os.path.exists(MODEL_PATH):
        print(f"Error: model not found at '{MODEL_PATH}'. Run scripts/rebuild_model.py first.")
        return 1
    if not os.path.exists(DATA_PATH):
        print(f"Error: dataset not found at '{DATA_PATH}'.")
        return 1

    model = joblib.load(MODEL_PATH)
    extractor = FeatureExtractor()

    df, url_col, label_col = _load_dataset(args.samples)
    # Raw label semantics: 0 = phishing, 1 = legitimate (see ml/train.py).
    y = (df[label_col] == 0).astype(int).to_numpy()
    urls = df[url_col].astype(str).tolist()

    phishing = [(u, 1) for u, yi in zip(urls, y, strict=False) if yi == 1]
    legitimate = [(u, 0) for u, yi in zip(urls, y, strict=False) if yi == 0]

    print("=" * 68)
    print("PhishGuard — Adversarial Robustness Evaluation")
    print("=" * 68)
    print(f"Phishing URLs sampled:    {len(phishing)}")
    print(f"Legitimate URLs sampled:  {len(legitimate)}")
    print(f"Model: {MODEL_PATH}\n")

    print(f"{'Perturbation':<26} {'Phish F1':>9} {'Evasion%':>9} {'Legit FP%':>10}")
    print("-" * 68)

    results = {"baseline": {}}

    # Baseline (clean URLs)
    start = time.time()
    base_f1 = _evaluate(model, extractor, [u for u, _ in phishing], np.ones(len(phishing)))["f1"]
    legit_fp = _evaluate(model, extractor, [u for u, _ in legitimate], np.zeros(len(legitimate)))
    results["baseline"] = {"phishing_f1": base_f1, "legit_fp_rate": 1.0 - legit_fp["accuracy"]}
    print(
        f"{'baseline (clean)':<26} {base_f1:>9.4f} {0.0:>9.1f} {1.0 - legit_fp['accuracy']:>10.1%}"
    )

    for name, perturb in PERTURBATIONS.items():
        p_phish = [perturb(u) for u, _ in phishing]
        p_legit = [perturb(u) for u, _ in legitimate]

        p_f1 = _evaluate(model, extractor, p_phish, np.ones(len(phishing)))["f1"]
        p_legit_eval = _evaluate(model, extractor, p_legit, np.zeros(len(legitimate)))

        # Evasion rate: phishing URLs that dropped below the 0.5 threshold.
        X_p = np.array([extractor.extract_as_list(u) for u in p_phish])
        proba = model.predict_proba(X_p)[:, 1]
        evasion = float(np.mean(proba < 0.5))

        fp_rate = 1.0 - p_legit_eval["accuracy"]
        print(f"{name:<26} {p_f1:>9.4f} {evasion:>9.1%} {fp_rate:>10.1%}")
        results[name] = {
            "phishing_f1": p_f1,
            "evasion_rate": round(evasion, 4),
            "legit_fp_rate": round(fp_rate, 4),
        }

    print("-" * 68)
    print(f"Completed in {time.time() - start:.1f}s")

    report_path = os.path.join("models", "adversarial_report.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Report written to '{report_path}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
