"""
rebuild_model.py
================
Obtain a usable PhishGuard model.

The trained artifact (models/phishing_model.joblib) IS committed to git so the
Render Docker build always contains it. This script is the canonical way to
(Re)build it:

1. If a model already exists and `--force` is not passed, do nothing.
2. Otherwise ensure the dataset is present (downloads via the Kaggle CLI if
   available), then run the training pipeline (ml/train.py). After retraining,
   commit the regenerated models/*.joblib + models/*.json artifacts.

Usage:
    python scripts/rebuild_model.py            # rebuild only if missing
    python scripts/rebuild_model.py --force    # always retrain
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "models" / "phishing_model.joblib"
DATA = ROOT / "data" / "phishing_urls.csv"

KAGGLE_DATASET = "hemanthd007/phiusiil-phishing-url-dataset"


def _model_exists() -> bool:
    return MODEL.is_file() and MODEL.stat().st_size > 0


def _ensure_dataset() -> None:
    """Download the dataset via the Kaggle CLI if it is missing."""
    if DATA.is_file():
        print(f"Dataset found at '{DATA}'.")
        return

    print(f"Dataset missing at '{DATA}'. Attempting download...")
    if shutil.which("kaggle") is None:
        print(
            "The 'kaggle' CLI is not installed. Install it with "
            "`pip install kaggle`, add your API credentials (see "
            "https://github.com/Kaggle/kaggle-api), then re-run this script. "
            "Alternatively download the CSV manually into data/ as "
            "phishing_urls.csv (see data/README.md)."
        )
        sys.exit(1)

    os.makedirs(ROOT / "data", exist_ok=True)
    subprocess.run(
        ["kaggle", "datasets", "download", "-d", KAGGLE_DATASET, "-p", str(ROOT / "data")],
        check=True,
    )
    # Extract the zip (named after the dataset).
    zip_path = ROOT / "data" / "phiusiil-phishing-url-dataset.zip"
    if zip_path.is_file():
        shutil.unpack_archive(str(zip_path), str(ROOT / "data"))
        zip_path.unlink()
    print(f"Dataset ready at '{DATA}'.")


def main() -> int:
    if MODEL.exists() and "--force" not in sys.argv:
        print(f"Model already exists at '{MODEL}'. Use --force to retrain.")
        return 0

    _ensure_dataset()

    print("Running training pipeline (ml/train.py)...")
    subprocess.run([sys.executable, "ml/train.py"], cwd=str(ROOT), check=True)

    if _model_exists():
        print(f"Model ready at '{MODEL}'.")
        return 0
    print("Training completed but the model file was not produced.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
