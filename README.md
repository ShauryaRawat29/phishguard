# 🛡️ PhishGuard — AI-Powered Phishing URL Detection

> Analyzes URLs using machine learning and explains exactly *why* a URL is suspicious.

[![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-In%20Development-orange)]()

**PhishGuard** is a full-stack cybersecurity web application that uses a machine learning model (XGBoost + SHAP) to classify URLs as **legitimate** or **phishing**, and provides a human-readable explanation of the prediction.

---

> 🚧 **This project is currently under active development.**  
> Documentation will be updated as each phase is completed.

---

## Quick Links

- 🌐 **Live Demo:** *(coming soon — Phase 12)*
- 📖 **API Docs:** *(coming soon — Phase 9)*
- 📓 **ML Notebook:** `notebooks/phishing_detection.ipynb`

---

## What It Does

1. You enter a URL into the web interface
2. The system extracts 25 structural and lexical features from the URL
3. An XGBoost model classifies it as **PHISHING** or **LEGITIMATE**
4. A risk score and confidence level are calculated
5. SHAP values explain *which features* drove the prediction

---

## Technology Stack

| Layer | Technology |
|---|---|
| ML Pipeline | Python, scikit-learn, XGBoost, SHAP |
| Backend API | FastAPI, uvicorn, Pydantic |
| Frontend | HTML, CSS, JavaScript |
| Deployment | Render.com (API) + GitHub Pages (UI) |

---

## Project Structure

```
phishguard/
├── ml/                  # Feature extraction, training, explainability
├── notebooks/           # Jupyter ML pipeline notebook
├── models/              # Trained model artifacts
├── backend/             # FastAPI application
├── frontend/            # Static web interface
├── data/                # Dataset (see data/README.md to download)
├── docs/                # Charts, diagrams, screenshots
└── tests/               # Unit and integration tests
```

---

## Getting Started (Local)

### Prerequisites
- Python 3.11+
- pip

### 1. Clone the repository
```bash
git clone https://github.com/ShauryaRawat29/phishguard.git
cd phishguard
```

### 2. Create a virtual environment
```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # macOS/Linux
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 4. Download the dataset
See [data/README.md](data/README.md) for instructions.

### 5. Run the ML pipeline
Open `notebooks/phishing_detection.ipynb` in Jupyter and run all cells.

### 6. Start the backend
```bash
uvicorn backend.main:app --reload
```

### 7. Open the frontend
Open `frontend/index.html` in your browser.

---

## License

[MIT](LICENSE) © 2026 PhishGuard
