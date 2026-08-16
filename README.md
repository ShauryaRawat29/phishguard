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
2. The system extracts 27 structural and lexical features from the URL
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
├── models/              # Trained artifacts (gitignored — see scripts/rebuild_model.py)
├── backend/             # FastAPI application
│   ├── main.py          # App entry: middleware, routing, static mount
│   ├── config.py        # pydantic-settings configuration
│   ├── dependencies.py  # DI providers (predictor)
│   ├── rate_limit.py    # slowapi limiter + per-route limits
│   ├── routes/          # API endpoints
│   └── services/        # validator, predictor
├── frontend/            # Static web interface
├── data/                # Dataset (gitignored, see data/README.md to download)
├── docs/                # Mirror of frontend/ for GitHub Pages (keep in sync)
├── scripts/             # sync_docs.py, rebuild_model.py
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

### 4. Obtain the trained model
The model artifact is not committed. Download the dataset (see
[data/README.md](data/README.md)) and rebuild it, or retrain directly:

```bash
python scripts/rebuild_model.py    # downloads data if missing, then trains
# or, for faster iteration:
python ml/train.py
```

### 5. (Alternative) Run the ML pipeline interactively
Open `notebooks/phishing_detection.ipynb` in Jupyter and run all cells.

### 6. Start the backend
```bash
uvicorn backend.main:app --reload
```

### 7. Open the frontend
Open `frontend/index.html` in your browser, or visit `http://localhost:8000`
where FastAPI serves the UI directly.

---

## Development

```bash
pytest                       # run tests
ruff check .                 # lint
ruff format --check .        # format check
python scripts/sync_docs.py  # keep docs/ mirror in sync with frontend/
```

CI runs lint, format, tests (with coverage), and verifies the `docs/` mirror on
every push and pull request.

---

## Security Notes

- The server **never** makes network requests to the URLs it analyzes — all
  feature extraction is lexical/structural, preventing SSRF.
- Rate limiting is applied per-IP on `POST /api/analyze`
  (`RATE_LIMIT_PER_MINUTE`). Behind a proxy set `TRUST_PROXY_HEADERS=true`.
- HTTP responses carry hardened security headers.
- Unsafe URI schemes (`file://`, `data:`, `javascript:`) are rejected.

---

## License

[MIT](LICENSE) © 2026 PhishGuard
