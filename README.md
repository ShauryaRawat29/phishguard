# 🛡️ PhishGuard — AI-Powered Phishing URL Detection

> Analyzes URLs using machine learning and explains exactly *why* a URL is suspicious.

[![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-green)]()

**PhishGuard** is a full-stack cybersecurity web application that uses a machine learning model (XGBoost + SHAP) to classify URLs as **legitimate** or **phishing**, and provides a human-readable explanation of the prediction.

---

> ✅ **Stable:** PhishGuard is feature-complete and deployed. See the
> [roadmap](ROADMAP.md) for planned improvements.

---

## Quick Links

- 🌐 **Live UI:** [shauryarawat29.github.io/phishguard](https://shauryarawat29.github.io/phishguard)
- 🛰️ **Live API:** `https://phishguard-api-dkoj.onrender.com` (health: `/api/health`)
- 📖 **API Docs:** Interactive Swagger UI at `/docs` (enabled by default locally at
  `http://localhost:8000/docs`; gated off in production via `DOCS_ENABLED`)
- 📓 **ML Notebook:** `notebooks/phishing_detection.ipynb`

---

## What It Does

1. You enter a URL into the web interface
2. The system extracts 33 structural and lexical features from the URL
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
The production model is committed to the repo at `models/phishing_model.joblib`,
so no download is needed. If you want to retrain it from scratch:

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

## Deployment

PhishGuard ships with free-tier deployment config for both halves of the app:

### API — Render (free)

1. Push this repo to GitHub.
2. Go to [render.com](https://render.com) → **New** → **Blueprint**, and point it
   at this repo. Render reads `render.yaml` and creates the `phishguard-api`
   web service automatically.
3. Set the `CORS_ORIGINS` environment variable to your GitHub Pages URL
   (e.g. `https://shauryarawat29.github.io`) in the Render dashboard.
4. Set `TRUST_PROXY_HEADERS=true` (already the default in `render.yaml`) so rate
   limiting sees real client IPs behind the proxy.

The service uses the repo's `Dockerfile` and the committed model at
`models/phishing_model.joblib`. A health check runs against `/api/health`.

> Note: Render's free tier spins the service down after 15 minutes of
> inactivity; the first request after idle takes ~30-60s to respond (cold
> start). This is fine for a demo/portfolio project.

#### Keeping the free API warm (optional)

To avoid cold starts, ping the service at least every 10 minutes. Two free
options are included:

- **Built-in:** `.github/workflows/keep-warm.yml` pings `/api/health` on a cron
  schedule (every 10 minutes) using GitHub Actions — no extra account needed.
- **UptimeRobot:** create a free HTTP(S) monitor for
  `https://phishguard-api-dkoj.onrender.com/api/health` at a 5-minute interval.
  UptimeRobot also emails you if the service goes down.

Note: GitHub Actions only runs scheduled workflows for repos that have had
activity in the last 60 days, so an UptimeRobot monitor is the more reliable
long-term option for a dormant repo.

### UI — GitHub Pages (free)

1. In your repo: **Settings → Pages → Source: GitHub Actions**.
2. The `.github/workflows/pages.yml` workflow deploys the `docs/` mirror
   (synced from `frontend/`) on every push to `main`.
3. Enable **Pages → Deploy from a branch** as an alternative if you prefer
   `main` `/docs` instead of the Actions workflow.

The frontend calls the API at the same origin in production, so set the API
deployment to serve the UI too (FastAPI mounts `frontend/` automatically), or
point the GitHub Pages `CORS_ORIGINS` at your Pages URL.

---

## Security Notes

- The server **never** makes network requests to the URLs it analyzes — all
  feature extraction is lexical/structural, preventing SSRF.
- Rate limiting is applied per-IP on `POST /api/analyze`
  (`RATE_LIMIT_PER_MINUTE`). Behind a proxy set `TRUST_PROXY_HEADERS=true` and
  list your proxy in `TRUSTED_PROXY_IPS` so `X-Forwarded-For` cannot be spoofed
  by clients.
- Allowed Host headers are enforced with `TrustedHostMiddleware`
  (`TRUSTED_HOSTS`), preventing DNS-rebinding style header poisoning.
- HTTP responses carry hardened security headers:
  - `Strict-Transport-Security` (HSTS, over HTTPS only; `HSTS_ENABLED`)
  - `Content-Security-Policy` (self + Google Fonts + jsdelivr for the Pages UI;
    `frame-ancestors 'none'`)
  - `Cache-Control: no-store` and `Cross-Origin-Resource-Policy: same-origin`
    on API responses
- Interactive API docs (`/docs`, `/redoc`, `/openapi.json`) are disabled in
  production (`DOCS_ENABLED=false`) to hide the API surface.
- CORS rejects wildcard `*` origins in production (`CORS_ORIGINS`).
- Unsafe URI schemes (`file://`, `data:`, `javascript:`) are rejected.
- `pip-audit` runs in CI to catch vulnerable dependencies.

### Adversarial robustness

`scripts/adversarial_eval.py` measures how well the model resists common
evasion tricks — leet substitutions, hex/double-encoding, fullwidth unicode
homoglyphs, backslash-scheme tricks, `www-` sandwich typosquats, suspicious
token padding, and benign subdomain prefixes. Against the retrained
33-feature model (full 468,783-URL dataset), evasion succeeds in **<1%** of
adversarial samples while clean F1 stays at **0.9972**. Host-shape
perturbations (token padding, backslash tricks) produce conservative
false positives by design: an abnormal host or suspicious keyword in the
path flags the URL. Risk thresholds (`decision_threshold`,
`high_risk_threshold`, `low_risk_threshold`) are configurable via
`Settings` / `.env`.

---

## License

[MIT](LICENSE) © 2026 PhishGuard
