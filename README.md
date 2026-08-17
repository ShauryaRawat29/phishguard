# PhishGuard

Detects phishing URLs with an XGBoost model and explains every verdict with SHAP values.

[![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-green)]()

This is my final-year minor project — a full-stack app that takes a URL, classifies
it as phishing or legitimate, and tells you *why*. It's live, so you can try it
without setting anything up:

- **UI:** [shauryarawat29.github.io/phishguard](https://shauryarawat29.github.io/phishguard)
- **API:** `https://phishguard-api-dkoj.onrender.com` (health check at `/api/health`)
- **API docs:** Swagger UI at `/docs` (enabled by default locally; gated off in production)

The idea was to build the whole pipeline end to end myself — feature extraction,
model training, a FastAPI backend, and a frontend that doesn't just give you a
"PHISHING / LEGIT" verdict but shows you exactly which signals pushed it one way
or the other.

## What it does

1. You paste a URL into the page.
2. The backend extracts 33 structural and lexical features — URL length, subdomain
   count, suspicious keywords, TLD type, entropy, brand-spoofing, that kind of thing.
3. An XGBoost model scores it as **PHISHING** or **LEGITIMATE**, with a confidence
   level that's calibrated (not just a raw model probability).
4. SHAP values explain which features drove the prediction, ranked by impact.

One important detail: the server **never visits** the URL you submit. All feature
extraction is done on the string itself. No DNS lookups, no HTTP fetches — which
also means no SSRF-style attack surface.

## Tech stack

| Layer | What I used |
|---|---|
| ML | Python, scikit-learn, XGBoost, SHAP |
| Backend | FastAPI, uvicorn, Pydantic |
| Frontend | Plain HTML, CSS, JS (no framework) |
| Deployment | Render.com (API) + GitHub Pages (UI) |

The frontend is intentionally dependency-free — just static files. (There's a bit
of vitest/eslint tooling in `frontend/` for the dev workflow, but it's not needed
to run or serve the app.)

## Project layout

```
phishguard/
├── ml/                  # feature extraction, training, explainability
├── notebooks/           # Jupyter pipeline notebook
├── models/              # trained artifacts (committed for deploy; retrain via scripts/rebuild_model.py)
├── backend/             # FastAPI app
│   ├── main.py          # entry point: middleware, routing, static mount
│   ├── config.py        # pydantic-settings config
│   ├── dependencies.py  # DI providers (predictor)
│   ├── routes/          # API endpoints
│   └── services/        # validator, predictor
├── frontend/            # static UI
├── data/                # dataset (gitignored — see data/README.md to download)
├── docs/                # mirror of frontend/ for GitHub Pages (keep in sync)
├── scripts/             # sync_docs.py, rebuild_model.py
└── tests/               # pytest suite
```

## Running it locally

You'll need Python 3.11+ and pip.

```bash
git clone https://github.com/ShauryaRawat29/phishguard.git
cd phishguard
python -m venv .venv
.venv\Scripts\activate    # Windows — or `source .venv/bin/activate` on macOS/Linux
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

The trained model is committed at `models/phishing_model.joblib`, so you can skip
training entirely. If you want to rebuild it from scratch:

```bash
python scripts/rebuild_model.py    # downloads the dataset if missing, then trains
# or, for quicker iteration:
python ml/train.py
```

Then start the backend:

```bash
uvicorn backend.main:app --reload
```

Open `http://localhost:8000` — FastAPI serves the frontend directly. (Or open
`frontend/index.html` as a static file, though you'll need the API running for
analyzes to work.)

There's also a Jupyter notebook (`notebooks/phishing_detection.ipynb`) that walks
through the whole ML pipeline interactively if you prefer that.

## Development

```bash
pytest                       # run tests
ruff check .                 # lint
ruff format --check .        # format check
python scripts/sync_docs.py  # keep docs/ mirror in sync with frontend/

# frontend tooling (optional, dev only)
cd frontend
npm install
npm test                     # vitest tests for frontend/logic.js
npm run lint                 # eslint
```

CI runs lint, format, tests (with coverage), and verifies the `docs/` mirror on
every push and PR.

## Deployment

Both halves have free-tier configs checked into the repo.

### API — Render

1. Push the repo to GitHub.
2. On [render.com](https://render.com), create a **Blueprint** and point it at the
   repo. Render reads `render.yaml` and sets up the `phishguard-api` service.
3. Set `CORS_ORIGINS` to your Pages URL (e.g. `https://shauryarawat29.github.io`).
4. `TRUST_PROXY_HEADERS=true` is the default in `render.yaml` — keep it so rate
   limiting sees real client IPs behind the proxy.

The service builds from the repo's `Dockerfile` and uses the committed model. The
image runs as a non-root user and has a `HEALTHCHECK` against `/api/health`.

One gotcha: Render's free tier sleeps the service after ~15 minutes idle, so the
first request after a nap takes 30–60s (cold start). Fine for a portfolio project.

To keep it warm there are two free options:
- `.github/workflows/keep-warm.yml` pings `/api/health` every 10 minutes via
  GitHub Actions.
- An [UptimeRobot](https://uptimerobot.com) monitor on
  `https://phishguard-api-dkoj.onrender.com/api/health` at a 5-minute interval.
  This one's the more reliable long-term pick — GitHub Actions stops running
  scheduled workflows after 60 days of repo inactivity.

### UI — GitHub Pages

1. Repo **Settings → Pages → Source: GitHub Actions**.
2. `.github/workflows/pages.yml` deploys the `docs/` mirror (synced from
   `frontend/`) on every push to `main`.

If you'd rather serve the UI from the API itself, FastAPI mounts `frontend/`
automatically — the Pages setup is just the zero-server option.

## Model notes

Honestly, the numbers are a bit ridiculous for such a simple feature set. The
model is trained on a 468,783-URL dataset and sits at **0.9973 test F1** with an
AUC of **0.9994**. I also ran an adversarial evaluation (`scripts/adversarial_eval.py`)
throwing leet substitutions, hex/double-encoding, fullwidth homoglyphs,
backslash-scheme tricks, `www-` typosquats and token padding at it — evasion
succeeds in **<1%** of samples.

The confidence values you see in the UI are calibrated with an isotonic regression
(`ml/train.py` saves `models/calibrator.joblib`), so a "94% phishing" is genuinely
~94% likely, not just a raw model score. Calibration improved test log-loss from
0.0147 to 0.0144. It's optional at runtime — if `CALIBRATOR_PATH` is missing, the
API falls back to raw probabilities.

## Security notes

- No network requests to analyzed URLs (SSRF-safe by design).
- Per-IP rate limiting on `POST /api/analyze` (`RATE_LIMIT_PER_MINUTE`). Behind a
  proxy, keep `TRUST_PROXY_HEADERS=true` and list the proxy in `TRUSTED_PROXY_IPS`
  so `X-Forwarded-For` can't be spoofed.
- `TrustedHostMiddleware` enforces allowed hosts (`TRUSTED_HOSTS`), preventing
  DNS-rebinding style header poisoning.
- Hardened response headers: HSTS (over HTTPS, `HSTS_ENABLED`), a Content-Security
  Policy (self + Google Fonts + jsdelivr for the Pages UI; `frame-ancestors 'none'`),
  `Cache-Control: no-store` and `Cross-Origin-Resource-Policy: same-origin`.
- `/docs`, `/redoc`, `/openapi.json` are disabled in production (`DOCS_ENABLED=false`)
  to keep the API surface small.
- CORS rejects wildcard `*` origins in production.
- Unsafe schemes (`file://`, `data:`, `javascript:`) are rejected.
- `pip-audit` runs in CI; Dependabot keeps Python and Actions deps updated.
- See [SECURITY.md](SECURITY.md) for how to report issues.

## License

[MIT](LICENSE) © 2026 PhishGuard
