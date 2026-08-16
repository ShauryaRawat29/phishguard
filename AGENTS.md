# AGENTS.md — PhishGuard Developer Guide

Guidelines for AI agents and contributors working in this repository.

## Project Overview

PhishGuard is a full-stack cybersecurity web app that classifies URLs as
**phishing** or **legitimate** using an XGBoost model and explains each
prediction with SHAP values. The backend is FastAPI; the frontend is a static
single-page app (HTML/CSS/JS) that is also mirrored into `docs/` for GitHub
Pages deployment.

**Security invariant:** the server NEVER makes network requests to the URLs it
analyzes. Feature extraction is purely lexical/structural. Do not introduce
DNS lookups, HTTP fetches, or other SSRF-prone behavior.

## Architecture

```
backend/
  main.py            FastAPI app: lifespan, middleware, routing, static mount
  config.py          pydantic-settings Settings (single source of env config)
  dependencies.py    FastAPI dependency providers (get_predictor)
  models/schemas.py  Pydantic request/response schemas
  routes/analyze.py  POST /api/analyze (validate -> predict -> explain)
  services/
    validator.py     URL validation/sanitization (no network calls)
    predictor.py     Loads model once; predict() + SHAP + domain overrides
ml/
  feature_extractor.py  Extracts 27 deterministic URL features
  explainer.py          SHAP TreeExplainer wrapper
  train.py              End-to-end training + model serialization
models/               Trained artifacts (gitignored; see scripts/rebuild_model.py)
frontend/             Static UI (index.html, style.css, app.js)
docs/                 Mirror of frontend/ for GitHub Pages (keep in sync)
tests/                pytest suite (unit + API integration)
scripts/              Dev/deploy helpers (sync_docs.py, rebuild_model.py)
notebooks/            Jupyter ML pipeline notebook
data/                 Dataset (gitignored, download separately, see data/README.md)
```

## Commands

```bash
# Run the API server (local dev)
uvicorn backend.main:app --reload --port 8000

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest

# Lint + format (ruff)
ruff check .
ruff format --check .

# Regenerate the trained model (requires dataset in data/)
python scripts/rebuild_model.py        # downloads data if missing, then trains
python ml/train.py                     # train directly

# Keep docs/ mirror in sync with frontend/
python scripts/sync_docs.py            # copy frontend -> docs
python scripts/sync_docs.py --check    # CI: fail if docs/ is out of sync
```

## Conventions

- Python 3.11+; type hints everywhere; `from __future__ import annotations`.
- 27 features in `FeatureExtractor.FEATURE_NAMES` — never call it "25".
- Use `backend.config.settings` for all configuration; never scatter `os.getenv`.
- Errors: raise `URLValidationError` for input problems; HTTP errors are mapped
  once in the route; log the real exception, never leak internals to clients.
- No new external dependencies unless necessary — prefer stdlib (e.g. `difflib`
  for fuzzy matching over adding a fuzzy-match library).
- When editing `frontend/`, re-run `python scripts/sync_docs.py` and commit the
  mirror together. CI enforces parity.
- Log via the module `logger` (`from backend.logging import get_logger`), not
  `print()`.
- Rate limiting is applied per-route with `@limiter.limit(...)`; `RATE_LIMIT_PER_MINUTE`
  in settings controls the analyze endpoint.
- The event loop must not be blocked: keep CPU-bound work (`predictor.predict`)
  in sync `def` endpoints so FastAPI runs them in the threadpool.
