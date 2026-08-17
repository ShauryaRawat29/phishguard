# PhishGuard Roadmap

Tracking document for planned improvements. Update the checkboxes as items are
completed. This file is the canonical reference for continuing work across
sessions — read it first when picking up a new session.

## Current Status (2026-08-17)

- API live on Render: `https://phishguard-api-dkoj.onrender.com`
- UI live on GitHub Pages: `https://shauryarawat29.github.io/phishguard/`
- Keep-warm cron workflow active (`.github/workflows/keep-warm.yml`)

### Session log — 2026-08-17 (this session)

- **8.4 ✅** (calibration, deferred from Phase 8) — isotonic probability
  calibration: `ml/train.py` carves a 20% calibration split out of the
  training set, fits `IsotonicRegression`, saves `models/calibrator.joblib`,
  and reports raw→calibrated Brier score and log loss on the test set.
  `predictor.py` applies the calibrator to raw model probabilities
  (`CALIBRATOR_PATH`; graceful fallback to raw if missing). Retrained on the
  full 468,783-URL dataset with the tuned params — test F1 **0.9973**,
  accuracy 0.9961, AUC 0.9994 (matches the Phase 8 production model);
  calibration improved test log loss 0.0147→0.0144. Also fixed a latent bug:
  tuned best params are now the `ml/train.py` defaults so the canonical
  `scripts/rebuild_model.py` path reproduces the production model instead of
  silently training a weaker default-params model. Adversarial eval re-run
  (unchanged: baseline F1 0.9971, evasion <1% for all perturbations).
- **Phase 1 ✅** commit `b67e6a0` — security headers, TrustedHostMiddleware,
  docs gating, rate-limit XFF hardening, CORS prod rejection, `pip-audit` in CI.
- **Phase 2 ✅** commit `0d17ed2` — 33 features (was 27), expanded brands/TLDs/
  whitelist, `scripts/adversarial_eval.py`, model retrained (test F1 **0.9969**,
  accuracy 0.9973, AUC 0.9992), adversarial evasion <1%.
- **Phase 3 ✅** commit `f72bfc1` — SHAP bars, verdict summary, show-all features,
  localStorage scan history, favicon + OG tags, WCAG improvements; new
  `GET /api/features` endpoint; `docs/` re-synced.
- **Phase 4 ✅** — test suite at **116 passing**, **100% coverage** (excluding
  `ml/train.py`, omitted in `pyproject.toml`); closed the last
  `feature_extractor.py:543` homograph gap and `is_trusted_proxy` edge cases;
  README updated (live links, security headers, docs gating, adversarial
  robustness).
- **Phase 5 ✅** — retrained on the **full 235,795-URL dataset**
  (was 50k sample). `ml/train.py` now takes an optional `--samples` flag and
  defaults to all data. Test F1 **0.9965** on a 35k held-out test set
  (accuracy 0.9970, AUC 0.9986), XGBoost still the winner; adversarial evasion
  still **<1%** for all perturbations. Model artifacts recommitted.
- **Phase 6 ✅** — correctness sweep: IPv6 host-parsing fix, favicon sync bug,
  full-dataset retrain, stale notebook/README cleanup. Model retrained (F1
  0.9965, unchanged), adversarial evasion still <1%, 100% coverage.
- **Phase 7 ✅** — dataset extension: `ml/augment.py` (leet/homoglyph/
  typosquat, stdlib-only), `scripts/build_dataset.py` (PhishTank +
  URLhaus dumps, `data/extra/`, ccTLD legit variants, dedup/standardize),
  `--dataset` flag in `ml/train.py`. Extended to **468,783 URLs** (333,741
  phishing / 135,042 legit). Retrained XGBoost: test F1 **0.9975** (was
  0.9965), accuracy 0.9964, AUC 0.9994, adversarial evasion still <1%.
- **Phase 8 ✅** — ML refinement: XGBoost `GridSearchCV` tuning (`--tune`
  in `ml/train.py`; best `learning_rate=0.05, max_depth=6, n_estimators=200`,
  test F1 **0.9972**, accuracy 0.9961, AUC 0.9994); risk thresholds
  (`decision_threshold` / `high_risk_threshold` / `low_risk_threshold`)
  moved into `Settings` + `.env.example` with tests; `adversarial_eval.py`
  extended with double-encoding, fullwidth homoglyphs, backslash-scheme and
  `www-` sandwich perturbators (evasion still <1% for all; host-shape
  perturbators remain conservative FP-prone by design). 8.4 (calibration)
  deferred as optional.
- **Phase 9 ✅** — backend hardening: request-ID middleware + structured
  JSON access logs (`LOG_FORMAT`, `X-Request-ID`, request-id correlation via
  contextvar); cache TTL (`CACHE_TTL_SECONDS`) on the prediction cache;
  validator now accepts `http`/`https` only (ftp dropped); richer
  `/api/health` (feature count, uptime, model metadata); Docker runs as a
  non-root user with a python-based `HEALTHCHECK`. Coverage back to 100%.
- **Phase 10 ✅** — CI/CD & security: test matrix widened to Python
  3.11–3.14; coverage gate `--cov-fail-under=95`; new Docker-build job
  (build + health smoke test); Dependabot config for pip + GitHub Actions;
  `SECURITY.md` with a private vulnerability-reporting process; README
  security notes updated.
- **Phase 11 ✅** — frontend & DX: `frontend/logic.js` pure-helper module
  (normalizeUrl, escapeHtml, buildVerdictSummary, buildCopyText, history)
  unit-tested with **vitest** (13 tests) and linted with **eslint**;
  app.js converted to an ES module; UX fixes (skip-to-content link, timed
  loading-step progression, copy-result includes top factors); client-side
  validation now mirrors the http/https-only backend rule. `logic.js` added
  to the docs mirror; `node_modules/` gitignored.

---

## Phase 6 — Correctness Sweep

- [x] 6.1 Fix IPv6 host parsing in `ml/feature_extractor.py`
      (`host = netloc.split(":")[0]` corrupts bracketed IPv6 hosts → wrong
      `domain_length`, `sld_length`, `domain_entropy`, `subdomain_count`).
      Parse bracketed IPv6 properly; add tests.
- [x] 6.2 Fix favicon sync bug: `frontend/favicon.svg` is not in
      `docs/` and not in `sync_docs.py`'s `FILES` list. Add it and re-sync.
- [x] 6.3 Retrain on the full dataset (features changed) + recommit model
      artifacts + re-run `scripts/adversarial_eval.py`.
- [x] 6.4 Fix stale notebook (`notebooks/phishing_detection.ipynb` says
      "25 features" → 33; reflect full-dataset training).
- [x] 6.5 Update README status badge (In Development → stable).
- [x] 6.6 Tests for all of the above; run `pytest`, `ruff`, `sync_docs --check`,
      commit, push.

## Phase 7 — Dataset Extension

- [x] 7.1 Multi-source data collection: integrate PhishTank, OpenPhish, and UCI ML Repository datasets
- [x] 7.2 Data augmentation: implement character substitution, typosquatting, and homoglyph generation
- [x] 7.3 Temporal updates: add recent 2024-2026 phishing URLs to capture new patterns
- [x] 7.4 Geographic diversity: add international URLs and country-specific TLDs
- [x] 7.5 Dataset validation: deduplication, format standardization, and quality checks
- [x] 7.6 Retrain and evaluate: compare model performance with extended dataset
- [x] 7.7 Update documentation and scripts for new data sources

## Phase 8 — ML Refinement (no new Python deps)

- [x] 8.1 XGBoost hyperparameter search via `GridSearchCV` (depth, estimators,
      learning rate) on the full dataset.
- [x] 8.2 Configurable risk thresholds: move `_get_risk_level` cutoffs
      (0.70 / 0.40) into `Settings`; tune the 0.5 decision threshold.
- [x] 8.3 Extend `scripts/adversarial_eval.py`: double-encoding, fullwidth/
      unicode homoglyphs, backslash tricks, `www-` sandwich.
- [x] 8.4 Isotonic probability calibration for well-calibrated confidence
      (fitted on a held-out calibration split; `models/calibrator.joblib`;
      applied in `predictor.py`; raw probabilities used if the file is
      missing). See session log entry above.
- [x] 8.5 Retrain/recommit + re-run adversarial eval + docs updates.

## Phase 9 — Backend Hardening & Observability

- [x] 9.1 Request-ID middleware + structured JSON logging (request id, latency,
      status).
- [x] 9.2 Cache TTL on the FIFO prediction cache (predictor.py).
- [x] 9.3 Validator: restrict to `http` / `https` only (drop `ftp`).
- [x] 9.4 Richer `/api/health`: model metadata, feature count, uptime.
- [x] 9.5 Docker: non-root user + `HEALTHCHECK`.

## Phase 10 — CI/CD & Security

- [x] 10.1 CI matrix: add Python 3.13 / 3.14.
- [x] 10.2 Coverage gate: `--cov-fail-under=95` in CI.
- [x] 10.3 Docker-build job in CI.
- [x] 10.4 Dependabot config + `SECURITY.md`.
- [x] 10.5 Tests for new behaviors; docs updates.

## Phase 11 — Frontend & DX (dev-only JS tooling)

- [x] 11.1 Add vitest + eslint (dev-only; `frontend/` stays plain static files;
      docs sync unchanged).
- [x] 11.2 Unit-test `app.js`: extract pure functions (buildVerdictSummary,
      escapeHtml, history) to make them testable.
- [x] 11.3 UX fixes: skip-to-content link, real loading-step progression,
      copy-result includes explanation.
- [x] 11.4 Client/server validation parity: mirror http/https-only rule in
      `app.js`.
- [x] 11.5 Sync docs mirror + commit.

---

## Invariants

- Server NEVER makes network requests to analyzed URLs (no SSRF).
- No new runtime dependencies unless necessary (prefer stdlib / existing libs).
- `docs/` must stay byte-for-byte in sync with `frontend/` (CI enforces).
- Feature count is referenced in many places — update all when it changes.

---

## Phase 1 — Security Hardening (backend)

- [x] 1.1 Add missing security headers in `backend/main.py`:
  - [x] `Strict-Transport-Security` (only over HTTPS)
  - [x] `Content-Security-Policy` (self + Google Fonts + jsdelivr for docs; `frame-ancestors 'none'`)
  - [x] `Cache-Control: no-store` on API responses
  - [x] `Cross-Origin-Resource-Policy: same-origin`
- [x] 1.2 Add `TrustedHostMiddleware` (Render URL + localhost + GitHub Pages)
- [x] 1.3 `docs_enabled` setting: gate `/docs`, `/redoc`, `/openapi.json` (off in production)
- [x] 1.4 Rate-limit key: only trust `X-Forwarded-For` when peer IP is in `trusted_proxy_ips`
- [x] 1.5 CORS: reject wildcard `*` when `APP_ENV=production`
- [x] 1.6 Add `pip-audit` job to CI
- [x] 1.7 Tests for all of the above
- [x] Update `render.yaml` + `.env.example` for new settings
- **Decision:** rate limiting stays in-memory (single Render worker). Document limitation.

## Phase 2 — ML / Detection (full retrain)

- [x] 2.1 Expand signal sets: more brands, suspicious TLDs, whitelisted apex domains
- [x] 2.2 Add ~6 new lexical features:
      `has_punycode`, `is_ipv6`, `sld_length`, `path_has_https`, `brand_in_path`,
      `domain_entropy`
  - This **intentionally breaks the 27-feature contract**. Update:
    `FEATURE_NAMES`, `FEATURE_LABELS`, tests, `AGENTS.md`, README, frontend copy.
- [x] 2.3 `scripts/adversarial_eval.py` — evasion-robustness measurement
      (homoglyphs, hex encoding, token padding) vs. clean F1
- [x] 2.4 Retrain with `data/phishing_urls.csv`, re-verify SHAP, recommit model +
      `feature_names.json` + `model_metadata.json`
  - Result: 33 features, test F1 **0.9969**, accuracy 0.9973, AUC 0.9992.
  - Adversarial: evasion <1% for all perturbations; token-padding FP is
    conservative-by-design (suspicious keyword in path flags the URL).
- **Constraint:** NO network/DNS/WHOIS features (SSRF invariant).

## Phase 3 — Frontend Polish

- [x] 3.1 SHAP bar visualization (pure CSS horizontal bars) for explanation items
- [x] 3.2 Plain-language verdict summary sentence
- [x] 3.3 WCAG: `:focus-visible`, `prefers-reduced-motion`, contrast, color-blind-safe
- [x] 3.4 "Show all features" progressive disclosure + recent-scans history (localStorage)
      — backed by new `GET /api/features` endpoint (feature names + labels)
- [x] 3.5 SVG favicon + Open Graph meta tags
- [x] 3.6 Micro-interactions (verdict animation, hover tooltips)
- [x] 3.7 Sync `docs/` mirror after all frontend changes

## Phase 4 — Tests, CI, Docs

- [x] New tests for Phase 1 & 2 features
- [x] `pip-audit` in CI (see 1.6)
- [x] Test for `GET /api/features` endpoint
- [x] Coverage ≥ 85-90% (now **100%**; `ml/train.py` omitted from coverage)
- [x] README updates: security headers, docs gating, adversarial eval, new feature count

## Invariants

- Server NEVER makes network requests to analyzed URLs (no SSRF).
- No new runtime dependencies unless necessary (prefer stdlib / existing libs).
- `docs/` must stay byte-for-byte in sync with `frontend/` (CI enforces).
- Feature count is referenced in many places — update all when it changes.

## How to continue next session

1. Read this file.
2. Start with the oldest unchecked item.
3. After each phase: run `pytest`, `ruff check .`, `ruff format --check .`,
   `python scripts/sync_docs.py --check`, commit, push.
