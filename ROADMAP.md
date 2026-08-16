# PhishGuard Roadmap

Tracking document for planned improvements. Update the checkboxes as items are
completed. This file is the canonical reference for continuing work across
sessions — read it first when picking up a new session.

## Current Status (2026-08-17)

- API live on Render: `https://phishguard-api-dkoj.onrender.com`
- UI live on GitHub Pages: `https://shauryarawat29.github.io/phishguard/`
- Keep-warm cron workflow active (`.github/workflows/keep-warm.yml`)

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

- [ ] 2.1 Expand signal sets: more brands, suspicious TLDs, whitelisted apex domains
- [ ] 2.2 Add ~6 new lexical features:
      `has_punycode`, `is_ipv6`, `sld_length`, `path_has_https`, `brand_in_path`,
      `domain_entropy`
  - This **intentionally breaks the 27-feature contract**. Update:
    `FEATURE_NAMES`, `FEATURE_LABELS`, tests, `AGENTS.md`, README, frontend copy.
- [ ] 2.3 `scripts/adversarial_eval.py` — evasion-robustness measurement
      (homoglyphs, hex encoding, token padding) vs. clean F1
- [ ] 2.4 Retrain with `data/phishing_urls.csv`, re-verify SHAP, recommit model +
      `feature_names.json` + `model_metadata.json`
- **Constraint:** NO network/DNS/WHOIS features (SSRF invariant).

## Phase 3 — Frontend Polish

- [ ] 3.1 SHAP bar visualization (pure CSS horizontal bars) for explanation items
- [ ] 3.2 Plain-language verdict summary sentence
- [ ] 3.3 WCAG: `:focus-visible`, `prefers-reduced-motion`, contrast, color-blind-safe
- [ ] 3.4 "Show all features" progressive disclosure + recent-scans history (localStorage)
- [ ] 3.5 SVG favicon + Open Graph meta tags
- [ ] 3.6 Micro-interactions (verdict animation, hover tooltips)
- [ ] 3.7 Sync `docs/` mirror after all frontend changes

## Phase 4 — Tests, CI, Docs

- [ ] New tests for Phase 1 & 2 features
- [ ] Coverage ≥ 85-90% (currently 75%; `ml/train.py` untested by design)
- [ ] `pip-audit` in CI (see 1.6)
- [ ] README updates: security headers, docs gating, adversarial eval, new feature count

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
