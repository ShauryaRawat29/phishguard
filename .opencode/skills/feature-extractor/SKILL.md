---
name: feature-extractor
description: Use when adding, modifying, or testing URL features in ml/feature_extractor.py, when retraining the model, or when the brand-spoofing/typosquatting/homograph logic is involved. Covers the 33-feature contract, FeatureExtractor.FEATURE_NAMES invariants, and the training/rebuild workflow.
---

# Feature Extractor & ML Pipeline

The URL feature extractor produces the model's input. Keep it deterministic,
fast, and free of any network access.

## The 33-feature contract

- `FeatureExtractor.FEATURE_NAMES` is the single source of truth: exactly **33**
  features, in a fixed order. Never call it "25" anywhere (docs, copy, comments).
- `extract()` returns a dict; `extract_as_list()` returns values in
  `FEATURE_NAMES` order — always build vectors from `FEATURE_NAMES`, never from
  dict iteration order.
- The trained model is coupled to this feature schema. `predictor._load`
  verifies `models/feature_names.json` matches `FEATURE_NAMES` at startup and
  refuses to boot on mismatch.
- Every feature name must have a human-readable label in `ml/explainer.py`
  `FEATURE_LABELS` (a test enforces this).

## Security invariant

Feature extraction is purely lexical/structural. NEVER add DNS lookups, HTTP
fetches, or any network call. This is an SSRF-prevention requirement.

## Brand spoofing / typosquatting

`_is_brand_spoofed` uses three layers (in order):
1. Direct containment: brand name appears but host is not the official apex
   domain or a subdomain of it.
2. Fuzzy typosquatting: second-level-domain tokens of length >= 5 that reach a
   difflib `SequenceMatcher` ratio >= 0.83 against a brand. Exact brand tokens
   are skipped (handled by layer 1) to avoid false positives like
   `www.paypal.com`.
3. IDN homograph: punycode `xn--` labels decoded via the stdlib punycode codec,
   then confusable non-Latin letters mapped to Latin via `_CONFUSABLES` and
   checked against brands.

Common-word false positives (`case.com`, `ample.com`) are expected to stay
clean — verify against them when changing thresholds.

## Whitelist semantics

`_is_whitelisted_domain` is strict: host must equal a trusted apex domain or
be a subdomain of one. Subdomains of trusted domains that also contain a brand
are NOT spoofed.

## Retraining

- Canonical workflow: `python scripts/rebuild_model.py` (downloads data via
  Kaggle CLI if missing, then runs `ml/train.py`).
- After changing feature behavior, retrain: `python scripts/rebuild_model.py
  --force`.
- Training samples to 50k URLs if the dataset is larger; label semantics in
  the raw CSV are `0 = phishing, 1 = legitimate` (train.py converts internally
  to `y=1` = phishing).
- Model artifacts (`models/phishing_model.joblib`, `feature_names.json`,
  `model_metadata.json`) are **committed to the repo** so Render's Docker build
  always contains them. After changing features, retrain and recommit them.
