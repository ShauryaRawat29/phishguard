---
name: testing
description: Use when writing, running, or extending tests under tests/. Covers the stub-model pattern for fast predictor/API tests, TestClient usage, coverage, and the rule that CI has no model or dataset.
---

# Testing

Run: `pytest` (aliased `python -m pytest tests -p no:warnings`). Coverage:
`pytest --cov=backend --cov=ml --cov-report=term-missing`. Lint must stay
clean: `ruff check .` and `ruff format --check .`.

## The stub-model pattern (fast tests)

The real model + SHAP explainer take ~35s to load, so tests never load it.
Monkeypatch `PhishGuardPredictor._load` on the class to install a stub:

```python
class StubModel:
    def __init__(self, phishing_proba): self._proba = phishing_proba; self.calls = 0
    def predict_proba(self, X): self.calls += 1; return np.array([[1-self._proba, self._proba]])

def _install_stub(monkeypatch, proba, is_loaded=True):
    model = StubModel(proba)
    def fake_load(self, model_path, feature_names_path):
        self._model = model
        self._explainer = None
        self.feature_names = FeatureExtractor.FEATURE_NAMES
        self.is_loaded = is_loaded
    monkeypatch.setattr(PhishGuardPredictor, "_load", fake_load)
    return model
```

Because `__init__` calls `_load`, patch it BEFORE constructing the predictor.

## API integration tests

- Use the real `backend.main.app` with `TestClient(app)` as a context manager
  (triggers lifespan), with `_load` stubbed.
- Toggle availability via a module-level `STATE = {"model_loaded": True}` that
  `fake_load` reads, to exercise the 503 path.
- `predictor._load` failure paths (missing file, non-estimator, feature-name
  mismatch) are tested by monkeypatching `settings.model_path` /
  `settings.feature_names_path` to `tmp_path` files.

## Constraints

- CI runs without the dataset and without the trained model. Never write a
  test that depends on `data/` or `models/*.joblib`.
- Keep `FEATURE_LABELS` in `ml/explainer.py` complete: a test asserts every
  name in `FEATURE_NAMES` has a label.
- Don't hammer the shared slowapi limiter: exceeding the analyze budget in one
  test would starve the others. Rate-limit behavior is tested on an isolated
  mini-app with its own low limit.
