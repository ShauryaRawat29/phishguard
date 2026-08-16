---
name: frontend-docs-mirror
description: Use when editing anything under frontend/ (index.html, style.css, app.js) or when the docs/ GitHub Pages mirror is involved. Covers the required sync workflow and the CI parity check.
---

# Frontend ↔ docs Mirror

The `docs/` directory is a byte-for-byte mirror of `frontend/` and is what
GitHub Pages serves. Never edit `docs/` files directly.

## Required workflow after any frontend edit

1. Edit files under `frontend/` only.
2. Re-sync the mirror:
   ```
   python scripts/sync_docs.py
   ```
3. Commit `frontend/` and `docs/` changes together in the same commit.

## Checks

- `python scripts/sync_docs.py --check` fails (exit 1) if the mirror drifted.
  CI runs this on every push, so a missing sync breaks the build.
- If a check fails, run the sync script and re-commit the mirror.

## App notes

- `frontend/app.js` targets `http://localhost:8000` when the hostname is
  `localhost`/`127.0.0.1` and uses a relative path otherwise (production).
- Client-side validation mirrors backend behavior: scheme-less input is
  auto-prepended with `https://`.
