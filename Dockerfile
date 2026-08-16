# ─── PhishGuard Dockerfile ────────────────────────────────────────────────────
# Multi-stage build: install dependencies into an isolated prefix, then assemble
# a slim runtime image.
#
# NOTE: the trained model (models/*.joblib) is gitignored. Ensure it exists in
# the build context (run `python scripts/rebuild_model.py` locally first) or
# mount it at runtime, otherwise the API serves a degraded health status.

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

FROM base AS builder
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM base
WORKDIR /app

COPY --from=builder /install /usr/local

COPY backend/ backend/
COPY ml/ ml/
COPY models/ models/
COPY frontend/ frontend/

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
