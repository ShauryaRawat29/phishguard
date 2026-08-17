# ─── PhishGuard Dockerfile ────────────────────────────────────────────────────
# Multi-stage build: install dependencies into an isolated prefix, then assemble
# a slim runtime image.
#
# NOTE: the trained model (models/phishing_model.joblib) is committed to the
# repo, so the Docker build context always contains it.

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

# Run as a non-root user (container hardening).
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

# The health probe hits /api/health with the stdlib HTTP client so no curl
# dependency is needed in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"]

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
