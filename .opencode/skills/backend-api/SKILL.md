---
name: backend-api
description: Use when building or changing FastAPI endpoints, routes, services, dependencies, or configuration under backend/. Covers the layered architecture, Settings-based config, dependency injection, sync endpoints, the error contract, rate limiting, logging, and caching.
---

# Backend API Development

## Architecture

```
backend/
  main.py            app entry: lifespan, middleware, routing, static mount
  config.py          pydantic-settings Settings (single source of config)
  dependencies.py    DI providers (get_predictor)
  rate_limit.py      slowapi Limiter + analyze_limit()
  logging.py         get_logger / setup_logging
  models/schemas.py  Pydantic request/response schemas
  routes/            one module per resource
  services/          validator, predictor
```

## Rules

- **Config:** import `settings` from `backend.config`. NEVER scatter
  `os.getenv` in modules. Add new env-driven options to `Settings` and to
  `.env.example`.
- **DI:** receive services via `Annotated[Service, Depends(get_predictor)]`.
  Do not reach into `request.app.state` from routes.
- **CPU-bound work:** keep it in sync `def` endpoints so FastAPI runs them in
  the threadpool. `POST /api/analyze` is sync for this reason.
- **Error contract:** raise `URLValidationError` with a machine-readable code
  in services; map it once in the route to an HTTPException whose `detail` is
  `{"error", "message", "input"}` (matches `ErrorResponse`). Log the real
  exception (`logger.exception`) but never include internals in the response.
  Use `raise ... from e` / `from None` so B904 stays satisfied.
- **Rate limiting:** every new user-facing POST endpoint gets
  `@limiter.limit(...)` from `backend.rate_limit`. Do not add routes without
  it. `TRUST_PROXY_HEADERS` controls `X-Forwarded-For` keying.
- **Logging:** use `get_logger(__name__)`, never `print()`.
- **Validation:** client-visible scheme enforcement lives in
  `services/validator.py` (schema only strips whitespace).

## Prediction cache

`PhishGuardPredictor` caches the last 512 unique URL results in a lock-guarded
FIFO. Do not assume every `predict()` call re-runs inference; the timestamp is
refreshed on cache hits.
