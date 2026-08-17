"""
logging.py
==========
Centralized logging configuration for PhishGuard.

All backend modules should obtain a logger via `get_logger(__name__)` and
never use `print()` for operational messages. This module configures one
shared handler so log records are consistent across the app.

Structured logging: when `log_format="json"` is selected, every record is
emitted as a single-line JSON object. A `RequestIdFilter` injects the
active request id (a context variable set by the request-ID middleware in
`backend.main`) into every record so logs emitted while handling a request
are correlated. Pass extra structured fields (method, status, latency) as
`extra={...}` when calling logger methods; the JSON formatter serializes
them as top-level keys.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar

_CONFIGURED = False

# Per-request context: set by the request-ID middleware and read by the
# logging filter below so all records during a request carry the id.
_request_id: ContextVar[str] = ContextVar("request_id", default="-")

_TEXT_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | request_id=%(request_id)s | %(message)s"


class RequestIdFilter(logging.Filter):
    """Attach the current request id to every emitted log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id.get()
        return True


class JsonFormatter(logging.Formatter):
    """Format each record as a single-line JSON object (structured logging).

    Extra attributes passed via `extra={...}` (and not part of the standard
    LogRecord set) are serialized as top-level keys, e.g. method, status,
    latency_ms. This is what makes access logs machine-parseable.
    """

    _RESERVED = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "asctime",
        "message",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging(level: int = logging.INFO, log_format: str = "text") -> None:
    """
    Configure the root logger once.

    Args:
        level: Minimum severity to emit (default INFO).
        log_format: "text" (human-readable) or "json" (structured, one
            object per line).
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    if log_format == "json":
        formatter: logging.Formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(_TEXT_FORMAT)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(RequestIdFilter())

    root = logging.getLogger()
    root.setLevel(level)
    # Avoid duplicate handlers if setup is called twice.
    root.handlers.clear()
    root.addHandler(handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger, ensuring logging is configured first.

    Args:
        name: Usually the calling module's `__name__`.

    Returns:
        A configured `logging.Logger` instance.
    """
    setup_logging()
    return logging.getLogger(name)


def set_request_id(request_id: str) -> object:
    """
    Set the request id for the current request context.

    Returns a token to pass to `reset_request_id` in a finally block.
    """
    return _request_id.set(request_id)


def reset_request_id(token: object) -> None:
    """Restore the request-id context after the request completes."""
    _request_id.reset(token)
