"""
logging.py
==========
Centralized logging configuration for PhishGuard.

All backend modules should obtain a logger via `get_logger(__name__)` and
never use `print()` for operational messages. This module configures one
shared handler so log records are consistent across the app.
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False

_DEFAULT_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure the root logger once.

    Args:
        level: Minimum severity to emit (default INFO).
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT))

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
