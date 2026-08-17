"""
test_logging.py
===============
Unit tests for the structured-logging helpers (request-id context and the
JSON formatter).
Run with: pytest tests/test_logging.py -v
"""

from __future__ import annotations

import json
import logging

from backend.logging import JsonFormatter, RequestIdFilter, reset_request_id, set_request_id


def _record(
    name: str = "test", msg: str = "analyzed %s", args: tuple = ("url",)
) -> logging.LogRecord:
    return logging.LogRecord(
        name=name,
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=args,
        exc_info=None,
    )


def test_set_and_reset_request_id():
    from backend.logging import _request_id

    assert _request_id.get() == "-"
    token = set_request_id("abc")
    try:
        assert _request_id.get() == "abc"
    finally:
        reset_request_id(token)
    assert _request_id.get() == "-"


def test_request_id_filter_sets_attribute():
    record = _record()
    token = set_request_id("rid-2")
    try:
        assert RequestIdFilter().filter(record) is True
        assert record.request_id == "rid-2"
    finally:
        reset_request_id(token)


def test_request_id_filter_defaults_to_dash():
    record = _record()
    assert RequestIdFilter().filter(record) is True
    assert record.request_id == "-"


def test_json_formatter_emits_structured_fields():
    record = _record()
    record.request_id = "rid-1"
    record.method = "POST"
    record.status = 200
    record.latency_ms = 3.5

    data = json.loads(JsonFormatter().format(record))
    assert data["level"] == "INFO"
    assert data["logger"] == "test"
    assert data["request_id"] == "rid-1"
    assert data["message"] == "analyzed url"
    assert data["method"] == "POST"
    assert data["status"] == 200
    assert data["latency_ms"] == 3.5


def test_json_formatter_serializes_exc_info():
    record = _record()
    try:
        raise ValueError("boom")
    except ValueError:
        record.exc_info = logging.sys.exc_info()
    data = json.loads(JsonFormatter().format(record))
    assert "exc_info" in data
    assert "ValueError: boom" in data["exc_info"]


def test_setup_logging_json_format(monkeypatch):
    """setup_logging picks the JSON formatter when log_format='json'."""
    import backend.logging as logging_mod

    monkeypatch.setattr(logging_mod, "_CONFIGURED", False)
    logging_mod.setup_logging(log_format="json")
    monkeypatch.setattr(logging_mod, "_CONFIGURED", True)

    handler = logging.getLogger().handlers[0]
    assert isinstance(handler.formatter, JsonFormatter)
