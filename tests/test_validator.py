"""
test_validator.py
=================
Unit tests for the URL validator service.
Run with: pytest tests/test_validator.py -v
"""

import pytest
from backend.services.validator import URLValidationError, validate_url


# ─── Valid URLs ───────────────────────────────────────────────────────────────

def test_valid_https_url():
    result = validate_url("https://example.com")
    assert result == "https://example.com"

def test_valid_http_url():
    result = validate_url("http://example.com/path?q=1")
    assert result == "http://example.com/path?q=1"

def test_strips_whitespace():
    result = validate_url("  https://example.com  ")
    assert result == "https://example.com"

def test_valid_ip_url():
    result = validate_url("http://192.168.1.1/page")
    assert result == "http://192.168.1.1/page"


# ─── Invalid URLs ─────────────────────────────────────────────────────────────

def test_empty_url_raises():
    with pytest.raises(URLValidationError) as exc:
        validate_url("")
    assert exc.value.code == "EMPTY_URL"

def test_whitespace_only_raises():
    with pytest.raises(URLValidationError) as exc:
        validate_url("   ")
    assert exc.value.code == "EMPTY_URL"

def test_no_scheme_raises():
    with pytest.raises(URLValidationError) as exc:
        validate_url("example.com/path")
    assert exc.value.code == "INVALID_SCHEME"

def test_unsupported_scheme_raises():
    with pytest.raises(URLValidationError) as exc:
        validate_url("file:///etc/passwd")
    assert exc.value.code == "INVALID_SCHEME"

def test_data_uri_raises():
    with pytest.raises(URLValidationError) as exc:
        validate_url("data:text/html,<script>alert(1)</script>")
    assert exc.value.code == "INVALID_SCHEME"

def test_url_too_long_raises():
    long_url = "https://example.com/" + "a" * 2100
    with pytest.raises(URLValidationError) as exc:
        validate_url(long_url)
    assert exc.value.code == "URL_TOO_LONG"

def test_no_netloc_raises():
    with pytest.raises(URLValidationError) as exc:
        validate_url("https:///just-path")
    assert exc.value.code == "INVALID_URL"
