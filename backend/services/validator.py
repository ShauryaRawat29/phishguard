"""
validator.py
============
URL validation and sanitization for the PhishGuard backend.

Validates that a submitted URL is syntactically well-formed and safe to
process. The server NEVER makes network requests to the submitted URL.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Schemes the server will accept
ALLOWED_SCHEMES: set[str] = {"http", "https", "ftp"}

# Maximum URL length (matches IE/browser limit)
MAX_URL_LENGTH: int = 2083


class URLValidationError(ValueError):
    """Raised when a URL fails validation checks."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


def validate_url(url: str) -> str:
    """
    Validate and return a sanitized URL string.

    Checks performed:
    1. Not empty after stripping whitespace
    2. Does not exceed maximum length
    3. Has an allowed scheme (http / https / ftp)
    4. Has a non-empty netloc (domain or IP)
    5. Is not a file:// or data:// URI (security risk)

    Args:
        url: Raw URL string from the user.

    Returns:
        The stripped, validated URL string.

    Raises:
        URLValidationError: If any check fails, with a machine-readable code
                            and a user-friendly message.
    """
    url = url.strip()

    if not url:
        raise URLValidationError(
            code="EMPTY_URL",
            message="Please enter a URL.",
        )

    # Reject unsafe URI protocols
    if url.lower().startswith(("file://", "data:", "javascript:", "vbscript:")):
        raise URLValidationError(
            code="INVALID_SCHEME",
            message="Unsafe URI scheme. Only http, https, and ftp URLs are allowed.",
        )

    # Auto-prepend https:// if user entered domain/path without scheme
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "https://" + url

    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(
            code="URL_TOO_LONG",
            message=(
                f"URL exceeds the maximum allowed length of {MAX_URL_LENGTH} characters. "
                f"Submitted URL is {len(url)} characters."
            ),
        )

    try:
        parsed = urlparse(url)
    except Exception:
        raise URLValidationError(
            code="INVALID_URL",
            message="The provided input could not be parsed as a URL.",
        )

    if not parsed.netloc:
        raise URLValidationError(
            code="INVALID_URL",
            message=(
                "The URL does not contain a valid domain. "
                "Example: example.com or https://example.com"
            ),
        )

    return url
