# Security Policy

## Supported Versions

PhishGuard is a single-version project. The `main` branch is the only
actively supported version.

| Version | Supported          |
| ------- | ------------------ |
| main    | Yes                |

## Reporting a Vulnerability

Please do **not** open a public issue for security vulnerabilities. Report
privately via a GitHub Security Advisory:

1. Go to <https://github.com/ShauryaRawat29/phishguard/security/advisories>
2. Click **New draft security advisory**.
3. Describe the vulnerability, the affected component/endpoint, and steps to
   reproduce.

You should receive an acknowledgement within 72 hours. We will keep you
informed as a fix is prepared and released. Please do not disclose the issue
publicly until it has been addressed.

## Security Notes

- The server **never** makes network requests to the URLs it analyzes (no SSRF).
- Only `http` / `https` URLs are accepted; unsafe schemes are rejected.
- Rate limiting applies per IP to `POST /api/analyze`.
- Interactive API docs are disabled in production (`DOCS_ENABLED=false`).
- Dependencies are audited for known vulnerabilities (`pip-audit`) and kept up
  to date by Dependabot.
