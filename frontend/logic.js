/* ==========================================================================
   PhishGuard — Pure Frontend Helpers
   ==========================================================================
   Browser-agnostic, unit-tested functions (vitest). Keep this module free of
   DOM/localStorage/fetch access so it runs in Node and in the browser.
   app.js imports these via ES modules (loaded with <script type="module">).
   ========================================================================== */

// Escape HTML metacharacters to prevent XSS from server-provided strings.
export function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (match) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[match]));
}

// Client-side URL normalization that mirrors backend/services/validator.py:
//   - trims whitespace
//   - rejects empty input
//   - rejects ftp (backend accepts http/https only)
//   - auto-prepends https:// when no scheme is present
// Returns { url, error } — url is '' when error is set.
export function normalizeUrl(raw) {
  const url = (raw || '').trim();
  if (!url) {
    return { url: '', error: 'Please enter a URL to analyze.' };
  }
  if (url.toLowerCase().startsWith('ftp://')) {
    return { url: '', error: 'Only http and https URLs are allowed.' };
  }
  let formatted = url;
  if (!formatted.startsWith('http://') && !formatted.startsWith('https://')) {
    formatted = 'https://' + formatted;
  }
  return { url: formatted, error: null };
}

// Plain-language verdict summary sentence (returns an HTML string).
export function buildVerdictSummary(data) {
  const isPhishing = data.prediction === 'PHISHING';
  const pct = Math.round(data.confidence * 100);
  const labels = (data.explanation || [])
    .slice(0, 3)
    .map((i) => i.label.toLowerCase())
    .filter(Boolean);

  if (isPhishing) {
    const parts = labels.length ? [` It shows signs of ${labels.join(', ')}.`] : [];
    return `This URL appears to be <strong class="phishing">phishing</strong> ` +
      `(high probability: ${pct}%).${parts.join('')} Avoid entering any personal information.`;
  }
  return `This URL appears <strong class="legitimate">legitimate</strong> ` +
    `(${pct}% confidence). It shows no strong phishing indicators.`;
}

// Plain-text copy payload for the "Copy Result" button, including the top
// explanation factors.
export function buildCopyText(result) {
  const lines = [
    'PhishGuard Analysis:',
    `URL: ${result.url}`,
    `Verdict: ${result.prediction} (${Math.round(result.confidence * 100)}% confidence)`,
    `Risk Level: ${result.risk_level}`,
  ];
  const factors = (result.explanation || []).slice(0, 3).map(
    (i) => `  - ${i.label} (${i.direction}, value ${i.value})`,
  );
  if (factors.length) {
    lines.push('Top factors:', ...factors);
  }
  return lines.join('\n');
}

// Insert a scan entry at the front of the history list, capped at `max`.
export function prependHistoryEntry(history, entry, max) {
  return [entry, ...history].slice(0, max);
}
