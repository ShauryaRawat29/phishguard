import { describe, expect, it } from 'vitest';

import {
  buildCopyText,
  buildVerdictSummary,
  escapeHtml,
  normalizeUrl,
  prependHistoryEntry,
} from './logic.js';

describe('escapeHtml', () => {
  it('escapes HTML metacharacters', () => {
    expect(escapeHtml(`<script>alert("x&'")</script>`)).toBe(
      '&lt;script&gt;alert(&quot;x&amp;&#39;&quot;)&lt;/script&gt;',
    );
  });

  it('returns an empty string for null/undefined', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
  });

  it('coerces non-strings to strings', () => {
    expect(escapeHtml(42)).toBe('42');
  });
});

describe('normalizeUrl', () => {
  it('auto-prepends https for scheme-less input', () => {
    expect(normalizeUrl('example.com/path')).toEqual({
      url: 'https://example.com/path',
      error: null,
    });
  });

  it('keeps http and https as-is', () => {
    expect(normalizeUrl('http://example.com')).toEqual({
      url: 'http://example.com',
      error: null,
    });
    expect(normalizeUrl('https://example.com')).toEqual({
      url: 'https://example.com',
      error: null,
    });
  });

  it('trims surrounding whitespace', () => {
    expect(normalizeUrl('  https://example.com  ')).toEqual({
      url: 'https://example.com',
      error: null,
    });
  });

  it('rejects empty input', () => {
    const { url, error } = normalizeUrl('   ');
    expect(url).toBe('');
    expect(error).toMatch(/enter a URL/i);
  });

  it('rejects ftp to mirror the backend http/https-only rule', () => {
    const { url, error } = normalizeUrl('ftp://example.com');
    expect(url).toBe('');
    expect(error).toMatch(/http and https/i);
  });
});

describe('buildVerdictSummary', () => {
  it('builds a phishing summary with the top factors', () => {
    const data = {
      prediction: 'PHISHING',
      confidence: 0.94,
      explanation: [
        { label: 'URL length' },
        { label: 'Suspicious keywords' },
        { label: 'suspicious tld' },
      ],
    };
    const out = buildVerdictSummary(data);
    expect(out).toContain('phishing');
    expect(out).toContain('94%');
    expect(out).toContain('url length, suspicious keywords, suspicious tld');
  });

  it('builds a legitimate summary', () => {
    const out = buildVerdictSummary({
      prediction: 'LEGITIMATE',
      confidence: 0.9,
      explanation: [],
    });
    expect(out).toContain('legitimate');
    expect(out).toContain('90%');
  });
});

describe('buildCopyText', () => {
  it('includes url, verdict, risk level, and top factors', () => {
    const result = {
      url: 'https://example.com',
      prediction: 'PHISHING',
      confidence: 0.94,
      risk_level: 'HIGH',
      explanation: [{ label: 'Suspicious keywords', direction: 'phishing', value: 2 }],
    };
    const text = buildCopyText(result);
    expect(text).toContain('PhishGuard Analysis');
    expect(text).toContain('URL: https://example.com');
    expect(text).toContain('PHISHING (94% confidence)');
    expect(text).toContain('Risk Level: HIGH');
    expect(text).toContain('Top factors:');
    expect(text).toContain('Suspicious keywords');
  });
});

describe('prependHistoryEntry', () => {
  it('prepends the new entry and caps at max', () => {
    const out = prependHistoryEntry([{ url: 'a' }], { url: 'b' }, 2);
    expect(out).toEqual([{ url: 'b' }, { url: 'a' }]);
  });

  it('drops the oldest entry past max', () => {
    const out = prependHistoryEntry([{ url: '1' }, { url: '2' }], { url: '3' }, 2);
    expect(out).toEqual([{ url: '3' }, { url: '1' }]);
  });
});
