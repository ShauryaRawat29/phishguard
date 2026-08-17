/* ==========================================================================
   PhishGuard — Frontend Application Logic
   Retro CRT single page: themes, CRT toggle, SFX, matrix rain, keyboard
   shortcuts, plus the URL analyzer.
   ========================================================================== */

import {
  buildCopyText,
  buildVerdictSummary,
  escapeHtml,
  normalizeUrl,
  prependHistoryEntry,
} from './logic.js';

// Base API URL.
//   - Local dev: use the local FastAPI server.
//   - Anywhere else (Render UI, GitHub Pages mirror, custom domain): use the
//     deployed API, overridable via window.PHISHGUARD_API_URL.
const API_BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://localhost:8000'
  : (window.PHISHGUARD_API_URL || 'https://phishguard-api-dkoj.onrender.com');

// Storage keys
const HISTORY_KEY = 'phishguard.history';
const THEME_KEY = 'phishguard.theme';
const CRT_KEY = 'phishguard.crt';
const SFX_KEY = 'phishguard.sfx';
const HISTORY_MAX = 8;
const LOADING_STEP_INTERVAL_MS = 1200;

// DOM Elements — analyzer
const form = document.getElementById('url-form');
const input = document.getElementById('url-input');
const inputError = document.getElementById('url-error');
const inputGroup = document.getElementById('input-group');
const submitBtn = document.getElementById('analyze-btn');

const sampleLegit = document.getElementById('sample-legit');
const samplePhish = document.getElementById('sample-phish');

const resultDivider = document.getElementById('result-divider');
const loadingState = document.getElementById('loading-state');
const resultState = document.getElementById('result-state');
const errorState = document.getElementById('error-state');
const errorMessage = document.getElementById('error-message');

const verdictBanner = document.getElementById('verdict-banner');
const verdictLabel = document.getElementById('verdict-label');
const verdictUrl = document.getElementById('verdict-url');
const verdictIcon = document.getElementById('verdict-icon');
const riskBadge = document.getElementById('risk-badge');
const verdictSummary = document.getElementById('verdict-summary');

const confidenceValue = document.getElementById('confidence-value');
const confidenceFill = document.getElementById('confidence-fill');
const explanationList = document.getElementById('explanation-list');
const showAllBtn = document.getElementById('show-all-btn');
const allFeaturesGrid = document.getElementById('all-features-grid');

const historySection = document.getElementById('history-section');
const historyList = document.getElementById('history-list');
const historyClearBtn = document.getElementById('history-clear-btn');

const analyzeAnotherBtn = document.getElementById('analyze-another-btn');
const copyResultBtn = document.getElementById('copy-result-btn');
const retryBtn = document.getElementById('retry-btn');

const loadingSteps = [
  document.getElementById('step-1'),
  document.getElementById('step-2'),
  document.getElementById('step-3'),
];

// DOM Elements — display controls
const themeSelect = document.getElementById('theme-select');
const toggleCrtBtn = document.getElementById('toggle-crt-btn');
const crtIndicator = document.getElementById('crt-indicator');
const toggleSfxBtn = document.getElementById('toggle-sfx-btn');
const sfxIcon = document.getElementById('sfx-icon');
const sfxStatus = document.getElementById('sfx-status');
const triggerMatrixBtn = document.getElementById('trigger-matrix-btn');
const matrixRain = document.getElementById('matrix-rain');

let currentAnalysisResult = null;
let featureLabels = null;
let loadingStepTimer = null;

// ── Theme switching ───────────────────────────────────────────────────────

function applyTheme(id) {
  document.documentElement.dataset.theme = id;
  localStorage.setItem(THEME_KEY, id);
}

function initTheme() {
  const saved = localStorage.getItem(THEME_KEY) || 'green';
  applyTheme(saved);
  themeSelect.value = saved;
}

themeSelect.addEventListener('change', () => {
  applyTheme(themeSelect.value);
  beep(600, 0.05);
});

// ── CRT toggle ────────────────────────────────────────────────────────────

let crtEnabled = localStorage.getItem(CRT_KEY) !== 'off';

function applyCRT() {
  document.documentElement.style.setProperty('--scanline-opacity', crtEnabled ? '0.15' : '0');
  document.documentElement.style.setProperty('--vignette-opacity', crtEnabled ? '0.65' : '0');
  document.body.classList.toggle('crt-on', crtEnabled);
  document.body.classList.toggle('crt-off', !crtEnabled);
  crtIndicator.classList.toggle('muted', !crtEnabled);
}

toggleCrtBtn.addEventListener('click', () => {
  crtEnabled = !crtEnabled;
  localStorage.setItem(CRT_KEY, crtEnabled ? 'on' : 'off');
  applyCRT();
  beep(450, 0.04);
});

// ── SFX (Web Audio keypress clicks / chimes) ──────────────────────────────

let sfxEnabled = localStorage.getItem(SFX_KEY) !== 'off';
let audioCtx = null;

function ensureAudioCtx() {
  if (!audioCtx) {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (AC) audioCtx = new AC();
  }
  return audioCtx;
}

function beep(freq, dur, type = 'square', gain = 0.03) {
  if (!sfxEnabled) return;
  const ctx = ensureAudioCtx();
  if (!ctx) return;
  if (ctx.state === 'suspended') ctx.resume();
  const osc = ctx.createOscillator();
  const amp = ctx.createGain();
  osc.type = type;
  osc.frequency.value = freq;
  amp.gain.setValueAtTime(gain, ctx.currentTime);
  amp.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + dur);
  osc.connect(amp);
  amp.connect(ctx.destination);
  osc.start();
  osc.stop(ctx.currentTime + dur);
}

function playKey() {
  beep(660, 0.02, 'square', 0.015);
}

function playSuccess() {
  beep(880, 0.08);
  window.setTimeout(() => beep(1320, 0.1), 90);
}

function playError() {
  beep(240, 0.14, 'sawtooth', 0.05);
}

function updateSfxUI() {
  sfxIcon.textContent = sfxEnabled ? '🔊' : '🔇';
  sfxStatus.textContent = sfxEnabled ? 'SFX' : 'MUTED';
}

toggleSfxBtn.addEventListener('click', () => {
  sfxEnabled = !sfxEnabled;
  localStorage.setItem(SFX_KEY, sfxEnabled ? 'on' : 'off');
  updateSfxUI();
  if (sfxEnabled) playSuccess();
});

// ── Matrix rain ───────────────────────────────────────────────────────────

let matrixActive = false;
let matrixRaf = null;

function startMatrix() {
  matrixRain.hidden = false;
  const ctx = matrixRain.getContext('2d');
  const font = 14;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*<>/\\|{}=+-_';
  let cols = 0;
  let drops = [];

  function resize() {
    matrixRain.width = window.innerWidth;
    matrixRain.height = window.innerHeight;
    cols = Math.floor(window.innerWidth / font);
    drops = new Array(cols).fill(1);
  }

  resize();
  window.addEventListener('resize', resize);

  const accent = window.getComputedStyle(document.documentElement)
    .getPropertyValue('--accent').trim() || '#00ff66';

  function draw() {
    ctx.fillStyle = 'rgba(0, 0, 0, 0.06)';
    ctx.fillRect(0, 0, matrixRain.width, matrixRain.height);
    ctx.font = `${font}px monospace`;
    for (let i = 0; i < cols; i += 1) {
      const ch = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillStyle = accent;
      ctx.fillText(ch, i * font, drops[i] * font);
      if (drops[i] * font > matrixRain.height && Math.random() > 0.975) drops[i] = 0;
      drops[i] += 1;
    }
    matrixRaf = window.requestAnimationFrame(draw);
  }

  draw();
}

function stopMatrix() {
  matrixRain.hidden = true;
  if (matrixRaf) window.cancelAnimationFrame(matrixRaf);
  matrixRaf = null;
}

function setMatrix(on) {
  if (on === matrixActive) return;
  matrixActive = on;
  if (on) startMatrix();
  else stopMatrix();
}

triggerMatrixBtn.addEventListener('click', () => {
  setMatrix(true);
  beep(700, 0.08);
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (matrixActive) setMatrix(false);
    return;
  }
  const tag = e.target && e.target.tagName;
  if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
  const key = e.key.toLowerCase();
  if (key === 'c') toggleCrtBtn.click();
  else if (key === 's') toggleSfxBtn.click();
  else if (key === 'm') {
    if (matrixActive) setMatrix(false);
    else {
      setMatrix(true);
      beep(700, 0.08);
    }
  } else if (key === 't') {
    themeSelect.focus();
    beep(500, 0.04);
  }
});

// ── Event listeners ───────────────────────────────────────────────────────

form.addEventListener('submit', handleSubmit);
sampleLegit.addEventListener('click', () => useSample(sampleLegit.dataset.url));
samplePhish.addEventListener('click', () => useSample(samplePhish.dataset.url));
analyzeAnotherBtn.addEventListener('click', resetForm);
retryBtn.addEventListener('click', resetForm);
copyResultBtn.addEventListener('click', copyResult);
showAllBtn.addEventListener('click', toggleAllFeatures);
historyClearBtn.addEventListener('click', clearHistory);

input.addEventListener('keydown', () => playKey());
input.addEventListener('input', hideInputError);

// ── Init ──────────────────────────────────────────────────────────────────

renderHistory();
initTheme();
applyCRT();
updateSfxUI();

// ── Sample URLs ───────────────────────────────────────────────────────────

function useSample(url) {
  input.value = url;
  hideInputError();
  form.requestSubmit();
}

// ── Form submission ───────────────────────────────────────────────────────

async function handleSubmit(e) {
  e.preventDefault();

  // Client-side validation mirrors backend/services/validator.py.
  const { url: formattedUrl, error } = normalizeUrl(input.value);
  if (error) {
    showInputError(error);
    playError();
    return;
  }
  input.value = formattedUrl;

  hideInputError();
  beep(520, 0.04);
  showLoading();

  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: formattedUrl }),
    });

    const data = await response.json();

    if (!response.ok) {
      const msg = data.detail?.message || data.message || 'An error occurred during analysis.';
      showError(msg);
      return;
    }

    currentAnalysisResult = data;
    renderResult(data);
  } catch {
    showError('Could not connect to the PhishGuard analysis service. Ensure backend is running.');
  }
}

// ── Result rendering ──────────────────────────────────────────────────────

function renderResult(data) {
  const isPhishing = data.prediction === 'PHISHING';
  const confidencePct = Math.round(data.confidence * 100);

  // Verdict Banner styling
  verdictBanner.className = `verdict-banner ${data.prediction.toLowerCase()}`;
  verdictLabel.textContent = data.prediction;
  verdictUrl.textContent = data.url;
  verdictIcon.innerHTML = isPhishing
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>';

  riskBadge.textContent = `${data.risk_level} RISK`;

  // Plain-language verdict summary
  verdictSummary.className = `verdict-summary ${data.prediction.toLowerCase()}`;
  verdictSummary.innerHTML = buildVerdictSummary(data);

  // Confidence Bar
  confidenceValue.textContent = `${confidencePct}%`;
  confidenceFill.style.width = `${confidencePct}%`;
  confidenceFill.style.backgroundColor = isPhishing
    ? (confidencePct > 75 ? 'var(--color-phish)' : 'var(--color-warn)')
    : 'var(--color-legit)';

  // Explanation Items with SHAP magnitude bars
  explanationList.innerHTML = '';
  const items = data.explanation || [];
  const maxAbs = Math.max(...items.map(i => Math.abs(i.shap_value || 0)), 0.0001);
  if (items.length > 0) {
    items.forEach(item => {
      const li = document.createElement('li');
      li.className = 'explanation-item';

      const isPushingPhish = item.direction === 'phishing';
      const bulletSymbol = isPushingPhish ? '⚠' : '✓';
      const bulletClass = isPushingPhish ? 'phishing' : 'legitimate';
      const barWidth = Math.min(100, Math.max(4, (Math.abs(item.shap_value) / maxAbs) * 100));

      li.innerHTML = `
        <span class="exp-bullet ${bulletClass}" aria-hidden="true">${bulletSymbol}</span>
        <div class="exp-content">
          <div class="exp-label" title="SHAP contribution: ${escapeHtml(String(item.shap_value))}">${escapeHtml(item.label)}</div>
          <div class="exp-detail">
            VALUE: <code>${escapeHtml(String(item.value))}</code> &bull;
            IMPACT: <strong>${item.impact.toUpperCase()}</strong> (${item.direction})
          </div>
          <div class="exp-bar" aria-hidden="true">
            <div class="exp-bar-fill ${bulletClass}" style="width: ${barWidth}%"></div>
          </div>
        </div>
      `;
      explanationList.appendChild(li);
    });
  } else {
    explanationList.innerHTML = '<li class="explanation-item">No strong feature indicators detected.</li>';
  }

  // Reset "show all features" disclosure
  allFeaturesGrid.hidden = true;
  allFeaturesGrid.innerHTML = '';
  showAllBtn.setAttribute('aria-expanded', 'false');

  saveToHistory(data);
  hideLoading();
  resultState.hidden = false;
  if (isPhishing) playError();
  else playSuccess();
}

// ── UI state toggles ──────────────────────────────────────────────────────

function setLoadingStep(index) {
  loadingSteps.forEach((el, i) => {
    if (!el) return;
    el.classList.toggle('active', i === index);
    el.classList.toggle('done', i < index);
  });
}

function startLoadingSteps() {
  setLoadingStep(0);
  clearInterval(loadingStepTimer);
  let current = 0;
  loadingStepTimer = setInterval(() => {
    current += 1;
    if (current < loadingSteps.length) {
      setLoadingStep(current);
    } else {
      clearInterval(loadingStepTimer);
    }
  }, LOADING_STEP_INTERVAL_MS);
}

function stopLoadingSteps() {
  clearInterval(loadingStepTimer);
  loadingStepTimer = null;
  setLoadingStep(0);
}

function showLoading() {
  submitBtn.disabled = true;
  resultDivider.hidden = false;
  loadingState.hidden = false;
  resultState.hidden = true;
  errorState.hidden = true;
  startLoadingSteps();
}

function hideLoading() {
  submitBtn.disabled = false;
  loadingState.hidden = true;
  stopLoadingSteps();
}

function showError(msg) {
  hideLoading();
  errorMessage.textContent = msg;
  errorState.hidden = false;
  resultState.hidden = true;
  playError();
}

function resetForm() {
  input.value = '';
  resultDivider.hidden = true;
  resultState.hidden = true;
  errorState.hidden = true;
  loadingState.hidden = true;
  hideInputError();
  input.focus();
}

function showInputError(msg) {
  inputError.textContent = msg;
  inputError.hidden = false;
  inputGroup.style.borderColor = 'var(--color-phish)';
}

function hideInputError() {
  inputError.hidden = true;
  inputGroup.style.borderColor = '';
}

function copyResult() {
  if (!currentAnalysisResult) return;
  const text = buildCopyText(currentAnalysisResult);
  navigator.clipboard.writeText(text).then(() => {
    const originalText = copyResultBtn.innerHTML;
    copyResultBtn.innerHTML = '[ ✓ COPIED ]';
    window.setTimeout(() => { copyResultBtn.innerHTML = originalText; }, 2000);
  });
}

// ── "Show all features" progressive disclosure ────────────────────────────

async function toggleAllFeatures() {
  if (allFeaturesGrid.hidden) {
    if (!featureLabels) {
      try {
        const resp = await fetch(`${API_BASE_URL}/api/features`);
        if (resp.ok) {
          const meta = await resp.json();
          featureLabels = meta.feature_labels || {};
        }
      } catch {
        featureLabels = {};
      }
    }
    renderAllFeatures(currentAnalysisResult?.features || {});
    allFeaturesGrid.hidden = false;
    showAllBtn.setAttribute('aria-expanded', 'true');
  } else {
    allFeaturesGrid.hidden = true;
    showAllBtn.setAttribute('aria-expanded', 'false');
  }
}

function renderAllFeatures(features) {
  allFeaturesGrid.innerHTML = '';
  Object.keys(features).forEach(name => {
    const cell = document.createElement('div');
    cell.className = 'feature-cell';
    cell.innerHTML = `
      <span class="feature-cell-name" title="${escapeHtml(name)}">${escapeHtml(featureLabels?.[name] || name)}</span>
      <span class="feature-cell-value">${escapeHtml(String(features[name]))}</span>
    `;
    allFeaturesGrid.appendChild(cell);
  });
}

// ── Recent scans history (localStorage) ───────────────────────────────────

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
  } catch {
    return [];
  }
}

function saveToHistory(data) {
  const history = loadHistory();
  const entry = {
    url: data.url,
    prediction: data.prediction,
    risk_level: data.risk_level,
    confidence: data.confidence,
    timestamp: data.timestamp || new Date().toISOString(),
  };
  localStorage.setItem(HISTORY_KEY, JSON.stringify(prependHistoryEntry(history, entry, HISTORY_MAX)));
  renderHistory();
}

function renderHistory() {
  const history = loadHistory();
  historySection.hidden = history.length === 0;
  historyList.innerHTML = '';
  history.forEach((entry) => {
    const li = document.createElement('li');
    li.className = 'history-item';
    li.tabIndex = 0;
    li.setAttribute('role', 'button');
    li.setAttribute('aria-label', `Re-analyze ${entry.url}`);
    li.innerHTML = `
      <span class="history-item-dot ${entry.prediction.toLowerCase()}" aria-hidden="true"></span>
      <span class="history-item-url">${escapeHtml(entry.url)}</span>
      <span class="history-item-confidence">${entry.prediction} · ${Math.round(entry.confidence * 100)}%</span>
    `;
    li.addEventListener('click', () => reanalyzeFromHistory(entry));
    li.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        reanalyzeFromHistory(entry);
      }
    });
    historyList.appendChild(li);
  });
}

function reanalyzeFromHistory(entry) {
  input.value = entry.url;
  hideInputError();
  form.requestSubmit();
}

function clearHistory() {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
}
