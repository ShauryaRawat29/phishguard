/* ==========================================================================
   PhishGuard — Frontend Application Logic
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

// DOM Elements
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

let currentAnalysisResult = null;
let featureLabels = null;
let loadingStepTimer = null;
const HISTORY_KEY = 'phishguard.history';
const HISTORY_MAX = 8;
const LOADING_STEP_INTERVAL_MS = 1200;

// Event Listeners
form.addEventListener('submit', handleSubmit);
sampleLegit.addEventListener('click', () => useSample(sampleLegit.dataset.url));
samplePhish.addEventListener('click', () => useSample(samplePhish.dataset.url));
analyzeAnotherBtn.addEventListener('click', resetForm);
retryBtn.addEventListener('click', resetForm);
copyResultBtn.addEventListener('click', copyResult);
showAllBtn.addEventListener('click', toggleAllFeatures);
historyClearBtn.addEventListener('click', clearHistory);

input.addEventListener('input', () => {
  hideInputError();
});

renderHistory();
initTilt();

// Subtle pointer tilt for product surfaces (hero analyzer + mockup).
function initTilt() {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (!window.matchMedia('(hover: hover)').matches) return;
  const MAX_TILT_DEG = 3;
  document.querySelectorAll('[data-tilt]').forEach((el) => {
    el.addEventListener('mousemove', (e) => {
      const rect = el.getBoundingClientRect();
      const px = (e.clientX - rect.left) / rect.width - 0.5;
      const py = (e.clientY - rect.top) / rect.height - 0.5;
      el.style.transform = `perspective(900px) rotateX(${(-py * MAX_TILT_DEG).toFixed(2)}deg) rotateY(${(px * MAX_TILT_DEG).toFixed(2)}deg)`;
    });
    el.addEventListener('mouseleave', () => {
      el.style.transform = '';
    });
  });
}

// Use Sample URL
function useSample(url) {
  input.value = url;
  hideInputError();
  form.requestSubmit();
}

// Form Submission Handler
async function handleSubmit(e) {
  e.preventDefault();

  // Client-side validation mirrors backend/services/validator.py.
  const { url: formattedUrl, error } = normalizeUrl(input.value);
  if (error) {
    showInputError(error);
    return;
  }
  input.value = formattedUrl;

  hideInputError();
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

// Render Result Card
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
            Value: <code>${escapeHtml(String(item.value))}</code> &bull;
            Impact: <strong>${item.impact.toUpperCase()}</strong> (${item.direction})
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
}

// UI State Toggles
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
    copyResultBtn.innerHTML = '✓ Copied!';
    setTimeout(() => { copyResultBtn.innerHTML = originalText; }, 2000);
  });
}

// ── "Show all features" progressive disclosure ──────────────────────────────

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

// ── Recent scans history (localStorage) ─────────────────────────────────────

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
