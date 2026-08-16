/* ==========================================================================
   PhishGuard — Frontend Application Logic
   ========================================================================== */

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

let currentAnalysisResult = null;
let featureLabels = null;
const HISTORY_KEY = 'phishguard.history';
const HISTORY_MAX = 8;

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

// Use Sample URL
function useSample(url) {
  input.value = url;
  hideInputError();
  form.requestSubmit();
}

// Form Submission Handler
async function handleSubmit(e) {
  e.preventDefault();
  const url = input.value.trim();

  // Basic client-side validation
  if (!url) {
    showInputError('Please enter a URL to analyze.');
    return;
  }

  // Auto-prepend scheme if omitted
  let formattedUrl = url;
  if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://') && !formattedUrl.startsWith('ftp://')) {
    formattedUrl = 'https://' + formattedUrl;
    input.value = formattedUrl;
  }

  hideInputError();
  showLoading();

  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    if (!response.ok) {
      const msg = data.detail?.message || data.message || 'An error occurred during analysis.';
      showError(msg);
      return;
    }

    currentAnalysisResult = data;
    renderResult(data);
  } catch (err) {
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
  verdictIcon.textContent = isPhishing ? '🚨' : '🛡️';

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

// Build a plain-language summary sentence from the prediction + top factors.
function buildVerdictSummary(data) {
  const isPhishing = data.prediction === 'PHISHING';
  const pct = Math.round(data.confidence * 100);
  const items = (data.explanation || []).slice(0, 3);
  const labels = items.map(i => i.label.toLowerCase()).filter(Boolean);

  if (isPhishing) {
    const parts = labels.length
      ? [` It shows signs of ${labels.join(', ')}.`]
      : [];
    return `This URL appears to be <strong class="phishing">phishing</strong> ` +
      `(high probability: ${pct}%).${parts.join('')} Avoid entering any personal information.`;
  }
  return `This URL appears <strong class="legitimate">legitimate</strong> ` +
    `(${pct}% confidence). It shows no strong phishing indicators.`;
}

// UI State Toggles
function showLoading() {
  submitBtn.disabled = true;
  resultDivider.hidden = false;
  loadingState.hidden = false;
  resultState.hidden = true;
  errorState.hidden = true;
}

function hideLoading() {
  submitBtn.disabled = false;
  loadingState.hidden = true;
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
  const text = `PhishGuard Analysis:\nURL: ${currentAnalysisResult.url}\nVerdict: ${currentAnalysisResult.prediction} (${currentAnalysisResult.confidence * 100}% confidence)\nRisk Level: ${currentAnalysisResult.risk_level}`;
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
      } catch (err) {
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
  } catch (err) {
    return [];
  }
}

function saveToHistory(data) {
  const history = loadHistory();
  history.unshift({
    url: data.url,
    prediction: data.prediction,
    risk_level: data.risk_level,
    confidence: data.confidence,
    timestamp: data.timestamp || new Date().toISOString(),
  });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, HISTORY_MAX)));
  renderHistory();
}

function renderHistory() {
  const history = loadHistory();
  historySection.hidden = history.length === 0;
  historyList.innerHTML = '';
  history.forEach((entry, index) => {
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

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, match => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[match]));
}
