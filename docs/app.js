/* ==========================================================================
   PhishGuard — Frontend Application Logic
   ========================================================================== */

// Base API URL (falls back to relative path for production deployment)
const API_BASE_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://localhost:8000'
  : '';

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

const confidenceValue = document.getElementById('confidence-value');
const confidenceFill = document.getElementById('confidence-fill');
const explanationList = document.getElementById('explanation-list');

const analyzeAnotherBtn = document.getElementById('analyze-another-btn');
const copyResultBtn = document.getElementById('copy-result-btn');
const retryBtn = document.getElementById('retry-btn');

let currentAnalysisResult = null;

// Event Listeners
form.addEventListener('submit', handleSubmit);
sampleLegit.addEventListener('click', () => useSample(sampleLegit.dataset.url));
samplePhish.addEventListener('click', () => useSample(samplePhish.dataset.url));
analyzeAnotherBtn.addEventListener('click', resetForm);
retryBtn.addEventListener('click', resetForm);
copyResultBtn.addEventListener('click', copyResult);

input.addEventListener('input', () => {
  hideInputError();
});

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

  // Confidence Bar
  confidenceValue.textContent = `${confidencePct}%`;
  confidenceFill.style.width = `${confidencePct}%`;
  confidenceFill.style.backgroundColor = isPhishing 
    ? (confidencePct > 75 ? 'var(--color-phish)' : 'var(--color-warn)')
    : 'var(--color-legit)';

  // Explanation Items
  explanationList.innerHTML = '';
  if (data.explanation && data.explanation.length > 0) {
    data.explanation.forEach(item => {
      const li = document.createElement('li');
      li.className = 'explanation-item';
      
      const isPushingPhish = item.direction === 'phishing';
      const bulletSymbol = isPushingPhish ? '⚠' : '✓';
      const bulletClass = isPushingPhish ? 'phishing' : 'legitimate';

      li.innerHTML = `
        <span class="exp-bullet ${bulletClass}">${bulletSymbol}</span>
        <div class="exp-content">
          <div class="exp-label">${escapeHtml(item.label)}</div>
          <div class="exp-detail">
            Value: <code>${escapeHtml(String(item.value))}</code> &bull; 
            Impact: <strong>${item.impact.toUpperCase()}</strong> (${item.direction})
          </div>
        </div>
      `;
      explanationList.appendChild(li);
    });
  } else {
    explanationList.innerHTML = '<li class="explanation-item">No strong feature indicators detected.</li>';
  }

  hideLoading();
  resultState.hidden = false;
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

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, match => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[match]));
}
