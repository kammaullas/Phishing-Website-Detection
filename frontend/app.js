/**
 * PhishGuard ML — Frontend Logic
 * Handles URL scanning, result rendering, and scan history.
 */

const API_BASE = 'http://localhost:8000';

// --- DOM Elements ---
const scanForm = document.getElementById('scan-form');
const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const loading = document.getElementById('loading');
const results = document.getElementById('results');
const errorAlert = document.getElementById('error-alert');
const errorMessage = document.getElementById('error-message');

// Verdict
const verdictCard = document.getElementById('verdict-card');
const verdictUrl = document.getElementById('verdict-url');
const verdictIcon = document.getElementById('verdict-icon');
const verdictLabel = document.getElementById('verdict-label');
const confidencePct = document.getElementById('confidence-pct');
const confidenceFill = document.getElementById('confidence-fill');

// Lists
const riskList = document.getElementById('risk-list');
const safetyList = document.getElementById('safety-list');
const shapList = document.getElementById('shap-list');
const featuresGrid = document.getElementById('features-grid');
const historyList = document.getElementById('history-list');

// Toggle
const featuresToggleBtn = document.getElementById('features-toggle-btn');

// --- Scan History ---
let scanHistory = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
renderHistory();

// --- Feature Name Formatting ---
function formatFeatureName(name) {
    return name
        .replace(/_/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase())
        .replace('Url', 'URL')
        .replace('Ip', 'IP')
        .replace('Https', 'HTTPS')
        .replace('Tld', 'TLD')
        .replace('Shap', 'SHAP');
}

// --- Form Submit ---
scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const url = urlInput.value.trim();
    if (!url) return;

    // Reset UI
    hideError();
    results.classList.remove('active');
    loading.classList.add('active');
    scanBtn.disabled = true;
    confidenceFill.style.width = '0%';

    try {
        const response = await fetch(`${API_BASE}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Server error (${response.status})`);
        }

        const data = await response.json();
        renderResults(data);
        addToHistory(data);

    } catch (err) {
        showError(err.message || 'Failed to connect to the backend. Is the FastAPI server running?');
    } finally {
        loading.classList.remove('active');
        scanBtn.disabled = false;
    }
});

// --- Render Results ---
function renderResults(data) {
    const isPhishing = data.verdict === 'phishing';
    const confidence = (data.confidence * 100).toFixed(1);

    // Verdict card
    verdictCard.className = `verdict-card ${data.verdict}`;
    verdictUrl.textContent = data.url;
    verdictIcon.textContent = isPhishing ? '🚫' : '✅';
    verdictLabel.textContent = isPhishing ? 'Phishing Detected' : 'Legitimate Website';
    confidencePct.textContent = `${confidence}%`;

    // Animate confidence bar
    setTimeout(() => {
        confidenceFill.style.width = `${confidence}%`;
    }, 100);

    // Risk indicators
    riskList.innerHTML = '';
    if (data.risk_indicators && data.risk_indicators.length > 0) {
        data.risk_indicators.forEach(text => {
            riskList.innerHTML += `
                <li class="indicator-item">
                    <span class="indicator-dot risk"></span>
                    <span>${text}</span>
                </li>`;
        });
    } else {
        riskList.innerHTML = '<div class="no-indicators">No risk indicators found</div>';
    }

    // Safety indicators
    safetyList.innerHTML = '';
    if (data.safety_indicators && data.safety_indicators.length > 0) {
        data.safety_indicators.forEach(text => {
            safetyList.innerHTML += `
                <li class="indicator-item">
                    <span class="indicator-dot safe"></span>
                    <span>${text}</span>
                </li>`;
        });
    } else {
        safetyList.innerHTML = '<div class="no-indicators">No safety signals found</div>';
    }

    // SHAP breakdown
    shapList.innerHTML = '';
    if (data.top_drivers) {
        const maxContrib = Math.max(...data.top_drivers.map(d => Math.abs(d.contribution)), 0.001);

        data.top_drivers.forEach((driver, i) => {
            const isRisk = driver.contribution > 0;
            const barWidth = Math.min((Math.abs(driver.contribution) / maxContrib) * 100, 100);
            const dirClass = isRisk ? 'risk' : 'safe';
            const dirText = isRisk ? '↑ Risk' : '↓ Safe';

            shapList.innerHTML += `
                <div class="shap-item" style="animation: fadeIn 0.3s ease ${i * 0.05}s both">
                    <div>
                        <div class="shap-feature">${formatFeatureName(driver.feature)}</div>
                        <div class="shap-value">= ${driver.actual_value}</div>
                    </div>
                    <div class="shap-bar-track">
                        <div class="shap-bar-fill ${dirClass}" style="width: 0%"
                             data-target-width="${barWidth}%"></div>
                    </div>
                    <div class="shap-direction ${dirClass}">${dirText}</div>
                </div>`;
        });

        // Animate bars after render
        setTimeout(() => {
            document.querySelectorAll('.shap-bar-fill[data-target-width]').forEach(bar => {
                bar.style.width = bar.dataset.targetWidth;
            });
        }, 100);
    }

    // All features
    featuresGrid.innerHTML = '';
    if (data.features) {
        // Close the toggle if it was open
        featuresGrid.classList.remove('open');
        featuresToggleBtn.classList.remove('open');

        Object.entries(data.features).forEach(([key, val]) => {
            const displayVal = typeof val === 'number' ? (Number.isInteger(val) ? val : val.toFixed(4)) : val;
            featuresGrid.innerHTML += `
                <div class="feature-chip">
                    <span class="feature-chip-name">${formatFeatureName(key)}</span>
                    <span class="feature-chip-value">${displayVal}</span>
                </div>`;
        });
    }

    // Show results
    results.classList.add('active');

    // Scroll to results smoothly
    verdictCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// --- Features Toggle ---
featuresToggleBtn.addEventListener('click', () => {
    featuresGrid.classList.toggle('open');
    featuresToggleBtn.classList.toggle('open');
});

// --- Error Handling ---
function showError(msg) {
    errorMessage.textContent = msg;
    errorAlert.classList.add('active');
}

function hideError() {
    errorAlert.classList.remove('active');
}

// --- Scan History ---
function addToHistory(data) {
    const entry = {
        url: data.url,
        verdict: data.verdict,
        confidence: data.confidence,
        timestamp: new Date().toISOString()
    };

    // Remove duplicate if exists
    scanHistory = scanHistory.filter(h => h.url !== data.url);

    // Add to front
    scanHistory.unshift(entry);

    // Keep max 20
    if (scanHistory.length > 20) scanHistory = scanHistory.slice(0, 20);

    localStorage.setItem('phishguard_history', JSON.stringify(scanHistory));
    renderHistory();
}

function renderHistory() {
    if (scanHistory.length === 0) {
        historyList.innerHTML = '<div class="history-empty">No scans yet. Enter a URL above to get started.</div>';
        return;
    }

    historyList.innerHTML = scanHistory.map(entry => {
        const isPhishing = entry.verdict === 'phishing';
        const conf = (entry.confidence * 100).toFixed(0);

        return `
            <div class="history-item" onclick="rescan('${entry.url.replace(/'/g, "\\'")}')">
                <span class="history-dot ${entry.verdict}"></span>
                <span class="history-url" title="${entry.url}">${entry.url}</span>
                <span class="history-verdict ${entry.verdict}">${entry.verdict}</span>
                <span class="history-confidence">${conf}%</span>
            </div>`;
    }).join('');
}

function rescan(url) {
    urlInput.value = url;
    scanForm.dispatchEvent(new Event('submit'));
}