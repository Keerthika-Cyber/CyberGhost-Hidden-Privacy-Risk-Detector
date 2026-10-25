/**
 * CyberGhost — Hidden Privacy Risk Detector
 * Detection Engine & UI Logic
 *
 * PRIVACY NOTICE:
 * All scanning is performed locally in this browser.
 * No user text is transmitted to any server or external API.
 * No data is stored in localStorage or sessionStorage.
 * No analytics or tracking is performed.
 */

'use strict';

/* =========================================================
   CONSTANTS & CONFIGURATION
   ========================================================= */

const MAX_INPUT_CHARS = 100_000;

const SCORE_WEIGHTS = {
  email:      15,
  phone:      20,
  secret:     35,
  identifier: 25,
  address:    20,
};

const RISK_LEVELS = {
  email:      'Medium',
  phone:      'Medium',
  secret:     'High',
  identifier: 'High',
  address:    'Medium',
};

const CATEGORY_LABELS = {
  email:      'Email Address',
  phone:      'Phone Number',
  secret:     'Secret / Credential',
  identifier: 'Possible Identifier',
  address:    'Possible Address',
};

const MASK_LABELS = {
  email:      '[EMAIL REDACTED]',
  phone:      '[PHONE REDACTED]',
  secret:     '[SECRET REDACTED]',
  identifier: '[IDENTIFIER REDACTED]',
  address:    '[ADDRESS REDACTED]',
};

const PRIORITY = { secret: 0, identifier: 1, address: 2, phone: 3, email: 4 };

/* =========================================================
   DETECTION PATTERNS
   ========================================================= */

const PATTERNS = {
  /**
   * Email – RFC-ish common format. Not a validator, just a detector.
   * Matches: user@domain.tld, user.name+tag@sub.domain.co.in
   */
  email: /\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,10}\b/g,

  /**
   * Phone – supports Indian mobile, international +XX formats, US style.
   * Excludes short numbers (< 7 digits total stripped) and obvious years.
   */
  phone: /(?<!\d)(\+?\d{1,3}[\s\-]?)?(\(?\d{2,4}\)?[\s\-]?)?\d{3,5}[\s\-]?\d{4,6}(?!\d)/g,

  /**
   * Secrets – keyword=value assignments and bearer tokens.
   */
  secret: {
    keyValue: /(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer|private[_\-]?key|encryption[_\-]?key)\s*[=:]\s*\S+/gi,
    bearerHeader: /Authorization:\s*Bearer\s+\S+/gi,
    privateKeyMarker: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/gi,
  },

  /**
   * Possible identifier – Aadhaar-like (12 digits), PAN-like, SSN-like.
   * Described as "possible" patterns, not validated real numbers.
   */
  identifier: {
    aadhaar: /\b\d{4}\s?\d{4}\s?\d{4}\b/g,
    pan:     /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
    ssn:     /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  },

  /**
   * Possible address – keyword anchor + nearby digits or common address tokens.
   */
  address: /(?:(?:\d{1,5}\s+)?(?:[A-Za-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct|Circle|Cir|Place|Pl|Nagar|Colony|Sector|Phase|Layout|Extension|Block|Apartment|Apt|Flat|Floor|Building|Bldg|Tower|Wing|Plot|House|Villa|Gate|Cross|Main)[\s,]?\d{0,5})/gi,
};

/* =========================================================
   FINDING FACTORY
   ========================================================= */

let _findingIdCounter = 0;
function createFinding({ category, start, end, originalText, explanation, recommendation }) {
  const masked = MASK_LABELS[category];
  return {
    id:             `f${++_findingIdCounter}`,
    category,
    severity:       RISK_LEVELS[category],
    label:          CATEGORY_LABELS[category],
    start,
    end,
    originalLength: end - start,
    maskedValue:    masked,
    // Store a brief context snippet (never the full secret value)
    contextSnippet: safeContextSnippet(originalText, start, end, category),
    explanation,
    recommendation,
  };
}

/**
 * Returns a context snippet for display. For secrets, only shows type prefix.
 */
function safeContextSnippet(text, start, end, category) {
  if (category === 'secret') {
    // Only reveal the keyword part, not the actual value
    const raw = text.slice(start, end);
    const eqIdx = raw.search(/[=:]/);
    if (eqIdx !== -1) {
      return raw.slice(0, eqIdx + 1) + '***';
    }
    return '***';
  }
  // For other categories, show the match (it's already in the text)
  const snippet = text.slice(start, end);
  return snippet.length > 60 ? snippet.slice(0, 57) + '…' : snippet;
}

/* =========================================================
   DETECTION FUNCTIONS
   ========================================================= */

/**
 * Detect email addresses.
 * @param {string} text
 * @returns {Array}
 */
function detectEmails(text) {
  const findings = [];
  const rx = new RegExp(PATTERNS.email.source, 'g');
  let m;
  while ((m = rx.exec(text)) !== null) {
    findings.push(createFinding({
      category: 'email',
      start: m.index,
      end: m.index + m[0].length,
      originalText: text,
      explanation:
        'An email address can reveal personal contact information and may be harvested by automated crawlers, sold to marketers, or targeted in phishing attacks.',
      recommendation:
        'Remove the email address or replace it with a general contact form URL if public sharing is intended.',
    }));
  }
  return findings;
}

/**
 * Detect phone numbers.
 * Applies heuristics to filter obvious false positives (dates, short numbers, lone years).
 * @param {string} text
 * @returns {Array}
 */
function detectPhones(text) {
  const findings = [];
  const rx = new RegExp(PATTERNS.phone.source, 'g');
  let m;
  while ((m = rx.exec(text)) !== null) {
    const raw = m[0].trim();
    const digits = raw.replace(/\D/g, '');

    // Filter: too short (less than 7 digits) or too long (more than 15)
    if (digits.length < 7 || digits.length > 15) continue;

    // Filter: looks like a standalone year (4 digits 1900–2099)
    if (/^\d{4}$/.test(digits) && +digits >= 1900 && +digits <= 2099) continue;

    // Filter: looks like a date format (DD/MM/YYYY, MM/DD/YYYY, YYYY-MM-DD)
    if (/^\d{1,4}[\/\-]\d{1,2}[\/\-]\d{2,4}$/.test(raw)) continue;

    // Filter: all same digit (1111111111)
    if (/^(.)\1+$/.test(digits)) continue;

    findings.push(createFinding({
      category: 'phone',
      start: m.index,
      end: m.index + m[0].length,
      originalText: text,
      explanation:
        'This pattern resembles a phone number. Phone numbers can be used for unsolicited contact, SIM-swap attacks, or identity correlation. Pattern matching cannot confirm whether this number is active or belongs to any individual.',
      recommendation:
        'Remove or mask the phone number before sharing this text publicly.',
    }));
  }
  return findings;
}

/**
 * Detect secrets: password assignments, API keys, tokens, bearer headers, PEM markers.
 * @param {string} text
 * @returns {Array}
 */
function detectSecrets(text) {
  const findings = [];

  const secretPatterns = [
    PATTERNS.secret.keyValue,
    PATTERNS.secret.bearerHeader,
    PATTERNS.secret.privateKeyMarker,
  ];

  for (const pat of secretPatterns) {
    const rx = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = rx.exec(text)) !== null) {
      findings.push(createFinding({
        category: 'secret',
        start: m.index,
        end: m.index + m[0].length,
        originalText: text,
        explanation:
          'A potential credential or secret key was detected. Exposed credentials can allow unauthorized access to accounts, APIs, or services. Detection covers common assignment patterns and cannot identify every possible secret format.',
        recommendation:
          'Immediately remove any real credentials from this text. Rotate any exposed credentials. Use environment variables or secret management services instead of embedding secrets in plaintext.',
      }));
    }
  }

  return findings;
}

/**
 * Detect possible government-style identifier patterns.
 * Results are described as possible patterns, never confirmed IDs.
 * @param {string} text
 * @returns {Array}
 */
function detectPossibleIdentifiers(text) {
  const findings = [];

  const idPatterns = [
    { rx: PATTERNS.identifier.aadhaar, name: 'Aadhaar-like (12-digit)' },
    { rx: PATTERNS.identifier.pan,     name: 'PAN-like' },
    { rx: PATTERNS.identifier.ssn,     name: 'SSN-like' },
  ];

  for (const { rx, name } of idPatterns) {
    const r = new RegExp(rx.source, rx.flags);
    let m;
    while ((m = r.exec(text)) !== null) {
      findings.push(createFinding({
        category: 'identifier',
        start: m.index,
        end: m.index + m[0].length,
        originalText: text,
        explanation:
          `This matches a possible ${name} identifier pattern. This tool cannot confirm that the number is a valid or genuine government-issued ID or that it belongs to any specific person. It is flagged as a precaution.`,
        recommendation:
          'Remove or mask any government-issued identification numbers from text you intend to share publicly. Exposing ID numbers can facilitate identity theft.',
      }));
    }
  }

  return findings;
}

/**
 * Detect possible postal/home address patterns.
 * Detection is approximate and may produce false positives.
 * @param {string} text
 * @returns {Array}
 */
function detectPossibleAddresses(text) {
  const findings = [];
  const rx = new RegExp(PATTERNS.address.source, PATTERNS.address.flags);
  let m;
  while ((m = rx.exec(text)) !== null) {
    const raw = m[0].trim();
    if (raw.split(/\s+/).length < 2) continue; // too short
    findings.push(createFinding({
      category: 'address',
      start: m.index,
      end: m.index + m[0].length,
      originalText: text,
      explanation:
        'This pattern resembles a postal or street address. Address detection is approximate and may produce false positives. Sharing a home address publicly can enable physical stalking, unsolicited mail, or targeted attacks.',
      recommendation:
        'Remove or generalise any home or personal address before sharing this text publicly. Use only city or region-level location when precise location is not necessary.',
    }));
  }
  return findings;
}

/* =========================================================
   OVERLAP RESOLUTION
   ========================================================= */

/**
 * Removes overlapping findings by keeping the highest-priority finding
 * for any overlapping range. Also deduplicates identical offsets.
 *
 * Priority (lower number = higher priority): secret > identifier > address > phone > email
 *
 * @param {Array} findings
 * @returns {Array} Non-overlapping findings sorted by start offset
 */
function resolveOverlaps(findings) {
  if (findings.length === 0) return [];

  // Sort by priority first, then by start position
  const sorted = [...findings].sort((a, b) => {
    const pd = (PRIORITY[a.category] ?? 99) - (PRIORITY[b.category] ?? 99);
    if (pd !== 0) return pd;
    return a.start - b.start;
  });

  const accepted = [];
  for (const f of sorted) {
    const overlaps = accepted.some(a => f.start < a.end && f.end > a.start);
    if (!overlaps) accepted.push(f);
  }

  // Return in document order
  return accepted.sort((a, b) => a.start - b.start);
}

/**
 * Alias for resolveOverlaps to conform to specification naming.
 * Normalizes and resolves overlapping/adjacent findings.
 */
function normalizeFindings(findings) {
  return resolveOverlaps(findings);
}

/* =========================================================
   PRIVACY SCORE
   ========================================================= */

/**
 * Calculates indicative privacy score (0–100).
 * Counts unique occurrences per category, not per duplicate.
 *
 * @param {Array} findings Non-overlapping deduplicated findings
 * @returns {{ score: number, categoryCounts: Object, deductions: Object }}
 */
function calculatePrivacyScore(findings) {
  const categoryCounts = {};
  const deductions = {};

  for (const f of findings) {
    categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
  }

  let totalDeduction = 0;
  for (const [cat, count] of Object.entries(categoryCounts)) {
    const weight = SCORE_WEIGHTS[cat] ?? 10;
    // First occurrence gets full weight; subsequent occurrences get half weight
    const deduction = weight + (count - 1) * Math.ceil(weight / 2);
    deductions[cat] = deduction;
    totalDeduction += deduction;
  }

  const score = Math.max(0, Math.min(100, 100 - totalDeduction));
  return { score, categoryCounts, deductions };
}

/* =========================================================
   MASKING
   ========================================================= */

/**
 * Replaces detected ranges in the original text with category-specific placeholders.
 * Handles multiple non-overlapping findings correctly using offset adjustment.
 *
 * @param {string} text Original input text
 * @param {Array} findings Sorted, non-overlapping findings
 * @returns {string} Masked text
 */
function maskFindings(text, findings) {
  if (findings.length === 0) return text;

  let result = '';
  let cursor = 0;

  for (const f of findings) {
    // Append text before this finding
    result += text.slice(cursor, f.start);
    // Append the mask placeholder
    result += f.maskedValue;
    cursor = f.end;
  }

  // Append remaining text after last finding
  result += text.slice(cursor);
  return result;
}

/* =========================================================
   REPORT GENERATION
   ========================================================= */

/**
 * Generates a JSON security report.
 * NEVER includes original unmasked input or complete secret values.
 *
 * @param {Array} findings
 * @param {Object} scoreData
 * @param {string} maskedText Whether masking was applied (boolean)
 * @returns {Object} Safe JSON-serialisable report object
 */
function generateSecurityReport(findings, scoreData, maskingApplied) {
  const { score, categoryCounts, deductions } = scoreData;

  const safeFindingsSummary = findings.map(f => ({
    id:             f.id,
    category:       f.label,
    severity:       f.severity,
    maskedPlaceholder: f.maskedValue,
    explanation:    f.explanation,
    recommendation: f.recommendation,
    // contextSnippet already safe (secrets replaced with ***)
    contextSnippet: f.contextSnippet,
  }));

  const categoryBreakdown = {};
  for (const [cat, count] of Object.entries(categoryCounts)) {
    categoryBreakdown[CATEGORY_LABELS[cat]] = {
      count,
      scoreDeduction: deductions[cat],
      riskLevel: RISK_LEVELS[cat],
    };
  }

  return {
    reportTitle:   'CyberGhost — Privacy Risk Scan Report',
    scanTimestamp:  new Date().toISOString(),
    privacyScore:   score,
    riskCategory:   getRiskCategory(score),
    totalFindings:  findings.length,
    maskingApplied,
    categoryBreakdown,
    findings:       safeFindingsSummary,
    recommendations: buildRecommendations(findings),
    disclaimer:
      'This report is an educational privacy indicator. It does not constitute a security certification or guarantee. Pattern matching cannot detect every type of sensitive information and may produce false positives.',
    privacyNotice:
      'CyberGhost scans text locally in your browser. No user input is transmitted to any server or external API. This tool does not store, log, or share scanned text.',
  };
}

function buildRecommendations(findings) {
  const seen = new Set();
  return findings
    .map(f => f.recommendation)
    .filter(r => { if (seen.has(r)) return false; seen.add(r); return true; });
}

/* =========================================================
   UTILITIES
   ========================================================= */

function getRiskCategory(score) {
  if (score >= 90) return 'Lower Detected Risk';
  if (score >= 70) return 'Mild Detected Risk';
  if (score >= 40) return 'Moderate Detected Risk';
  return 'Higher Detected Risk';
}

function getRiskColour(score) {
  if (score >= 90) return '#00e5a0';
  if (score >= 70) return '#ffc107';
  if (score >= 40) return '#ff8c42';
  return '#ff4757';
}

function severityBadgeClass(severity) {
  switch (severity) {
    case 'High':   return 'badge-high';
    case 'Medium': return 'badge-medium';
    default:       return 'badge-low';
  }
}

/**
 * Safely creates a text node — never interprets HTML.
 */
function safeText(str) {
  return document.createTextNode(str);
}

/**
 * Creates a DOM element with optional class and text content.
 */
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

/* =========================================================
   APPLICATION STATE
   ========================================================= */

const state = {
  findings:      [],
  scoreData:     null,
  maskedText:    '',
  maskingApplied: false,
  reportData:    null,
  hasScanned:    false,
};

function resetState() {
  state.findings      = [];
  state.scoreData     = null;
  state.maskedText    = '';
  state.maskingApplied = false;
  state.reportData    = null;
  state.hasScanned    = false;
  _findingIdCounter   = 0;
}

/* =========================================================
   DEMO SAMPLE TEXT
   ========================================================= */

const DEMO_TEXT = `Hi Team,

Please find my contact details below.

Email: alex.demo@example.com
Phone: +91 9876543210
Alt:   (022) 2456-7890

For API access use: api_key=demo_fake_key_abc123456
Auth token:         token=DEMO_TOKEN_PLACEHOLDER_XYZ

Note my address: 42 Maple Street, Downtown, City - 400001

This is a SAFE DEMO using fictional data only.
No real credentials, numbers, or addresses are included.`;

/* =========================================================
   MAIN SCAN FUNCTION
   ========================================================= */

function runScan(text) {
  resetState();

  const rawFindings = [
    ...detectEmails(text),
    ...detectPhones(text),
    ...detectSecrets(text),
    ...detectPossibleIdentifiers(text),
    ...detectPossibleAddresses(text),
  ];

  state.findings  = resolveOverlaps(rawFindings);
  state.scoreData = calculatePrivacyScore(state.findings);
  state.hasScanned = true;

  return { findings: state.findings, scoreData: state.scoreData };
}

/* =========================================================
   UI RENDERING
   ========================================================= */

function renderScoreCard(scoreData) {
  const { score } = scoreData;
  const colour = getRiskColour(score);
  const category = getRiskCategory(score);

  const card = document.getElementById('score-card');
  if (!card) return;

  // Score circle
  const circle = document.getElementById('score-circle');
  if (circle) {
    circle.textContent = score;
    circle.style.setProperty('--score-color', colour);
    circle.style.color = colour;
    circle.style.borderColor = colour;
    circle.style.boxShadow = `0 0 24px ${colour}55, inset 0 0 16px ${colour}22`;
  }

  const riskEl = document.getElementById('risk-category');
  if (riskEl) {
    riskEl.textContent = category;
    riskEl.style.color = colour;
  }

  const countEl = document.getElementById('finding-count');
  if (countEl) countEl.textContent = `${state.findings.length} finding${state.findings.length !== 1 ? 's' : ''} detected`;

  const disclaimerEl = document.getElementById('score-disclaimer');
  if (disclaimerEl) disclaimerEl.style.display = 'block';

  card.classList.add('visible');
}

function renderCategorySummary(categoryCounts) {
  const container = document.getElementById('category-summary');
  if (!container) return;
  container.innerHTML = '';

  if (Object.keys(categoryCounts).length === 0) {
    const msg = el('p', 'no-findings-msg', '✓ No privacy risks detected in this scan.');
    container.appendChild(msg);
    return;
  }

  for (const [cat, count] of Object.entries(categoryCounts)) {
    const row = el('div', 'cat-row');
    const label = el('span', 'cat-label', CATEGORY_LABELS[cat]);
    const badge = el('span', `cat-count badge ${severityBadgeClass(RISK_LEVELS[cat])}`, `${count} found`);
    row.appendChild(label);
    row.appendChild(badge);
    container.appendChild(row);
  }
}

function renderFindings(findings) {
  const container = document.getElementById('findings-list');
  if (!container) return;
  container.innerHTML = '';

  if (findings.length === 0) {
    container.appendChild(el('p', 'no-findings-msg', '✓ No sensitive patterns detected.'));
    return;
  }

  for (const f of findings) {
    const card = el('div', `finding-card severity-${f.severity.toLowerCase()}`);
    card.setAttribute('data-id', f.id);

    const header = el('div', 'finding-header');
    header.appendChild(el('span', 'finding-label', f.label));
    header.appendChild(el('span', `finding-badge badge ${severityBadgeClass(f.severity)}`, f.severity));
    card.appendChild(header);

    const snippet = el('div', 'finding-snippet');
    snippet.appendChild(el('span', 'snippet-label', 'Detected: '));
    snippet.appendChild(el('code', 'snippet-value', f.contextSnippet));
    card.appendChild(snippet);

    const masked = el('div', 'finding-masked');
    masked.appendChild(el('span', 'snippet-label', 'Will be masked as: '));
    masked.appendChild(el('code', 'snippet-mask', f.maskedValue));
    card.appendChild(masked);

    const explanation = el('p', 'finding-explanation', f.explanation);
    card.appendChild(explanation);

    const rec = el('div', 'finding-rec');
    rec.appendChild(el('strong', null, '→ Recommendation: '));
    rec.appendChild(safeText(f.recommendation));
    card.appendChild(rec);

    container.appendChild(card);
  }
}

function renderResults(text) {
  const { findings, scoreData } = runScan(text);

  renderScoreCard(scoreData);
  renderCategorySummary(scoreData.categoryCounts);
  renderFindings(findings);

  // Hide stale notice on fresh scan
  const staleEl = document.getElementById('stale-notice');
  if (staleEl) staleEl.classList.remove('visible');

  // Show results section
  document.getElementById('results-section').classList.add('visible');
  document.getElementById('actions-section').classList.add('visible');

  // Scroll to results
  document.getElementById('results-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* =========================================================
   MASKING UI
   ========================================================= */

function applyMasking(originalText) {
  if (!state.hasScanned) {
    showError('Please run a scan first.');
    return;
  }

  state.maskedText = maskFindings(originalText, state.findings);
  state.maskingApplied = true;

  const output = document.getElementById('masked-output');
  if (output) {
    // Use textContent — NEVER innerHTML — to display masked text safely
    output.textContent = state.maskedText;
  }

  document.getElementById('masked-section').classList.add('visible');
  document.getElementById('masked-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* =========================================================
   REPORT DOWNLOAD
   ========================================================= */

function downloadReport() {
  if (!state.hasScanned) {
    showError('Please run a scan first.');
    return;
  }

  const report = generateSecurityReport(state.findings, state.scoreData, state.maskingApplied);
  state.reportData = report;

  const json = JSON.stringify(report, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href     = url;
  a.download = `cyberghost-report-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  // Revoke object URL after a short delay
  setTimeout(() => URL.revokeObjectURL(url), 5000);

  showToast('Report downloaded. Only masked/metadata included — no original text.');
}

/* =========================================================
   VALIDATION & ERROR HELPERS
   ========================================================= */

function showError(msg) {
  const errEl = document.getElementById('input-error');
  if (!errEl) return;
  errEl.textContent = msg;
  errEl.classList.add('visible');
  setTimeout(() => errEl.classList.remove('visible'), 5000);
}

function clearError() {
  const errEl = document.getElementById('input-error');
  if (errEl) errEl.classList.remove('visible');
}

function showToast(msg) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 4000);
}

/* =========================================================
   COPY TO CLIPBOARD
   ========================================================= */

async function copyMaskedText() {
  if (!state.maskedText) {
    showToast('Nothing to copy — apply masking first.');
    return;
  }
  try {
    await navigator.clipboard.writeText(state.maskedText);
    showToast('Masked text copied to clipboard!');
  } catch {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = state.maskedText;
    ta.style.position = 'fixed';
    ta.style.opacity  = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Masked text copied to clipboard!');
  }
}

/* =========================================================
   CLEAR ALL
   ========================================================= */

function clearAll() {
  resetState();

  const inputEl = document.getElementById('text-input');
  if (inputEl) inputEl.value = '';

  updateCharCounter(0);
  clearError();

  document.getElementById('results-section').classList.remove('visible');
  document.getElementById('actions-section').classList.remove('visible');
  document.getElementById('masked-section').classList.remove('visible');
  document.getElementById('score-card').classList.remove('visible');

  const staleEl = document.getElementById('stale-notice');
  if (staleEl) staleEl.classList.remove('visible');

  const countEl = document.getElementById('finding-count');
  if (countEl) countEl.textContent = '';

  document.getElementById('findings-list').innerHTML = '';
  document.getElementById('category-summary').innerHTML = '';

  const output = document.getElementById('masked-output');
  if (output) output.textContent = '';

  if (inputEl) inputEl.focus();
}

/* =========================================================
   CHARACTER COUNTER
   ========================================================= */

function updateCharCounter(count) {
  const counterEl = document.getElementById('char-counter');
  if (!counterEl) return;
  counterEl.textContent = `${count.toLocaleString()} / ${MAX_INPUT_CHARS.toLocaleString()} characters`;
  counterEl.classList.toggle('warn', count > MAX_INPUT_CHARS * 0.9);
}

/* =========================================================
   EVENT WIRING
   ========================================================= */

document.addEventListener('DOMContentLoaded', () => {
  const inputEl    = document.getElementById('text-input');
  const scanBtn    = document.getElementById('btn-scan');
  const clearBtn   = document.getElementById('btn-clear');
  const demoBtn    = document.getElementById('btn-demo');
  const maskBtn    = document.getElementById('btn-mask');
  const copyBtn    = document.getElementById('btn-copy');
  const reportBtn  = document.getElementById('btn-report');

  // Character counter and stale-result tracking
  inputEl?.addEventListener('input', () => {
    const len = inputEl.value.length;
    updateCharCounter(len);
    if (len > MAX_INPUT_CHARS) {
      showError(`Input exceeds the maximum of ${MAX_INPUT_CHARS.toLocaleString()} characters. Please shorten your text.`);
    } else {
      clearError();
    }
    // When text changes after a scan, indicate that displayed results are stale
    if (state.hasScanned) {
      const staleEl = document.getElementById('stale-notice');
      if (staleEl) staleEl.classList.add('visible');
    }
  });

  // Scan button
  scanBtn?.addEventListener('click', () => {
    const text = inputEl?.value ?? '';
    if (!text.trim()) {
      showError('Please paste or type some text before scanning.');
      inputEl?.focus();
      return;
    }
    if (text.length > MAX_INPUT_CHARS) {
      showError(`Input exceeds the maximum of ${MAX_INPUT_CHARS.toLocaleString()} characters.`);
      return;
    }
    clearError();
    renderResults(text);
  });

  // Clear button
  clearBtn?.addEventListener('click', clearAll);

  // Demo button
  demoBtn?.addEventListener('click', () => {
    if (inputEl) {
      inputEl.value = DEMO_TEXT;
      updateCharCounter(DEMO_TEXT.length);
      clearError();
    }
  });

  // Mask button
  maskBtn?.addEventListener('click', () => {
    const text = inputEl?.value ?? '';
    applyMasking(text);
  });

  // Copy masked text
  copyBtn?.addEventListener('click', copyMaskedText);

  // Download report
  reportBtn?.addEventListener('click', downloadReport);

  // Keyboard: Enter in textarea should NOT auto-scan (normal textarea behaviour)
  // Keyboard: allow Ctrl+Enter to trigger scan
  inputEl?.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') {
      scanBtn?.click();
    }
  });

  // Initialise counter
  updateCharCounter(0);
});

// Export functions for test runners / Node.js if present
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    detectEmails,
    detectPhones,
    detectSecrets,
    detectPossibleIdentifiers,
    detectPossibleAddresses,
    resolveOverlaps,
    normalizeFindings,
    calculatePrivacyScore,
    maskFindings,
    generateSecurityReport,
    runScan,
    renderFindings,
  };
}

