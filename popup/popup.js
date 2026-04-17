/**
 * DeIDGuard – popup.js
 * Main Popup Controller
 *
 * Orchestrates all popup UI interactions:
 *   - Text capture from active tab
 *   - De-identification via lib/deid.js
 *   - Rule-based review via lib/rules.js
 *   - History management (last 5 items, chrome.storage.local)
 *   - Settings management (chrome.storage.local)
 *   - Clipboard copy + AI site shortcuts
 *
 * Privacy:
 *   - All processing is local.
 *   - No text data is transmitted off-device.
 *   - AI buttons ONLY open a new tab — they do NOT send or prefill any text.
 */

'use strict';

// ─── Shorthand DOM helper ─────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

// ─── App State ────────────────────────────────────────────────────────────────
const state = {
  originalText:  '',
  cleanedText:   '',
  deidSummary:   {},
  deidChanges:   0,
  riskScore:     { score: 'low', points: 0, factors: [] },
  flagResults:   [],
  settings:      {
    reviewMode:        'basic',
    useClientLabel:    false,
    dateGranularity:   'year',
    showPrivacyBadge:  true,
  },
  history:       [],
  currentPanel:  'main',   // 'main' | 'history' | 'settings'
};

// ─── Constants ────────────────────────────────────────────────────────────────
const MAX_HISTORY     = 5;
const STORAGE_KEYS = {
  settings:    'deidguard_settings',
  history:     'deidguard_history',
  rulesBasic:  'deidguard_rules_basic',
  rulesHPro:   'deidguard_rules_healthcare_pro',
  rulesFTC:    'deidguard_rules_ftc_hipra',
  rulesCustom: 'deidguard_rules_custom',
};

// ─── Utilities ────────────────────────────────────────────────────────────────

function setStatus(msg, type = 'idle') {
  const bar  = $('status-bar');
  const text = $('status-text');
  bar.className = `status-bar status-${type}`;
  text.textContent = msg;
}

function updateCharCount(id, text) {
  const el = $(id);
  if (el) {
    el.textContent = `${text.length} character${text.length !== 1 ? 's' : ''}`;
  }
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Highlight «match» markers in flag snippet text */
function highlightSnippet(snippet) {
  return escapeHtml(snippet).replace(/«(.*?)»/g, '<mark>$1</mark>');
}

function formatTimestamp(ts) {
  const d = new Date(ts);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
    ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

// ─── Settings ─────────────────────────────────────────────────────────────────

async function loadSettings() {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.settings);
    if (result[STORAGE_KEYS.settings]) {
      state.settings = { ...state.settings, ...result[STORAGE_KEYS.settings] };
    }
  } catch (e) {
    console.warn('[DeIDGuard] Could not load settings.', e);
  }
  applySettingsToUI();
}

async function saveSettings() {
  try {
    await chrome.storage.local.set({ [STORAGE_KEYS.settings]: state.settings });
  } catch (e) {
    console.warn('[DeIDGuard] Could not save settings.', e);
  }
}

function applySettingsToUI() {
  // Mode selector
  const modeSelect = $('select-mode');
  if (modeSelect) modeSelect.value = state.settings.reviewMode;

  // Client label toggle
  const clientToggle = $('toggle-client-label');
  if (clientToggle) clientToggle.checked = state.settings.useClientLabel;

  // Date granularity toggle
  const dateToggle = $('toggle-date-granularity');
  if (dateToggle) dateToggle.checked = state.settings.dateGranularity === 'month_year';

  // Privacy badge toggle
  const badgeToggle = $('toggle-privacy-badge');
  if (badgeToggle) badgeToggle.checked = state.settings.showPrivacyBadge;

  // Show/hide privacy badge
  const badge = $('privacy-badge');
  if (badge) badge.classList.toggle('hidden', !state.settings.showPrivacyBadge);

  // Mode badge in main panel
  updateModeBadge();

  // Show/hide custom rules section
  updateCustomRulesVisibility();
}

function updateModeBadge() {
  const badge = $('mode-badge');
  if (!badge) return;
  const labels = {
    basic:          'Basic',
    healthcare_pro: 'Healthcare Pro',
    ftc_hipra:      'FTC / HIPRA',
    custom:         'Custom',
  };
  badge.textContent = labels[state.settings.reviewMode] || 'Basic';
}

/** Render the re-identification risk score panel */
function renderRiskScore(riskScore) {
  const panel = $('risk-score-panel');
  if (!panel) return;

  if (!riskScore || riskScore.points === 0) {
    panel.classList.add('hidden');
    return;
  }

  panel.classList.remove('hidden');
  const scoreEl   = $('risk-score-value');
  const factorEl  = $('risk-score-factors');

  if (scoreEl) {
    scoreEl.textContent  = riskScore.score.toUpperCase();
    scoreEl.className    = `risk-badge risk-${riskScore.score}`;
  }

  if (factorEl && riskScore.factors && riskScore.factors.length > 0) {
    factorEl.innerHTML = riskScore.factors
      .map(f => `<li>${escapeHtml(f)}</li>`)
      .join('');
  } else if (factorEl) {
    factorEl.innerHTML = '<li>No quasi-identifier combinations detected.</li>';
  }
}

function updateCustomRulesVisibility() {
  const section = $('custom-rules-section');
  if (section) {
    section.classList.toggle('hidden', state.settings.reviewMode !== 'custom');
  }
}

// ─── History ──────────────────────────────────────────────────────────────────

async function loadHistory() {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.history);
    state.history = result[STORAGE_KEYS.history] || [];
  } catch (e) {
    state.history = [];
  }
  renderHistory();
}

async function saveToHistory(cleanedText, summary, changes) {
  const entry = {
    id:        Date.now(),
    timestamp: Date.now(),
    preview:   cleanedText.slice(0, 120),
    fullText:  cleanedText,
    summary,
    changes,
  };
  // Prepend and limit to MAX_HISTORY
  state.history = [entry, ...state.history].slice(0, MAX_HISTORY);
  try {
    await chrome.storage.local.set({ [STORAGE_KEYS.history]: state.history });
  } catch (e) {
    console.warn('[DeIDGuard] Could not save history.', e);
  }
  renderHistory();
}

function renderHistory() {
  const list    = $('history-list');
  const empty   = $('history-empty');
  if (!list) return;

  list.innerHTML = '';

  if (state.history.length === 0) {
    empty.classList.remove('hidden');
    return;
  }

  empty.classList.add('hidden');

  for (const entry of state.history) {
    const li = document.createElement('li');
    li.className = 'history-item';
    li.innerHTML = `
      <div class="history-item-meta">
        <span class="history-timestamp">${formatTimestamp(entry.timestamp)}</span>
        <span class="history-changes">${entry.changes} change${entry.changes !== 1 ? 's' : ''}</span>
      </div>
      <div class="history-preview">${escapeHtml(entry.preview)}${entry.fullText.length > 120 ? '…' : ''}</div>
      <div class="history-actions">
        <button class="history-btn restore" data-id="${entry.id}">↺ Restore</button>
        <button class="history-btn delete"  data-id="${entry.id}">✕ Remove</button>
      </div>
    `;
    list.appendChild(li);
  }

  // Restore
  list.querySelectorAll('.history-btn.restore').forEach(btn => {
    btn.addEventListener('click', () => {
      const entry = state.history.find(h => h.id === Number(btn.dataset.id));
      if (!entry) return;
      state.cleanedText  = entry.fullText;
      state.deidSummary  = entry.summary || {};
      state.deidChanges  = entry.changes || 0;
      showCleanedResult(entry.fullText, entry.summary, entry.changes);
      showPanel('main');
      setStatus('Restored from history.', 'success');
    });
  });

  // Delete
  list.querySelectorAll('.history-btn.delete').forEach(btn => {
    btn.addEventListener('click', async () => {
      state.history = state.history.filter(h => h.id !== Number(btn.dataset.id));
      await chrome.storage.local.set({ [STORAGE_KEYS.history]: state.history });
      renderHistory();
    });
  });
}

async function clearAllHistory() {
  state.history = [];
  await chrome.storage.local.set({ [STORAGE_KEYS.history]: [] });
  renderHistory();
}

// ─── Text Capture ─────────────────────────────────────────────────────────────

async function captureSelectedText() {
  setStatus('Capturing selected text…', 'loading');

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.id) {
      setStatus('Could not access the current tab.', 'error');
      return;
    }

    // Cannot inject into chrome:// or extension pages
    if (tab.url && (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://'))) {
      setStatus('Cannot capture text from browser system pages.', 'warning');
      showOriginalEmpty('DeIDGuard cannot run on browser system pages (chrome://).\nNavigate to a regular webpage and try again.');
      return;
    }

    // Inject a function directly into the tab to grab selected text
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func:   () => window.getSelection()?.toString()?.trim() || '',
    });

    const selectedText = results?.[0]?.result || '';

    if (!selectedText) {
      setStatus('No text selected on this page.', 'idle');
      showOriginalEmpty('No text is currently selected.\n\nHighlight some text on the page, then click ↺ Refresh.');
      $('btn-deid').disabled = true;
      return;
    }

    state.originalText = selectedText;
    showOriginalText(selectedText);
    setStatus(`${selectedText.length} characters captured. Ready to de-identify.`, 'success');
    $('btn-deid').disabled = false;

  } catch (err) {
    console.error('[DeIDGuard] captureSelectedText error:', err);

    // Provide helpful guidance on common errors
    if (err.message?.includes('Cannot access') || err.message?.includes('permissions')) {
      setStatus('Permission denied on this page.', 'error');
      showOriginalEmpty('DeIDGuard cannot access this page.\n\nTry on a standard website (http/https).');
    } else {
      setStatus('Could not capture text. Please try again.', 'error');
    }
    $('btn-deid').disabled = true;
  }
}

function showOriginalEmpty(message) {
  $('original-empty').classList.remove('hidden');
  $('original-empty').querySelector('p').textContent = message || 'No text selected.';
  $('original-text').classList.add('hidden');
  $('original-char-count').classList.add('hidden');
}

function showOriginalText(text) {
  $('original-empty').classList.add('hidden');
  const ta = $('original-text');
  ta.classList.remove('hidden');
  ta.value = text;
  $('original-char-count').classList.remove('hidden');
  updateCharCount('original-char-count', text);
}

// ─── De-Identification ────────────────────────────────────────────────────────

function runDeidentification() {
  const text = state.originalText;
  if (!text) {
    setStatus('No text to de-identify.', 'error');
    return;
  }

  setStatus('De-identifying…', 'loading');
  $('btn-deid').disabled = true;

  // Use setTimeout to allow UI to update before synchronous processing
  setTimeout(() => {
    try {
      // DeIDGuard.deidentify is exposed globally by lib/deid.js
      const { cleaned, summary, changes, riskScore } = window.DeIDGuard.deidentify(text, {
        dateGranularity: state.settings.dateGranularity,
        useClientLabel:  state.settings.useClientLabel,
      });

      state.cleanedText  = cleaned;
      state.deidSummary  = summary;
      state.deidChanges  = changes;
      state.riskScore    = riskScore;

      showCleanedResult(cleaned, summary, changes);
      renderRiskScore(riskScore);
      saveToHistory(cleaned, summary, changes);

      if (changes === 0) {
        setStatus('De-identification complete. No identifiers detected.', 'success');
      } else {
        setStatus(`De-identification complete. ${changes} item${changes !== 1 ? 's' : ''} replaced.`, 'success');
      }

      // Enable downstream buttons
      $('btn-rules').disabled = false;
      $('btn-copy').disabled  = false;
      $('btn-claude').disabled   = false;
      $('btn-chatgpt').disabled  = false;

    } catch (err) {
      console.error('[DeIDGuard] De-identification error:', err);
      setStatus('De-identification failed. Please try again.', 'error');
    }

    $('btn-deid').disabled = false;
  }, 10);
}

function showCleanedResult(cleaned, summary, changes) {
  $('cleaned-empty').classList.add('hidden');
  $('cleaned-result').classList.remove('hidden');

  // Changes badge
  const badge = $('changes-badge');
  badge.textContent = changes === 0 ? '0 changes' : `${changes} replaced`;
  badge.style.background = changes === 0 ? 'var(--text-faint)' : 'var(--teal)';

  // Text area
  const ta = $('cleaned-text');
  ta.value = cleaned;
  updateCharCount('cleaned-char-count', cleaned);

  // Summary list
  const summaryEl = $('deid-summary');
  const lines = window.DeIDGuard.formatSummary(summary);
  if (lines.length > 0) {
    summaryEl.innerHTML = '<ul>' + lines.map(l => `<li><span>${escapeHtml(l)}</span></li>`).join('') + '</ul>';
  } else {
    summaryEl.innerHTML = '<span style="color:var(--text-faint)">No identifiers detected.</span>';
  }

  // Sync state (textarea may have been edited by user)
  ta.addEventListener('input', () => {
    state.cleanedText = ta.value;
    updateCharCount('cleaned-char-count', ta.value);
  });
}

// ─── Rule Check ───────────────────────────────────────────────────────────────

async function runRuleCheck() {
  const text = state.cleanedText || state.originalText;
  if (!text) {
    setStatus('No text available to check.', 'error');
    return;
  }

  $('btn-rules').disabled = true;
  setStatus('Running rule check…', 'loading');

  try {
    const rules    = await window.DeIDGuard.loadRules(state.settings.reviewMode);
    const textToCheck = $('cleaned-text')?.value || text; // Use current textarea value (may have been edited)
    const flags    = window.DeIDGuard.runRuleCheck(textToCheck, rules);

    state.flagResults = flags;
    renderFlags(flags);

    if (flags.length === 0) {
      setStatus('Rule check complete. No flags found.', 'success');
    } else {
      const highCount = flags.filter(f => f.severity === 'high').length;
      const msg = highCount > 0
        ? `Rule check complete. ${flags.length} flag${flags.length !== 1 ? 's' : ''} found (${highCount} high severity).`
        : `Rule check complete. ${flags.length} flag${flags.length !== 1 ? 's' : ''} found.`;
      setStatus(msg, highCount > 0 ? 'warning' : 'success');
    }
  } catch (err) {
    console.error('[DeIDGuard] Rule check error:', err);
    setStatus('Rule check failed. Please try again.', 'error');
  }

  $('btn-rules').disabled = false;
}

function renderFlags(flags) {
  const container = $('flags-container');
  const noFlags   = $('no-flags');
  const list      = $('flags-list');

  container.classList.remove('hidden');
  list.innerHTML = '';

  if (flags.length === 0) {
    noFlags.classList.remove('hidden');
    return;
  }

  noFlags.classList.add('hidden');

  for (const flag of flags) {
    const { label, cssClass } = window.DeIDGuard.severityLabel(flag.severity);
    const card = document.createElement('div');
    card.className = `flag-card ${cssClass}`;

    const snippetsHtml = flag.matches
      .slice(0, 3)
      .map(s => `<div class="flag-snippet">${highlightSnippet(s)}</div>`)
      .join('');

    card.innerHTML = `
      <div class="flag-title-row">
        <span class="sev-badge">${escapeHtml(label)}</span>
        <span class="flag-label">${escapeHtml(flag.label)}</span>
        <span class="flag-count">${flag.count} match${flag.count !== 1 ? 'es' : ''}</span>
      </div>
      <div class="flag-message">${escapeHtml(flag.message)}</div>
      ${snippetsHtml ? `<div class="flag-snippets">${snippetsHtml}</div>` : ''}
    `;
    list.appendChild(card);
  }
}

// ─── Copy & AI Shortcuts ──────────────────────────────────────────────────────

async function copyCleanedText() {
  // Use current textarea value (user may have edited)
  const text = $('cleaned-text')?.value || state.cleanedText;
  if (!text) return;

  try {
    await navigator.clipboard.writeText(text);
    const hint = $('paste-hint');
    hint.classList.remove('hidden');
    setStatus('Copied to clipboard! Paste into your AI tool.', 'success');

    // Hide hint after 5 seconds
    setTimeout(() => hint.classList.add('hidden'), 5000);
  } catch (err) {
    setStatus('Could not copy. Try selecting and copying manually.', 'error');
  }
}

function openClaude() {
  chrome.tabs.create({ url: 'https://claude.ai', active: true });
}

function openChatGPT() {
  chrome.tabs.create({ url: 'https://chatgpt.com', active: true });
}

// ─── Panel Navigation ─────────────────────────────────────────────────────────

function showPanel(name) {
  // Hide all panels
  $('panel-main').classList.add('hidden');
  $('panel-history').classList.remove('active');
  $('panel-history').classList.add('hidden');
  $('panel-settings').classList.remove('active');
  $('panel-settings').classList.add('hidden');

  if (name === 'main') {
    $('panel-main').classList.remove('hidden');
    $('panel-main').classList.add('active');
  } else if (name === 'history') {
    $('panel-history').classList.remove('hidden');
    $('panel-history').classList.add('active');
    loadHistory();
  } else if (name === 'settings') {
    $('panel-settings').classList.remove('hidden');
    $('panel-settings').classList.add('active');
    loadCustomRulesIntoEditor();
  }

  state.currentPanel = name;
}

// ─── Custom Rules Editor ──────────────────────────────────────────────────────

async function loadCustomRulesIntoEditor() {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.rulesCustom);
    const rules = result[STORAGE_KEYS.rulesCustom] || [];
    const textarea = $('custom-rules-input');
    if (!textarea) return;

    if (rules.length === 0) {
      textarea.value = '';
    } else {
      textarea.value = rules
        .map(r => `${r.pattern} | ${r.message} | ${r.severity}`)
        .join('\n');
    }
  } catch (e) {
    console.warn('[DeIDGuard] Could not load custom rules.');
  }
}

async function saveCustomRules() {
  const textarea = $('custom-rules-input');
  const statusEl = $('custom-rules-status');
  if (!textarea) return;

  const lines = textarea.value.split('\n').filter(l => l.trim());
  const rules = [];
  const errors = [];

  lines.forEach((line, i) => {
    const parts = line.split('|').map(p => p.trim());
    if (parts.length < 2) {
      errors.push(`Line ${i + 1}: must have at least "pattern | message"`);
      return;
    }

    const [pattern, message, severity = 'medium'] = parts;
    const rule = {
      id:       `custom_${i + 1}`,
      label:    `Custom Rule ${i + 1}`,
      pattern,
      flags:    'gi',
      message,
      severity: ['high', 'medium', 'low'].includes(severity) ? severity : 'medium',
    };

    const validation = window.DeIDGuard.validateRule(rule);
    if (!validation.valid) {
      errors.push(`Line ${i + 1}: invalid regex — ${validation.error}`);
      return;
    }

    rules.push(rule);
  });

  if (errors.length > 0) {
    statusEl.className = 'status-inline error';
    statusEl.textContent = errors[0];
    statusEl.classList.remove('hidden');
    return;
  }

  try {
    await window.DeIDGuard.saveCustomRules(rules);
    statusEl.className = 'status-inline ok';
    statusEl.textContent = `✓ ${rules.length} rule${rules.length !== 1 ? 's' : ''} saved.`;
    statusEl.classList.remove('hidden');
    setTimeout(() => statusEl.classList.add('hidden'), 3000);
  } catch (e) {
    statusEl.className = 'status-inline error';
    statusEl.textContent = 'Could not save rules.';
    statusEl.classList.remove('hidden');
  }
}

// ─── Event Bindings ───────────────────────────────────────────────────────────

function bindEvents() {
  // ── Navigation ──
  $('btn-history-toggle').addEventListener('click', () => {
    showPanel(state.currentPanel === 'history' ? 'main' : 'history');
  });

  $('btn-settings-toggle').addEventListener('click', () => {
    showPanel(state.currentPanel === 'settings' ? 'main' : 'settings');
  });

  $('btn-history-close').addEventListener('click',  () => showPanel('main'));
  $('btn-settings-close').addEventListener('click', () => showPanel('main'));

  // ── Main actions ──
  $('btn-refresh').addEventListener('click', captureSelectedText);
  $('btn-deid').addEventListener('click', runDeidentification);
  $('btn-rules').addEventListener('click', runRuleCheck);
  $('btn-copy').addEventListener('click', copyCleanedText);
  $('btn-claude').addEventListener('click', openClaude);
  $('btn-chatgpt').addEventListener('click', openChatGPT);

  // ── History ──
  $('btn-clear-history').addEventListener('click', async () => {
    if (confirm('Clear all de-identification history?')) {
      await clearAllHistory();
    }
  });

  // ── Settings ──
  $('select-mode').addEventListener('change', async (e) => {
    state.settings.reviewMode = e.target.value;
    updateModeBadge();
    updateCustomRulesVisibility();
    await saveSettings();
  });

  $('toggle-client-label').addEventListener('change', async (e) => {
    state.settings.useClientLabel = e.target.checked;
    await saveSettings();
  });

  $('toggle-date-granularity').addEventListener('change', async (e) => {
    state.settings.dateGranularity = e.target.checked ? 'month_year' : 'year';
    await saveSettings();
  });

  $('toggle-privacy-badge').addEventListener('change', async (e) => {
    state.settings.showPrivacyBadge = e.target.checked;
    const badge = $('privacy-badge');
    if (badge) badge.classList.toggle('hidden', !e.target.checked);
    await saveSettings();
  });

  $('btn-save-custom-rules').addEventListener('click', saveCustomRules);

  $('btn-reset-settings').addEventListener('click', async () => {
    if (confirm('Reset all settings to defaults? Your custom rules will not be affected.')) {
      state.settings = {
        reviewMode:        'basic',
        useClientLabel:    false,
        dateGranularity:   'year',
        showPrivacyBadge:  true,
      };
      await saveSettings();
      applySettingsToUI();
    }
  });
}

// ─── Initialization ───────────────────────────────────────────────────────────

async function init() {
  try {
    // Load persisted settings first
    await loadSettings();

    // Bind all UI events
    bindEvents();

    // Start in main panel
    showPanel('main');

    // Auto-capture selected text from the active tab
    await captureSelectedText();

  } catch (err) {
    console.error('[DeIDGuard] Initialization error:', err);
    setStatus('Extension error. Please reload.', 'error');
  }
}

// ── Boot ──
document.addEventListener('DOMContentLoaded', init);
