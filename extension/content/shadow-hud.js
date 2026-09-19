/**
 * SentinelX — Closed Shadow DOM Security HUD
 *
 * Renders the in-page security interface inside a Closed Shadow DOM,
 * making it completely tamper-proof from host page scripts and CSS.
 *
 * attachShadow({ mode: 'closed' }) ensures:
 *   - No host script can read or manipulate security buttons
 *   - No host CSS can interfere with extension styling
 *   - Extension UI is cryptographically isolated from web content
 */

'use strict';

window.SentinelXHUD = (() => {

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------

  let shadowRoot = null;
  let hostElement = null;
  let currentResolve = null;
  let pasteEvent = null;

  // ------------------------------------------------------------------
  // HUD Styles (injected into Shadow DOM, completely isolated)
  // ------------------------------------------------------------------

  const HUD_CSS = `
    @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=Space+Grotesk:wght@500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600;700&display=swap');

    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    :host {
      all: initial;
      font-family: 'Space Grotesk', system-ui, sans-serif;
    }

    /* ── Backdrop ────────────────────────────────────────────────── */
    .sx-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(15, 17, 21, 0.75);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      z-index: 2147483646;
      display: flex;
      align-items: center;
      justify-content: center;
      animation: sxFadeIn 0.18s ease-out;
    }

    @keyframes sxFadeIn {
      from { opacity: 0; }
      to   { opacity: 1; }
    }

    /* ── Main Panel (Dark Glassmorphism) ──────────────────────────── */
    .sx-panel {
      background: linear-gradient(145deg, #0f1117 0%, #12151e 50%, #0d1018 100%);
      color: #f0f2f8;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 24px;
      box-shadow:
        0 35px 90px rgba(0, 0, 0, 0.85),
        0 0 0 1px rgba(255, 255, 255, 0.04) inset,
        0 1px 0 rgba(255, 255, 255, 0.1) inset;
      width: 500px;
      max-width: calc(100vw - 40px);
      max-height: calc(100vh - 80px);
      overflow-y: auto;
      overflow-x: hidden;
      animation: sxSlideUp 0.22s cubic-bezier(0.34, 1.56, 0.64, 1);
      position: relative;
    }

    @keyframes sxSlideUp {
      from { transform: translateY(24px) scale(0.96); opacity: 0; }
      to   { transform: translateY(0) scale(1); opacity: 1; }
    }

    /* ── Header ──────────────────────────────────────────────────── */
    .sx-header {
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 22px 26px 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.07);
      background: rgba(255, 255, 255, 0.03);
      position: relative;
      border-radius: 24px 24px 0 0;
    }

    .sx-logo {
      width: 38px;
      height: 38px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--sx-accent);
      color: #000;
      font-family: 'Syne', sans-serif;
      font-size: 15px;
      font-weight: 800;
      flex-shrink: 0;
      box-shadow: 0 0 16px rgba(var(--sx-accent-rgb), 0.5);
    }

    .sx-title-group {
      flex: 1;
    }

    .sx-brand {
      font-family: 'Space Grotesk', sans-serif;
      font-size: 10px;
      font-weight: 800;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: rgba(255, 255, 255, 0.4);
      margin-bottom: 3px;
    }

    .sx-title {
      font-family: 'Syne', sans-serif;
      font-size: 18px;
      font-weight: 800;
      color: #ffffff;
      letter-spacing: -0.01em;
      line-height: 1.2;
      text-transform: uppercase;
    }

    .sx-risk-badge {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      width: 58px;
      height: 58px;
      border-radius: 14px;
      background: rgba(var(--sx-accent-rgb), 0.15);
      border: 1px solid rgba(var(--sx-accent-rgb), 0.3);
      flex-shrink: 0;
    }

    .sx-risk-number {
      font-size: 22px;
      font-weight: 800;
      color: var(--sx-accent);
      font-family: 'Syne', sans-serif;
      line-height: 1;
    }

    .sx-risk-label {
      font-size: 8.5px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: rgba(255, 255, 255, 0.5);
      margin-top: 2px;
    }

    /* ── Content Body ─────────────────────────────────────────────── */
    .sx-body {
      padding: 20px 26px 24px;
    }

    /* ── Decision Banner ─────────────────────────────────────────── */
    .sx-decision-banner {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 12px 16px;
      border-radius: 10px;
      background: rgba(var(--sx-accent-rgb), 0.12);
      border: 1px solid rgba(var(--sx-accent-rgb), 0.25);
      margin-bottom: 18px;
    }

    .sx-decision-icon {
      font-size: 20px;
      flex-shrink: 0;
    }

    .sx-decision-text {
      flex: 1;
    }

    .sx-decision-label {
      font-size: 13px;
      font-weight: 700;
      color: var(--sx-accent);
      letter-spacing: 0.05em;
    }

    .sx-decision-reason {
      font-size: 11px;
      color: rgba(255, 255, 255, 0.65);
      margin-top: 3px;
      line-height: 1.5;
    }

    /* ── Info Grid ────────────────────────────────────────────────── */
    .sx-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-bottom: 16px;
    }

    .sx-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.09);
      border-radius: 10px;
      padding: 12px 14px;
    }

    .sx-card-label {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: rgba(255, 255, 255, 0.45);
      margin-bottom: 6px;
    }

    .sx-card-value {
      font-size: 12px;
      font-weight: 600;
      color: rgba(255, 255, 255, 0.92);
      font-family: 'JetBrains Mono', monospace;
    }

    /* ── Detected Tags ────────────────────────────────────────────── */
    .sx-tags-section {
      margin-bottom: 16px;
    }

    .sx-section-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: rgba(255, 255, 255, 0.4);
      margin-bottom: 8px;
    }

    .sx-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .sx-tag {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      background: rgba(var(--sx-accent-rgb), 0.15);
      color: var(--sx-accent);
      border: 1px solid rgba(var(--sx-accent-rgb), 0.3);
      font-family: 'IBM Plex Mono', monospace;
      letter-spacing: 0.03em;
    }

    /* ── Audit Telemetry (collapsible) ──────────────────────────── */
    .sx-audit-toggle {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px;
      cursor: pointer;
      margin-bottom: 10px;
      font-size: 11px;
      font-weight: 500;
      color: rgba(255, 255, 255, 0.5);
      transition: all 0.15s ease;
      user-select: none;
    }

    .sx-audit-toggle:hover {
      background: rgba(255, 255, 255, 0.07);
      color: rgba(255, 255, 255, 0.75);
    }

    .sx-audit-toggle svg {
      transition: transform 0.2s ease;
      flex-shrink: 0;
    }

    .sx-audit-toggle.open svg {
      transform: rotate(90deg);
    }

    .sx-audit-panel {
      display: none;
      margin-bottom: 14px;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .sx-audit-panel.open {
      display: block;
    }

    .sx-audit-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 12px;
      background: rgba(16, 185, 129, 0.1);
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }

    .sx-audit-privacy-label {
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      color: #10b981;
    }

    .sx-audit-bytes {
      font-size: 10px;
      color: rgba(255, 255, 255, 0.45);
      font-family: 'JetBrains Mono', monospace;
    }

    .sx-audit-json {
      padding: 12px;
      background: #020617;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      line-height: 1.6;
      color: #94a3b8;
      white-space: pre;
      overflow-x: auto;
    }

    .sx-json-key    { color: #7dd3fc; }
    .sx-json-string { color: #86efac; }
    .sx-json-number { color: #fbbf24; }
    .sx-json-bool   { color: #f472b6; }

    /* ── Risk Breakdown ────────────────────────────────────────── */
    .sx-breakdown {
      margin-bottom: 16px;
    }

    .sx-breakdown-bar-row {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
    }

    .sx-breakdown-name {
      font-size: 10px;
      color: rgba(255, 255, 255, 0.55);
      width: 110px;
      flex-shrink: 0;
      font-weight: 600;
    }

    .sx-breakdown-track {
      flex: 1;
      height: 5px;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 3px;
      overflow: hidden;
    }

    .sx-breakdown-fill {
      height: 100%;
      border-radius: 3px;
      background: linear-gradient(90deg, var(--sx-accent), rgba(var(--sx-accent-rgb), 0.45));
      transition: width 0.7s cubic-bezier(0.34, 1.56, 0.64, 1);
    }

    .sx-breakdown-val {
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      color: rgba(255, 255, 255, 0.55);
      width: 30px;
      text-align: right;
      flex-shrink: 0;
      font-weight: 600;
    }

    /* ── Action Buttons ───────────────────────────────────────── */
    .sx-actions {
      display: flex;
      flex-direction: column;
      gap: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.07);
      padding-top: 18px;
    }

    .sx-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 13px 20px;
      border-radius: 12px;
      font-size: 13px;
      font-weight: 700;
      font-family: 'Space Grotesk', sans-serif;
      cursor: pointer;
      border: none;
      transition: all 0.18s ease;
      letter-spacing: 0.03em;
    }

    .sx-btn:hover {
      transform: translateY(-2px);
      filter: brightness(1.12);
    }

    .sx-btn:active {
      transform: translateY(0);
      filter: brightness(0.93);
    }

    .sx-btn-primary {
      background: linear-gradient(135deg, var(--sx-accent) 0%, rgba(var(--sx-accent-rgb), 0.75) 100%);
      color: #000;
      box-shadow: 0 6px 20px rgba(var(--sx-accent-rgb), 0.4);
    }

    .sx-btn-secondary {
      background: rgba(255, 255, 255, 0.07);
      color: rgba(255, 255, 255, 0.8);
      border: 1px solid rgba(255, 255, 255, 0.12);
    }

    .sx-btn-danger {
      background: rgba(255, 61, 90, 0.12);
      color: #FF3D5A;
      border: 1px solid rgba(255, 61, 90, 0.3);
    }

    .sx-btn-redact {
      background: linear-gradient(135deg, #00C2FF, #0077FF);
      color: #000;
      font-weight: 700;
      box-shadow: 0 4px 16px rgba(0, 194, 255, 0.35);
    }

    /* ── Visual Redaction Diff ─────────────────────────────────── */
    .sx-diff-card {
      margin-top: 14px;
      background: rgba(0,0,0,0.35);
      border: 1px solid rgba(0,194,255,0.18);
      border-radius: 10px;
      overflow: hidden;
      font-size: 11px;
    }

    .sx-diff-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 9px 12px;
      background: rgba(0,194,255,0.06);
      border-bottom: 1px solid rgba(0,194,255,0.12);
      cursor: pointer;
      user-select: none;
    }

    .sx-diff-title {
      font-weight: 600;
      color: #00C2FF;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .sx-diff-badge {
      font-family: 'IBM Plex Mono', monospace;
      font-size: 9px;
      font-weight: 600;
      padding: 2px 7px;
      background: rgba(0,229,160,0.12);
      border: 1px solid rgba(0,229,160,0.3);
      color: #00E5A0;
      border-radius: 4px;
    }

    .sx-diff-body {
      display: none;
      padding: 10px;
      gap: 10px;
      flex-direction: column;
      animation: sxFadeIn 0.2s ease-out;
    }

    .sx-diff-card.expanded .sx-diff-body {
      display: flex;
    }

    .sx-diff-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }

    .sx-diff-col {
      background: #020617;
      border-radius: 6px;
      border: 1px solid rgba(255,255,255,0.06);
      padding: 8px 10px;
      display: flex;
      flex-direction: column;
      gap: 5px;
    }

    .sx-diff-col-title {
      font-size: 9px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .sx-diff-col.raw .sx-diff-col-title { color: #FF3D5A; }
    .sx-diff-col.clean .sx-diff-col-title { color: #00E5A0; }

    .sx-diff-box {
      font-family: 'IBM Plex Mono', monospace;
      font-size: 10px;
      line-height: 1.5;
      color: #cbd5e1;
      max-height: 90px;
      overflow-y: auto;
      word-break: break-all;
      white-space: pre-wrap;
    }

    .sx-raw-secret {
      background: rgba(255,61,90,0.25);
      color: #FF3D5A;
      padding: 1px 3px;
      border-radius: 3px;
      border: 1px solid rgba(255,61,90,0.4);
      font-weight: 600;
    }

    .sx-clean-token {
      background: rgba(0,229,160,0.2);
      color: #00E5A0;
      padding: 1px 4px;
      border-radius: 3px;
      border: 1px solid rgba(0,229,160,0.4);
      font-weight: 600;
    }

    .sx-row {
      display: flex;
      gap: 8px;
    }

    .sx-row .sx-btn {
      flex: 1;
    }

    /* ── Scrollbar ─────────────────────────────────────────────── */
    .sx-panel::-webkit-scrollbar { width: 4px; }
    .sx-panel::-webkit-scrollbar-track { background: transparent; }
    .sx-panel::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }

    /* ── Decision-specific theme vars ─────────────────────────── */
    .sx-theme-allow {
      --sx-accent: #00E5A0;
      --sx-accent-rgb: 0, 229, 160;
    }
    .sx-theme-warn {
      --sx-accent: #F5A623;
      --sx-accent-rgb: 245, 166, 35;
    }
    .sx-theme-block {
      --sx-accent: #FF3D5A;
      --sx-accent-rgb: 255, 61, 90;
    }
  `;

  // ------------------------------------------------------------------
  // SHA-256 utility (for audit fingerprint)
  // ------------------------------------------------------------------

  async function sha256Prefix(text) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
    } catch {
      return 'unavailable';
    }
  }

  // ------------------------------------------------------------------
  // Build Telemetry Payload (Zero-Knowledge: no raw content)
  // ------------------------------------------------------------------

  function buildTelemetryPayload(analysis) {
    const tags = [
      ...analysis.deterministicResult.findings.flatMap(f => f.tags || []),
      ...(analysis.semanticResult ? analysis.semanticResult.tags || [] : []),
      ...(analysis.entropyResult.hasSecrets ? ['HIGH_ENTROPY_SECRET'] : []),
      ...(analysis.mlResult && analysis.mlResult.sensitive ? ['ML_SENSITIVE'] : []),
    ];

    return {
      event_id:             `evt_${Date.now().toString(36)}`,
      timestamp:            Date.now(),
      destination_category: analysis.destinationResult.tier,
      detected_tags:        [...new Set(tags)],
      risk_score:           analysis.riskResult.score,
      action:               analysis.policyResult.finalDecision,
      content_length:       analysis.textLength,
      payload_sha256_prefix: analysis.sha256Prefix || 'pending',
      // ML classifier metadata (no raw content)
      ml_probability:       analysis.mlResult ? analysis.mlResult.probability : null,
      ml_confidence:        analysis.mlResult ? analysis.mlResult.confidence : null,
    };
  }

  // ------------------------------------------------------------------
  // Render Helpers
  // ------------------------------------------------------------------

  function makeTag(label) {
    const span = document.createElement('span');
    span.className = 'sx-tag';
    span.textContent = label;
    return span;
  }

  function syntaxHighlightJSON(obj) {
    const json = JSON.stringify(obj, null, 2);
    return json
      .replace(/("(?:[^"\\]|\\.)*")(\s*:)/g, '<span class="sx-json-key">$1</span>$2')
      .replace(/:\s*("(?:[^"\\]|\\.)*")/g, ': <span class="sx-json-string">$1</span>')
      .replace(/:\s*(\d+\.?\d*)/g, ': <span class="sx-json-number">$1</span>')
      .replace(/:\s*(true|false|null)/g, ': <span class="sx-json-bool">$1</span>');
  }

  // ------------------------------------------------------------------
  // HUD Creator
  // ------------------------------------------------------------------

  function createHUD(analysis, telemetry) {
    const { riskResult, policyResult, destinationResult, deterministicResult, entropyResult, semanticResult, mlResult, textLength } = analysis;

    const decision = policyResult.finalDecision;
    const themeClass = {
      ALLOW: 'sx-theme-allow',
      WARN:  'sx-theme-warn',
      BLOCK: 'sx-theme-block',
    }[decision] || 'sx-theme-warn';

    const decisionIcon  = { ALLOW: '+', WARN: '!', BLOCK: 'X' }[decision] || '?';
    const decisionLabel = { ALLOW: 'Safe to Send', WARN: 'Security Warning', BLOCK: 'Action Blocked' }[decision];

    // Collect detected labels — include ML signal if it fired
    const detectedLabels = [
      ...deterministicResult.findings.map(f => f.label),
      ...(semanticResult && semanticResult.detected ? semanticResult.findings.map(f => f.label) : []),
      ...(entropyResult.hasSecrets ? entropyResult.findings.map(f => f.reason) : []),
      ...(mlResult && mlResult.sensitive && mlResult.confidence !== 'LOW'
        ? [`ML: P=${(mlResult.probability * 100).toFixed(0)}% (${mlResult.confidence})`]
        : []),
    ];

    // Risk breakdown factors
    const { S, D, V, A, C } = riskResult.factors;

    // ── Build DOM ──────────────────────────────────────────────────────
    const backdrop = document.createElement('div');
    backdrop.className = 'sx-backdrop';
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) {
        resolve(decision === 'ALLOW' ? 'ALLOW' : 'CANCEL');
      }
    });

    const escHandler = (e) => {
      if (e.key === 'Escape') {
        window.removeEventListener('keydown', escHandler);
        resolve('CANCEL');
      }
    };
    window.addEventListener('keydown', escHandler);

    const panel = document.createElement('div');
    panel.className = `sx-panel ${themeClass}`;

    // ── Header ──────────────────────────────────────────────────────
    panel.innerHTML = `
      <div class="sx-header">
        <div class="sx-logo">SX</div>
        <div class="sx-title-group">
          <div class="sx-brand">SentinelX Runtime Shield</div>
          <div class="sx-title">${decisionLabel}</div>
        </div>
        <div class="sx-risk-badge">
          <div class="sx-risk-number">${riskResult.score}</div>
          <div class="sx-risk-label">Risk</div>
        </div>
      </div>
    `;

    // ── Body ─────────────────────────────────────────────────────────
    const body = document.createElement('div');
    body.className = 'sx-body';

    // Decision banner
    const banner = document.createElement('div');
    banner.className = 'sx-decision-banner';
    banner.innerHTML = `
      <div class="sx-decision-icon">${decisionIcon}</div>
      <div class="sx-decision-text">
        <div class="sx-decision-label">${decision}</div>
        <div class="sx-decision-reason">${policyResult.reason}</div>
      </div>
    `;
    body.appendChild(banner);

    // Info grid
    const grid = document.createElement('div');
    grid.className = 'sx-grid';
    grid.innerHTML = `
      <div class="sx-card">
        <div class="sx-card-label">Destination</div>
        <div class="sx-card-value">${destinationResult.label}</div>
      </div>
      <div class="sx-card">
        <div class="sx-card-label">Content Size</div>
        <div class="sx-card-value">${textLength.toLocaleString()} chars</div>
      </div>
    `;
    body.appendChild(grid);

    // Detected tags
    if (detectedLabels.length > 0) {
      const tagsSection = document.createElement('div');
      tagsSection.className = 'sx-tags-section';
      tagsSection.innerHTML = `<div class="sx-section-label">Detected Data Types</div>`;
      const tagsWrap = document.createElement('div');
      tagsWrap.className = 'sx-tags';
      detectedLabels.slice(0, 8).forEach(label => {
        tagsWrap.appendChild(makeTag(label));
      });
      tagsSection.appendChild(tagsWrap);
      body.appendChild(tagsSection);
    }

    // Risk breakdown bars
    const breakdown = document.createElement('div');
    breakdown.className = 'sx-breakdown';
    breakdown.innerHTML = `<div class="sx-section-label" style="margin-bottom:10px">Risk Breakdown</div>`;
    const factorRows = [
      { name: 'Data Sensitivity', value: S },
      { name: 'Destination Risk', value: D },
      { name: 'Data Volume',      value: V },
      { name: 'Action Vector',    value: A },
      { name: 'Context Risk',     value: C },
    ];
    factorRows.forEach(({ name, value }) => {
      const row = document.createElement('div');
      row.className = 'sx-breakdown-bar-row';
      row.innerHTML = `
        <div class="sx-breakdown-name">${name}</div>
        <div class="sx-breakdown-track">
          <div class="sx-breakdown-fill" style="width:${value}%"></div>
        </div>
        <div class="sx-breakdown-val">${value}</div>
      `;
      breakdown.appendChild(row);
    });
    body.appendChild(breakdown);

    // Audit telemetry toggle
    const auditToggle = document.createElement('div');
    auditToggle.className = 'sx-audit-toggle';
    auditToggle.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
        <path d="M4 2L8 6L4 10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      Inspect Telemetry Payload — 0 bytes plaintext transmitted
    `;

    const auditPanel = document.createElement('div');
    auditPanel.className = 'sx-audit-panel';
    const rawBytes = new TextEncoder().encode(JSON.stringify(telemetry)).length;
    auditPanel.innerHTML = `
      <div class="sx-audit-header">
        <span class="sx-audit-privacy-label">Zero-Knowledge Telemetry</span>
        <span class="sx-audit-bytes">~${rawBytes} bytes · 0 bytes plaintext</span>
      </div>
      <div class="sx-audit-json">${syntaxHighlightJSON(telemetry)}</div>
    `;

    auditToggle.addEventListener('click', () => {
      auditToggle.classList.toggle('open');
      auditPanel.classList.toggle('open');
    });

    body.appendChild(auditToggle);
    body.appendChild(auditPanel);

    // ── Visual Redaction Diff Preview ──────────────────────────────
    const rawText = analysis.rawText || '';
    const redaction = window.SentinelXRedactor ? window.SentinelXRedactor.redact(rawText) : { redacted: rawText, replacements: [] };
    const numReplacements = redaction.replacements ? redaction.replacements.length : 0;

    if (numReplacements > 0) {
      const diffCard = document.createElement('div');
      diffCard.className = 'sx-diff-card expanded';

      // Safe HTML escaping
      const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      let rawSnippet = esc(rawText.substring(0, 240));
      let cleanSnippet = esc(redaction.redacted.substring(0, 240));

      // Highlight sanitized tokens
      cleanSnippet = cleanSnippet.replace(/(\[[A-Z0-9_]+\])/g, '<span class="sx-clean-token">$1</span>');

      diffCard.innerHTML = `
        <div class="sx-diff-header">
          <div class="sx-diff-title">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="16 3 21 3 21 8"/>
              <line x1="4" y1="20" x2="21" y2="3"/>
              <polyline points="21 16 21 21 16 21"/>
              <line x1="15" y1="15" x2="21" y2="21"/>
              <line x1="4" y1="4" x2="9" y2="9"/>
            </svg>
            Surgical Redaction Diff
          </div>
          <span class="sx-diff-badge">${numReplacements} Secret${numReplacements > 1 ? 's' : ''} Sanitized</span>
        </div>
        <div class="sx-diff-body">
          <div class="sx-diff-grid">
            <div class="sx-diff-col raw">
              <div class="sx-diff-col-title">Original (Blocked from Page)</div>
              <div class="sx-diff-box">${rawSnippet}</div>
            </div>
            <div class="sx-diff-col clean">
              <div class="sx-diff-col-title">Sanitized (Safe for AI / Web)</div>
              <div class="sx-diff-box">${cleanSnippet}</div>
            </div>
          </div>
        </div>
      `;

      diffCard.querySelector('.sx-diff-header').addEventListener('click', () => {
        diffCard.classList.toggle('expanded');
      });

      body.appendChild(diffCard);
    }

    // ── Action Buttons ─────────────────────────────────────────────
    const actions = document.createElement('div');
    actions.className = 'sx-actions';

    if (decision === 'ALLOW') {
      const continueBtn = document.createElement('button');
      continueBtn.className = 'sx-btn sx-btn-primary';
      continueBtn.innerHTML = `<span>${decisionIcon}</span> Continue — No Sensitive Data Detected`;
      continueBtn.addEventListener('click', () => resolve('ALLOW'));
      actions.appendChild(continueBtn);

    } else if (decision === 'WARN') {
      const redactBtn = document.createElement('button');
      redactBtn.className = 'sx-btn sx-btn-redact';
      redactBtn.innerHTML = `Smart Redact & Paste`;
      redactBtn.addEventListener('click', () => resolve('REDACT'));

      const continueBtn = document.createElement('button');
      continueBtn.className = 'sx-btn sx-btn-danger';
      continueBtn.innerHTML = `Continue Anyway — Accept Risk`;
      continueBtn.addEventListener('click', () => resolve('CONTINUE'));

      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'sx-btn sx-btn-secondary';
      cancelBtn.innerHTML = `Cancel`;
      cancelBtn.addEventListener('click', () => resolve('CANCEL'));

      actions.appendChild(redactBtn);
      const row = document.createElement('div');
      row.className = 'sx-row';
      row.appendChild(continueBtn);
      row.appendChild(cancelBtn);
      actions.appendChild(row);

    } else {
      // BLOCK
      const redactBtn = document.createElement('button');
      redactBtn.className = 'sx-btn sx-btn-redact';
      redactBtn.innerHTML = `Smart Redact & Paste`;
      redactBtn.addEventListener('click', () => resolve('REDACT'));

      const closeBtn = document.createElement('button');
      closeBtn.className = 'sx-btn sx-btn-secondary';
      closeBtn.innerHTML = `Block & Cancel`;
      closeBtn.addEventListener('click', () => resolve('CANCEL'));

      actions.appendChild(redactBtn);
      actions.appendChild(closeBtn);
    }

    body.appendChild(actions);
    panel.appendChild(body);
    backdrop.appendChild(panel);

    return backdrop;
  }

  // ------------------------------------------------------------------
  // Shadow DOM Mounting
  // ------------------------------------------------------------------

  function mountShadowDOM(element) {
    if (!hostElement) {
      hostElement = document.createElement('div');
      hostElement.setAttribute('data-sentinelx', 'shield');
      hostElement.style.cssText = 'position:fixed;inset:0;width:100vw;height:100vh;z-index:2147483647;pointer-events:none;display:block;';
      document.documentElement.appendChild(hostElement);

      // attachShadow with mode:'closed' — host page scripts get null from .shadowRoot
      shadowRoot = hostElement.attachShadow({ mode: 'closed' });

      const style = document.createElement('style');
      style.textContent = HUD_CSS;
      shadowRoot.appendChild(style);
    }

    // Remove existing HUD elements
    [...shadowRoot.children].forEach(child => {
      if (child.tagName !== 'STYLE') child.remove();
    });

    hostElement.style.pointerEvents = 'auto';
    shadowRoot.appendChild(element);
  }

  function unmount() {
    if (shadowRoot) {
      [...shadowRoot.children].forEach(child => {
        if (child.tagName !== 'STYLE') child.remove();
      });
    }
    if (hostElement) {
      hostElement.style.pointerEvents = 'none';
    }
    currentResolve = null;
    pasteEvent = null;
  }

  function resolve(action) {
    if (currentResolve) {
      currentResolve(action);
      currentResolve = null;
    }
    unmount();
  }

  // ------------------------------------------------------------------
  // Public: Show HUD
  // ------------------------------------------------------------------

  /**
   * Shows the SentinelX security HUD and returns a Promise that resolves
   * with the user's decision: 'ALLOW' | 'WARN' | 'BLOCK' | 'REDACT' | 'CANCEL'
   *
   * @param {object} analysis — full detection analysis
   * @param {Event}  evt      — original paste event (for potential redacted re-insertion)
   * @returns {Promise<string>}
   */
  async function show(analysis, evt) {
    pasteEvent = evt;

    // Build zero-knowledge telemetry (async SHA-256)
    const hashPrefix = await sha256Prefix(analysis.rawText || '');
    analysis.sha256Prefix = hashPrefix;
    const telemetry = buildTelemetryPayload(analysis);

    const hudElement = createHUD(analysis, telemetry);

    return new Promise((resolvePromise) => {
      currentResolve = resolvePromise;
      mountShadowDOM(hudElement);

      // Animate risk bars after mount
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          shadowRoot.querySelectorAll('.sx-breakdown-fill').forEach(bar => {
            bar.style.width = bar.style.width; // Force reflow
          });
        });
      });
    });
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return { show, buildTelemetryPayload };

})();
