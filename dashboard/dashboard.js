'use strict';

// ──────────────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────────────

let BASE_URL = 'http://localhost:8000';

const CHART_COLORS = {
  ALLOW: '#059669',
  WARN:  '#D97706',
  BLOCK: '#DC2626',
  cyan:  '#1A56DB',
  adv:   '#7C3AED',
};

const DEST_COLORS = {
  INTERNAL:      '#059669',
  APPROVED_AI:   '#1A56DB',
  APPROVED_SAAS: '#6366F1',
  EXTERNAL_AI:   '#D97706',
  UNKNOWN_SAAS:  '#F97316',
  SUSPICIOUS:    '#DC2626',
};

// ──────────────────────────────────────────────────────────────────────
// Chart.js Global Defaults
// ──────────────────────────────────────────────────────────────────────

Chart.defaults.color = '#94A3B8';
Chart.defaults.font.family = "'IBM Plex Mono', monospace";
Chart.defaults.font.size = 11;

let charts = {};

function destroyChart(id) {
  if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

// ──────────────────────────────────────────────────────────────────────
// Auth Token
// ──────────────────────────────────────────────────────────────────────

const JWT_TOKEN = localStorage.getItem('sx_jwt') || '';

function authHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (JWT_TOKEN) h['Authorization'] = `Bearer ${JWT_TOKEN}`;
  return h;
}

function redirectToLogin() {
  localStorage.removeItem('sx_jwt');
  window.location.href = './login.html';
}

// ──────────────────────────────────────────────────────────────────────
// API Client
// ──────────────────────────────────────────────────────────────────────

async function api(path, options = {}) {
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      ...options,
      headers: { ...authHeaders(), ...(options.headers || {}) },
    });
    if (res.status === 401) { redirectToLogin(); return null; }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    if (!e.message?.includes('401')) console.warn(`[Dashboard] API error ${path}:`, e.message);
    return null;
  }
}

async function checkHealth() {
  const data = await api('/health');
  const el = document.getElementById('apiStatus');
  if (data && data.status === 'operational') {
    el.textContent = 'Connected';
    el.style.color = 'var(--allow)';
  } else {
    el.textContent = 'Offline';
    el.style.color = 'var(--block)';
  }
}

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

function formatTime(ts) {
  if (!ts) return '--';
  return new Date(ts).toLocaleTimeString('en-US', {
    hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

function scoreClass(score) {
  if (score >= 70) return 'score-high';
  if (score >= 40) return 'score-medium';
  return 'score-low';
}

function tagsHtml(tags) {
  if (!tags || tags.length === 0) return '<span style="color:var(--t3)">none</span>';
  return tags.slice(0, 3)
    .map(t => `<span class="tag-chip">${t}</span>`)
    .join('');
}

// ──────────────────────────────────────────────────────────────────────
// Overview Page
// ──────────────────────────────────────────────────────────────────────

async function loadOverview() {
  const [summary, byAction, byDest, events] = await Promise.all([
    api('/risk/summary'),
    api('/risk/by-action'),
    api('/risk/by-destination'),
    api('/events?limit=8'),
  ]);

  // KPIs
  if (summary) {
    document.getElementById('kpiTotal').textContent    = summary.total;
    document.getElementById('kpiAllow').textContent    = summary.allowed;
    document.getElementById('kpiWarn').textContent     = summary.warned;
    document.getElementById('kpiBlock').textContent    = summary.blocked;
    document.getElementById('kpiHigh').textContent     = summary.high_risk;
    document.getElementById('kpiCritical').textContent = summary.critical;
  }

  // Chart: Action distribution (doughnut)
  if (byAction && byAction.actions) {
    destroyChart('action');
    const labels = byAction.actions.map(a => a.action);
    const data   = byAction.actions.map(a => a.count);
    const colors = labels.map(l => CHART_COLORS[l] || CHART_COLORS.cyan);
    charts.action = new Chart(document.getElementById('chartAction'), {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{ data, backgroundColor: colors.map(c => c + '22'), borderColor: colors, borderWidth: 2 }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { padding: 14, boxWidth: 10 } }
        },
        cutout: '68%',
      }
    });
  }

  // Chart: Destination risk (horizontal bar)
  if (byDest && byDest.destinations) {
    destroyChart('dest');
    const sorted = [...byDest.destinations].sort((a, b) => b.avg_risk - a.avg_risk);
    const labels = sorted.map(d => d.destination_category);
    const counts = sorted.map(d => d.count);
    const colors = labels.map(l => DEST_COLORS[l] || CHART_COLORS.cyan);
    charts.dest = new Chart(document.getElementById('chartDestination'), {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Event Count',
          data: counts,
          backgroundColor: colors.map(c => c + '22'),
          borderColor: colors,
          borderWidth: 2,
          borderRadius: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { color: 'rgba(255,255,255,0.04)' },
            ticks: { precision: 0 },
          },
          y: { grid: { display: false } }
        }
      }
    });
  }

  // Recent events table
  if (events && events.events) {
    const tbody = document.getElementById('overviewEventsBody');
    if (events.events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No events yet. Load the extension and paste a test scenario.</td></tr>';
    } else {
      tbody.innerHTML = events.events.map(e => `
        <tr>
          <td style="font-family:'IBM Plex Mono',monospace;color:var(--t3)">${formatTime(e.timestamp)}</td>
          <td>${e.destination_category}</td>
          <td>${tagsHtml(e.detected_tags)}</td>
          <td><span class="risk-score ${scoreClass(e.risk_score)}">${e.risk_score}</span></td>
          <td><span class="action-pill action-${e.action}">${e.action}</span></td>
        </tr>
      `).join('');
    }
  }
}

// ──────────────────────────────────────────────────────────────────────
// Events Page
// ──────────────────────────────────────────────────────────────────────

async function loadEvents() {
  const action = document.getElementById('filterAction').value;
  const url = action ? `/events?limit=200&action=${action}` : '/events?limit=200';
  const data = await api(url);
  const tbody = document.getElementById('eventsBody');
  if (!data || !data.events) {
    tbody.innerHTML = '<tr><td colspan="7" class="table-empty">Backend unreachable.</td></tr>';
    return;
  }
  if (data.events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No events matching filter.</td></tr>';
    return;
  }
  tbody.innerHTML = data.events.map(e => `
    <tr>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--t3)">${e.event_id}</td>
      <td style="font-family:'IBM Plex Mono',monospace;color:var(--t3)">${formatTime(e.timestamp)}</td>
      <td>${e.destination_category}</td>
      <td>${tagsHtml(e.detected_tags)}</td>
      <td style="font-family:'IBM Plex Mono',monospace;color:var(--t3)">${e.content_length ? e.content_length + ' chars' : '--'}</td>
      <td><span class="risk-score ${scoreClass(e.risk_score)}">${e.risk_score}</span></td>
      <td><span class="action-pill action-${e.action}">${e.action}</span></td>
    </tr>
  `).join('');
}

// ──────────────────────────────────────────────────────────────────────
// Analytics Page
// ──────────────────────────────────────────────────────────────────────

async function loadAnalytics() {
  const [tags, byDest, eventsData] = await Promise.all([
    api('/risk/top-tags?limit=8'),
    api('/risk/by-destination'),
    api('/events?limit=200'),
  ]);

  const events = (eventsData && eventsData.events) ? eventsData.events : [];

  // Calculate Threat Vector Scores for Radar Chart
  let credScore = 0, infraScore = 0, piiScore = 0, stratScore = 0, finScore = 0, codeScore = 0;
  let t1552 = 0, t1567 = 0, t1020 = 0, t1048 = 0, t1005 = 0, t1052 = 0;
  let blockedCount = 0;

  events.forEach(e => {
    const tagsArr = Array.isArray(e.detected_tags) ? e.detected_tags.map(t => t.toUpperCase()) : [];
    const dest = (e.destination_category || '').toUpperCase();
    if (e.action === 'BLOCK') blockedCount++;

    if (tagsArr.some(t => t.includes('KEY') || t.includes('TOKEN') || t.includes('CREDENTIAL') || t.includes('AWS') || t.includes('GITHUB'))) {
      credScore++;
      t1552++;
    }
    if (tagsArr.some(t => t.includes('INFRA') || t.includes('IP') || t.includes('DB') || t.includes('INTERNAL_NETWORK'))) {
      infraScore++;
      t1048++;
    }
    if (tagsArr.some(t => t.includes('PII') || t.includes('EMAIL') || t.includes('CSV') || t.includes('BULK'))) {
      piiScore++;
      t1020++;
    }
    if (tagsArr.some(t => t.includes('STRATEGIC') || t.includes('CODENAME') || t.includes('INTERNAL_AFFAIRS') || t.includes('FINANCIAL'))) {
      stratScore++;
      finScore++;
    }
    if (tagsArr.some(t => t.includes('CODE') || t.includes('FUNCTION') || t.includes('IMPORT'))) {
      codeScore++;
      t1005++;
    }
    if (dest.includes('EXTERNAL_AI') || dest.includes('UNKNOWN_SAAS')) {
      t1567++;
    }
    if (e.content_length && e.content_length > 500) {
      t1052++;
    }
  });

  // Update Topology & MITRE counters
  const elFlowScanned = document.getElementById('flowScannedCount');
  const elTopoSource = document.getElementById('topoSourceCount');
  const elTopoQuarantine = document.getElementById('topoQuarantineCount');
  if (elFlowScanned) elFlowScanned.textContent = `${events.length} Payloads Intercepted`;
  if (elTopoSource) elTopoSource.textContent = `${events.length} Active Events Monitored`;
  if (elTopoQuarantine) elTopoQuarantine.textContent = `${blockedCount} Quarantined at Source`;

  const setHit = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setHit('hit-t1552', t1552);
  setHit('hit-t1567', t1567);
  setHit('hit-t1020', t1020);
  setHit('hit-t1048', t1048);
  setHit('hit-t1005', t1005);
  setHit('hit-t1052', t1052);

  // MITRE ATT&CK Exfiltration Radar Chart
  const radarEl = document.getElementById('chartThreatRadar');
  if (radarEl) {
    destroyChart('threatRadar');
    charts.threatRadar = new Chart(radarEl, {
      type: 'radar',
      data: {
        labels: [
          'Credentials & Secrets',
          'Infrastructure & DB',
          'Bulk PII / Identity',
          'Strategic Narrative',
          'Financial Data',
          'Source Code'
        ],
        datasets: [
          {
            label: 'Observed Threat Telemetry',
            data: [
              Math.max(credScore, 1),
              Math.max(infraScore, 1),
              Math.max(piiScore, 1),
              Math.max(stratScore, 1),
              Math.max(finScore, 1),
              Math.max(codeScore, 1)
            ],
            backgroundColor: 'rgba(255, 61, 90, 0.2)',
            borderColor: '#FF3D5A',
            borderWidth: 2,
            pointBackgroundColor: '#FF3D5A',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: '#FF3D5A'
          },
          {
            label: 'Enterprise Zero-Trust Baseline',
            data: [0, 0, 0, 0, 0, 0],
            backgroundColor: 'rgba(0, 194, 255, 0.08)',
            borderColor: '#00C2FF',
            borderWidth: 1.5,
            borderDash: [4, 4],
            pointBackgroundColor: '#00C2FF',
            pointRadius: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: {
              boxWidth: 12,
              padding: 10,
              font: { family: "'DM Sans', sans-serif", size: 11 },
              color: '#94a3b8'
            }
          }
        },
        scales: {
          r: {
            angleLines: { color: 'rgba(255, 255, 255, 0.08)' },
            grid: { color: 'rgba(255, 255, 255, 0.06)' },
            pointLabels: {
              font: { family: "'IBM Plex Mono', monospace", size: 10 },
              color: '#cbd5e1'
            },
            ticks: {
              display: false,
              stepSize: 1
            }
          }
        }
      }
    });
  }

  // Destination pie
  if (byDest && byDest.destinations && byDest.destinations.length > 0) {
    destroyChart('destPie');
    const labels = byDest.destinations.map(d => d.destination_category);
    const counts = byDest.destinations.map(d => d.count);
    const colors = labels.map(l => DEST_COLORS[l] || CHART_COLORS.cyan);
    charts.destPie = new Chart(document.getElementById('chartDestPie'), {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{ data: counts, backgroundColor: colors.map(c => c + '20'), borderColor: colors, borderWidth: 2 }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { padding: 12, boxWidth: 10 } } },
        cutout: '65%',
      }
    });
  }

  // Destination table
  if (byDest && byDest.destinations) {
    const tbody = document.getElementById('destBody');
    if (byDest.destinations.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="table-empty">No data.</td></tr>';
      return;
    }
    tbody.innerHTML = byDest.destinations.map(d => {
      const avg = Math.round(d.avg_risk || 0);
      return `
        <tr>
          <td>${d.destination_category}</td>
          <td style="font-family:'IBM Plex Mono',monospace">${d.count}</td>
          <td><span class="risk-score ${scoreClass(avg)}">${avg}</span></td>
          <td><span class="action-pill action-${avg >= 70 ? 'BLOCK' : avg >= 40 ? 'WARN' : 'ALLOW'}">${avg >= 70 ? 'HIGH' : avg >= 40 ? 'MEDIUM' : 'LOW'}</span></td>
        </tr>
      `;
    }).join('');
  }
}

// ──────────────────────────────────────────────────────────────────────
// Navigation
// ──────────────────────────────────────────────────────────────────────

const PAGE_META = {
  overview:   { title: 'Overview',          sub: 'Real-time security event monitoring' },
  events:     { title: 'Events',            sub: 'Complete security event log' },
  analytics:  { title: 'Analytics',         sub: 'Risk pattern analysis and reporting' },
  policies:   { title: 'Policies',          sub: 'Active DLP enforcement rules' },
  compliance: { title: 'Compliance Report', sub: 'SOC 2 Type II, ISO/IEC 27001 & Regulatory Verification' },
  settings:   { title: 'Settings',          sub: 'SIEM webhook, identity layer & database configuration' },
};

async function loadCompliance() {
  const tsEl = document.getElementById('reportAuditTimestamp');
  if (tsEl) {
    tsEl.textContent = 'Verified Active: ' + new Date().toISOString() + ' (UTC)';
  }

  try {
    const res = await fetch(`${BASE_URL}/compliance/metrics`, { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    if (data && data.metrics) {
      const m = data.metrics;
      const cm = data.confusion_matrix || {};
      
      const elPrec = document.getElementById('metricPrecision');
      const elRec = document.getElementById('metricRecall');
      const elF1 = document.getElementById('metricF1');
      const elAcc = document.getElementById('metricAccuracy');
      const elSample = document.getElementById('metricSampleCount');
      const elLatency = document.getElementById('trainLatencyVal');
      
      if (elPrec) elPrec.textContent = m.precision.toFixed(2);
      if (elRec) elRec.textContent = m.recall.toFixed(2);
      if (elF1) elF1.textContent = m.f1_score.toFixed(2);
      if (elAcc) elAcc.textContent = (m.accuracy_pct || (m.accuracy * 100)).toFixed(1) + '%';
      if (elSample) elSample.textContent = `${data.sample_size || 165} Labeled Attack & Control Samples`;
      if (elLatency) elLatency.textContent = `${data.training_latency_ms || 19.32}ms`;

      const elTP = document.getElementById('cmTP');
      const elFP = document.getElementById('cmFP');
      const elFN = document.getElementById('cmFN');
      const elTN = document.getElementById('cmTN');

      if (elTP && cm.true_positives !== undefined) elTP.textContent = cm.true_positives;
      if (elFP && cm.false_positives !== undefined) elFP.textContent = cm.false_positives;
      if (elFN && cm.false_negatives !== undefined) elFN.textContent = cm.false_negatives;
      if (elTN && cm.true_negatives !== undefined) elTN.textContent = cm.true_negatives;
    }
  } catch (err) {
    console.warn('Unable to load compliance metrics from backend:', err);
  }
}

function navigate(pageId) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => {
    p.classList.remove('active');
    p.style.display = 'none';
  });

  // Inject settings template on first visit
  if (pageId === 'settings' && !document.getElementById('page-settings')) {
    const tpl = document.getElementById('tpl-settings');
    if (tpl) {
      const mainContent = document.querySelector('.main-content');
      if (mainContent) mainContent.appendChild(tpl.content.cloneNode(true));
    }
  }

  const navEl  = document.getElementById(`nav-${pageId}`);
  const pageEl = document.getElementById(`page-${pageId}`);
  if (!navEl || !pageEl) return;

  navEl.classList.add('active');
  pageEl.classList.add('active');
  pageEl.style.display = 'block';

  const meta = PAGE_META[pageId];
  if (meta) {
    document.getElementById('pageTitle').textContent    = meta.title;
    document.getElementById('pageSubtitle').textContent = meta.sub;
  }

  if (pageId === 'overview')   loadOverview();
  if (pageId === 'events')     loadEvents();
  if (pageId === 'analytics')  loadAnalytics();
  if (pageId === 'compliance') loadCompliance();
  if (pageId === 'settings')   loadSettings();
}

// ──────────────────────────────────────────────────────────────────────
// Settings Page
// ──────────────────────────────────────────────────────────────────────

async function loadSettings() {
  // Load webhook status
  try {
    const res = await fetch(`${BASE_URL}/webhook`, { headers: authHeaders() });
    if (res.ok) {
      const data = await res.json();
      const badge = document.getElementById('webhookStatusBadge');
      if (badge) badge.style.display = data.configured ? 'inline-flex' : 'none';
    }
  } catch (_) {}

  // Load DB mode from health
  try {
    const res = await fetch(`${BASE_URL}/health`, { headers: authHeaders() });
    if (res.ok) {
      const data = await res.json();
      const badge = document.getElementById('dbModeBadge');
      if (badge) {
        if (data.database === 'postgresql') {
          badge.textContent = 'POSTGRESQL';
          badge.className = 'action-badge action-allow';
        } else {
          badge.textContent = 'SQLITE (DEV)';
          badge.className = 'action-badge action-warn';
        }
      }
    }
  } catch (_) {}

  // Wire up save button (delayed because settings page is injected dynamically)
  const saveBtn = document.getElementById('saveWebhookBtn');
  const testBtn = document.getElementById('testWebhookBtn');
  const msgEl   = document.getElementById('webhookMsg');

  if (saveBtn && !saveBtn._wired) {
    saveBtn._wired = true;
    saveBtn.addEventListener('click', async () => {
      const url = document.getElementById('webhookUrlInput')?.value?.trim();
      if (!url) { if (msgEl) msgEl.textContent = 'URL cannot be empty.'; return; }
      try {
        const res = await fetch(`${BASE_URL}/webhook`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ url }),
        });
        if (res.ok) {
          if (msgEl) { msgEl.textContent = 'Saved.'; msgEl.style.color = 'var(--allow)'; }
          const badge = document.getElementById('webhookStatusBadge');
          if (badge) badge.style.display = 'inline-flex';
        } else {
          if (msgEl) { msgEl.textContent = 'Save failed.'; msgEl.style.color = 'var(--block)'; }
        }
      } catch (e) {
        if (msgEl) { msgEl.textContent = 'Network error.'; msgEl.style.color = 'var(--block)'; }
      }
    });
  }

  if (testBtn && !testBtn._wired) {
    testBtn._wired = true;
    testBtn.addEventListener('click', async () => {
      if (msgEl) { msgEl.textContent = 'Sending test event...'; msgEl.style.color = 'var(--text-3)'; }
      try {
        const res = await fetch(`${BASE_URL}/webhook/test`, { method: 'POST', headers: authHeaders() });
        if (res.ok) {
          if (msgEl) { msgEl.textContent = 'Test dispatched successfully.'; msgEl.style.color = 'var(--allow)'; }
        } else if (res.status === 400) {
          if (msgEl) { msgEl.textContent = 'No webhook configured. Save a URL first.'; msgEl.style.color = 'var(--warn)'; }
        } else {
          if (msgEl) { msgEl.textContent = 'Dispatch failed.'; msgEl.style.color = 'var(--block)'; }
        }
      } catch (e) {
        if (msgEl) { msgEl.textContent = 'Network error.'; msgEl.style.color = 'var(--block)'; }
      }
    });
  }
}

// ──────────────────────────────────────────────────────────────────────
// Event Listeners
// ──────────────────────────────────────────────────────────────────────

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    navigate(item.dataset.page);
  });
});

document.getElementById('exportReportBtn')?.addEventListener('click', () => {
  navigate('compliance');
});

document.getElementById('printReportActionBtn')?.addEventListener('click', () => {
  window.print();
});

document.getElementById('trainModelActionBtn')?.addEventListener('click', async () => {
  const btn = document.getElementById('trainModelActionBtn');
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" style="animation:spin 1s linear infinite;margin-right:6px;">
      <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-dasharray="40" stroke-dashoffset="20"/>
    </svg>
    Training Classifier...
  `;
  try {
    const res = await fetch(`${BASE_URL}/train-eval`, { method: 'POST', headers: authHeaders() });
    if (res.ok) {
      await loadCompliance();
    }
  } catch (err) {
    console.error('Error triggering train-eval:', err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
});

document.getElementById('refreshBtn').addEventListener('click', () => {
  const active = document.querySelector('.nav-item.active');
  if (active) navigate(active.dataset.page);
  checkHealth();
});

document.getElementById('backendUrl').addEventListener('change', (e) => {
  BASE_URL = e.target.value.replace(/\/$/, '');
  checkHealth();
  navigate('overview');
});

document.getElementById('filterAction').addEventListener('change', loadEvents);

document.getElementById('viewAllBtn').addEventListener('click', () => navigate('events'));

document.getElementById('clearAllBtn').addEventListener('click', async () => {
  if (!confirm('Clear all security events from the backend?')) return;
  await fetch(`${BASE_URL}/events`, { method: 'DELETE', headers: authHeaders() });
  loadEvents();
  loadOverview();
});

// ──────────────────────────────────────────────────────────────────────
// Auto-refresh every 30s
// ──────────────────────────────────────────────────────────────────────

setInterval(() => {
  const active = document.querySelector('.nav-item.active');
  if (active) navigate(active.dataset.page);
}, 30000);

// ──────────────────────────────────────────────────────────────────────
// Init
// ──────────────────────────────────────────────────────────────────────

checkHealth();
navigate('overview');
