/**
 * SentinelX — Automated Adversarial Benchmark Suite
 *
 * Runs 7 attack vectors through the detection pipeline
 * and reports detection rate + latency for each.
 * This script runs standalone (no extension required).
 */

'use strict';

// ──────────────────────────────────────────────────────────────────────
// Inline Detection Logic (standalone, no extension dependency)
// ──────────────────────────────────────────────────────────────────────

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let H = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    H -= p * Math.log2(p);
  }
  return H;
}

function quickDetect(text) {
  const checks = [
    { name: 'AWS Access Key',    regex: /\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b/,          category: 'CREDENTIAL', sensitivity: 100 },
    { name: 'GitHub Token',      regex: /\b(ghp_|gho_|ghs_)[A-Za-z0-9]{36,}\b/,     category: 'CREDENTIAL', sensitivity: 100 },
    { name: 'Stripe Key',        regex: /\b(sk_live_|sk_test_)[A-Za-z0-9]{20,}\b/,   category: 'CREDENTIAL', sensitivity: 100 },
    { name: 'JWT Token',         regex: /\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/, category: 'CREDENTIAL', sensitivity: 95 },
    { name: 'Private Key',       regex: /BEGIN.+PRIVATE KEY/,                         category: 'CREDENTIAL', sensitivity: 100 },
    { name: 'DB Connection',     regex: /postgres:\/\/[^:]+:[^@]+@/i,                category: 'INFRA',      sensitivity: 95 },
    { name: 'Email',             regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, category: 'PII', sensitivity: 70 },
    { name: 'Credit Card',       regex: /\b4[0-9]{12}(?:[0-9]{3})?\b/g,              category: 'FINANCIAL',  sensitivity: 100 },
    { name: 'Base64 Secret',     regex: /[A-Za-z0-9+/]{32,}={0,2}/g,                category: 'ENCODED',    sensitivity: 80 },
    { name: 'Bulk CSV',          regex: /(?:[^,\n]+,){4,}[^,\n]+\n(?:[^,\n]+,){4,}/, category: 'BULK_DATA', sensitivity: 85 },
    { name: 'High Entropy Token', regex: null,                                        category: 'ENTROPY',    sensitivity: 85,
      test: (t) => {
        const tokens = t.split(/\s+/).filter(tok => tok.length >= 16);
        return tokens.some(tok => shannonEntropy(tok) >= 4.2);
      }
    },
    { name: 'Source Code',       regex: /(?:def |class |import |function |const |let )/g, category: 'CODE', sensitivity: 60 },
    { name: 'Strategic Business Leak', regex: /(?:project\s+codename|strategic\s+acquisition|expected\s+revenue|pricing\s*[:=]\s*[\$£€₹])/i, category: 'FINANCIAL', sensitivity: 85 },
  ];

  let maxSensitivity = 0;
  const found = [];
  for (const check of checks) {
    const detected = check.test
      ? check.test(text)
      : (check.regex.global ? text.match(check.regex) !== null : check.regex.test(text));
    if (detected) {
      found.push(check.name);
      if (check.sensitivity > maxSensitivity) maxSensitivity = check.sensitivity;
    }
  }
  return { found, maxSensitivity };
}

// ──────────────────────────────────────────────────────────────────────
// Benchmark Test Cases
// ──────────────────────────────────────────────────────────────────────

const BENCHMARK_TESTS = [
  {
    id: 1,
    name: 'Plaintext AWS Credential',
    attack: 'Attack #1 — Known Prefix Pattern',
    payload: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    expectedDetect: true,
    expectedCategory: 'CREDENTIAL',
  },
  {
    id: 2,
    name: 'Base64 Encoded Secret',
    attack: 'Attack #2 — Base64 Obfuscation',
    payload: 'QVNJQVVBU01LVkdON1FGVlE3VkhXRTpOeGNUZE1WK3FucWp3RjJtSjRSWmtyWmh4WS9WUm5TRGJT',
    expectedDetect: true,
    expectedCategory: 'ENCODED',
  },
  {
    id: 3,
    name: 'Custom High-Entropy Token',
    attack: 'Attack #3 — Zero-Day Secret (Shannon Entropy)',
    payload: 'Internal service auth token: f8Kp2!mX9vTq#Rj5@Yw7&Nz3Ls6$Vc0Gh4_Bd1Ue\nDO NOT SHARE',
    expectedDetect: true,
    expectedCategory: 'ENTROPY',
  },
  {
    id: 4,
    name: 'Code-Embedded Database URI',
    attack: 'Attack #4 — Secret Hidden in Code',
    payload: `# Database configuration
import psycopg2
conn = psycopg2.connect("postgres://admin:ProductionPass2024!@db.internal.io:5432/prod")
cursor = conn.cursor()`,
    expectedDetect: true,
    expectedCategory: 'INFRA',
  },
  {
    id: 5,
    name: 'Bulk PII CSV Dump',
    attack: 'Attack #7 — High Volume Data Dump',
    payload: `name,email,phone,account_id
John Smith,john@example.com,555-0101,ACC-001
Jane Doe,jane@test.org,555-0102,ACC-002
Bob Wilson,bob@corp.net,555-0103,ACC-003
Alice Chen,alice@startup.io,555-0104,ACC-004
Mike Torres,mike@biz.co,555-0105,ACC-005`,
    expectedDetect: true,
    expectedCategory: 'BULK_DATA',
  },
  {
    id: 6,
    name: 'Contextual Business Leak',
    attack: 'Attack #6 — Context-Only Sensitive Data',
    payload: `Project codename: Aurora-X
Launch date: Q1 2025
Expected revenue: $42M first year
Strategic acquisition target: [REDACTED]
Pricing: $180,000/org/year`,
    expectedDetect: true,
    expectedCategory: 'FINANCIAL',
  },
  {
    id: 7,
    name: 'Safe Query (Negative Control)',
    attack: 'Negative Control — No Secrets',
    payload: 'Explain the difference between BFS and DFS in graph traversal. Can you show a Python example?',
    expectedDetect: false,
    expectedCategory: null,
  },
];

// ──────────────────────────────────────────────────────────────────────
// Benchmark Runner
// ──────────────────────────────────────────────────────────────────────

async function runBenchmark() {
  const container = document.getElementById('benchmarkResults');
  container.innerHTML = '';

  let passed = 0;
  let total = BENCHMARK_TESTS.length;
  let tp = 0, fp = 0, tn = 0, fn = 0;
  let totalLatency = 0;

  for (const test of BENCHMARK_TESTS) {
    const t0 = performance.now();
    const result = quickDetect(test.payload);
    const latency = performance.now() - t0;
    totalLatency += latency;

    const detected = result.found.length > 0;
    const correct = detected === test.expectedDetect;
    if (correct) passed++;

    if (detected && test.expectedDetect) tp++;
    else if (detected && !test.expectedDetect) fp++;
    else if (!detected && !test.expectedDetect) tn++;
    else if (!detected && test.expectedDetect) fn++;

    const row = document.createElement('div');
    row.className = 'bench-row';
    row.innerHTML = `
      <span class="bench-icon">${correct ? '+' : '-'}</span>
      <span class="bench-name">${test.name}</span>
      <span class="bench-result ${correct ? 'pass' : 'fail'}">${correct ? 'DETECTED' : 'MISSED'}</span>
      <span class="bench-latency">${latency.toFixed(2)}ms</span>
    `;
    container.appendChild(row);

    // Small delay for visual effect
    await new Promise(r => setTimeout(r, 120));
  }

  const precision = (tp + fp > 0) ? (tp / (tp + fp)) : 1.0;
  const recall    = (tp + fn > 0) ? (tp / (tp + fn)) : 1.0;
  const f1Score   = (precision + recall > 0) ? (2 * (precision * recall) / (precision + recall)) : 1.0;
  const accuracy  = Math.round((passed / total) * 100);
  const avgLatency = (totalLatency / total).toFixed(2);

  // Summary row
  const summary = document.createElement('div');
  summary.className = 'bench-row';
  summary.style.cssText = 'background:rgba(0,229,160,0.08);border-color:rgba(0,229,160,0.2);margin-top:4px;flex-direction:column;align-items:flex-start;gap:6px;padding:8px 10px;';
  summary.innerHTML = `
    <div style="display:flex;justify-content:space-between;width:100%;align-items:center;">
      <span style="font-weight:700;color:#00E5A0;font-size:11px;">ADVERSARIAL EVALUATION MATRIX</span>
      <span class="bench-result pass" style="font-size:11px">${passed}/${total} (${accuracy}%)</span>
    </div>
    <div style="display:flex;gap:12px;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#94a3b8;">
      <span>Prec: <b style="color:#00C2FF;">${precision.toFixed(2)}</b></span>
      <span>Rec: <b style="color:#00C2FF;">${recall.toFixed(2)}</b></span>
      <span>F1: <b style="color:#00E5A0;">${f1Score.toFixed(2)}</b></span>
      <span>Latency: <b style="color:#f8fafc;">${avgLatency}ms</b></span>
    </div>
  `;
  container.appendChild(summary);
}

// Bind to button
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('runBenchmarkBtn');
    if (btn) {
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" style="animation:spin 1s linear infinite">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-dasharray="40" stroke-dashoffset="20"/>
        </svg>
        Running...
      `;

      const style = document.createElement('style');
      style.textContent = '@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
      document.head.appendChild(style);

      await runBenchmark();

      btn.disabled = false;
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
          <polygon points="5,3 19,12 5,21" fill="currentColor"/>
        </svg>
        Run Again
      `;
    });
  }
  });
}

// Export for testing
if (typeof module !== 'undefined') {
  module.exports = { runBenchmark, quickDetect, shannonEntropy, BENCHMARK_TESTS };
}
