'use strict';

// ------------------------------------------------------------------
// State
// ------------------------------------------------------------------

let events = [];

// ------------------------------------------------------------------
// DOM Refs
// ------------------------------------------------------------------

const toggleEl      = document.getElementById('toggleEnabled');
const statusBar     = document.getElementById('statusBar');
const statusDot     = document.getElementById('statusDot');
const statusText    = document.getElementById('statusText');
const statAllow     = document.getElementById('statAllow');
const statWarn      = document.getElementById('statWarn');
const statBlock     = document.getElementById('statBlock');
const eventsList    = document.getElementById('eventsList');
const clearBtn      = document.getElementById('clearBtn');
const lastPayload   = document.getElementById('lastPayload');
const auditBackend  = document.getElementById('auditBackendUrl');
const tabBtns       = document.querySelectorAll('.tab');
const tabPanels     = document.querySelectorAll('.tab-panel');

// ------------------------------------------------------------------
// Tab Switching
// ------------------------------------------------------------------

tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    tabBtns.forEach(b => b.classList.remove('active'));
    tabPanels.forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

// ------------------------------------------------------------------
// Toggle Enable/Disable
// ------------------------------------------------------------------

toggleEl.addEventListener('change', () => {
  const enabled = toggleEl.checked;
  chrome.storage.local.set({ sx_enabled: enabled });
  updateStatusBar(enabled);
});

function updateStatusBar(enabled) {
  if (enabled) {
    statusBar.classList.remove('inactive');
    statusText.textContent = 'Shield Active — Monitoring';
  } else {
    statusBar.classList.add('inactive');
    statusText.textContent = 'Shield Disabled';
  }
}

// ------------------------------------------------------------------
// Events Rendering
// ------------------------------------------------------------------

function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function renderEvents(events) {
  if (!events || events.length === 0) {
    eventsList.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/>
          </svg>
        </div>
        <div class="empty-text">No events yet</div>
        <div class="empty-sub">SentinelX is monitoring your browser activity</div>
      </div>
    `;
    return;
  }

  eventsList.innerHTML = '';
  events.slice(0, 50).forEach(event => {
    const item = document.createElement('div');
    item.className = 'event-item';

    const tagStr = (event.detected_tags || []).slice(0, 3).join(', ') || 'No tags';

    item.innerHTML = `
      <div class="event-indicator ${event.action}"></div>
      <div class="event-body">
        <div class="event-destination">${event.destination_category || 'Unknown'}</div>
        <div class="event-tags">${tagStr}</div>
      </div>
      <div class="event-meta">
        <div class="event-score ${event.action}">${event.risk_score}</div>
        <div class="event-time">${formatTime(event.timestamp)}</div>
      </div>
    `;
    eventsList.appendChild(item);
  });
}

function updateStats(events) {
  const counts = { ALLOW: 0, WARN: 0, BLOCK: 0 };
  events.forEach(e => {
    if (counts[e.action] !== undefined) counts[e.action]++;
  });
  statAllow.textContent = counts.ALLOW;
  statWarn.textContent  = counts.WARN;
  statBlock.textContent = counts.BLOCK;
}

// ------------------------------------------------------------------
// Load Data
// ------------------------------------------------------------------

function loadData() {
  chrome.storage.local.get(['sx_events', 'sx_enabled', 'sx_backend_url'], (result) => {
    events = result.sx_events || [];
    const enabled = result.sx_enabled !== false;

    toggleEl.checked = enabled;
    updateStatusBar(enabled);
    renderEvents(events);
    updateStats(events);

    // Last payload in audit tab
    if (events.length > 0) {
      lastPayload.textContent = JSON.stringify(events[0], null, 2);
    }

    // Backend URL
    auditBackend.textContent = result.sx_backend_url || 'Not configured';
  });
}

// ------------------------------------------------------------------
// Clear Events
// ------------------------------------------------------------------

clearBtn.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'CLEAR_EVENTS' });
  events = [];
  renderEvents([]);
  updateStats([]);
  lastPayload.textContent = 'No events recorded yet.';
});

// ------------------------------------------------------------------
// Real-time Updates (storage change listener)
// ------------------------------------------------------------------

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.sx_events) {
    events = changes.sx_events.newValue || [];
    renderEvents(events);
    updateStats(events);
    if (events.length > 0) {
      lastPayload.textContent = JSON.stringify(events[0], null, 2);
    }
  }
});

// ------------------------------------------------------------------
// Init
// ------------------------------------------------------------------

loadData();
