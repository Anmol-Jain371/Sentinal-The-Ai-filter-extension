/**
 * SentinelX — Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 *   1. Extension badge updates (+ / ! / X)
 *   2. Telemetry event relay to backend (zero-plaintext)
 *   3. Two-way dynamic policy synchronization with backend
 *   4. Local event log (chrome.storage ring buffer) for popup display
 *   5. Extension lifecycle management
 */

'use strict';

const BADGE_COLORS = {
  ALLOW: '#00E5A0',
  WARN:  '#F5A623',
  BLOCK: '#FF3D5A',
  IDLE:  '#00C2FF',
};

const DEFAULT_BACKEND_URL = 'http://localhost:8000';
const MAX_LOCAL_EVENTS = 100;

// In-memory identity cache — populated from chrome.storage.managed on startup
let _identityCache = { employee_id: null, device_id: null, browser_fingerprint: null };

async function loadIdentityCache() {
  try {
    await new Promise(resolve => {
      chrome.storage.managed.get(['employee_id', 'device_id'], (managed) => {
        if (!chrome.runtime.lastError && managed) {
          _identityCache.employee_id = managed.employee_id || null;
          _identityCache.device_id   = managed.device_id   || null;
        }
        resolve();
      });
    });
    // Also try local storage fallback (set by IT via extension options page)
    const local = await chrome.storage.local.get(['sx_employee_id', 'sx_device_id']);
    if (!_identityCache.employee_id && local.sx_employee_id) _identityCache.employee_id = local.sx_employee_id;
    if (!_identityCache.device_id   && local.sx_device_id)   _identityCache.device_id   = local.sx_device_id;
    // Browser fingerprint: non-PII browser+OS string
    _identityCache.browser_fingerprint = navigator.userAgent.substring(0, 80);
  } catch (e) {
    // Managed storage unavailable in non-enterprise environments — silently skip
  }
}

// ------------------------------------------------------------------
// Policy Synchronization (Backend -> Extension)
// ------------------------------------------------------------------

async function syncPoliciesFromBackend() {
  try {
    const result = await chrome.storage.local.get(['sx_backend_url']);
    const backendUrl = result.sx_backend_url || DEFAULT_BACKEND_URL;

    const res = await fetch(`${backendUrl}/policies`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });

    if (!res.ok) return;
    const data = await res.json();
    if (data && Array.isArray(data.policies)) {
      await chrome.storage.local.set({ customPolicies: data.policies });
      console.info(`[SentinelX SW] Synchronized ${data.policies.length} dynamic policies from backend.`);
    }
  } catch (e) {
    // Backend offline or unreachable — continue with built-in policies
  }
}

// ------------------------------------------------------------------
// Managed Policy Synchronization (Google Workspace / Intune / GPO)
// ------------------------------------------------------------------

async function syncManagedPolicies() {
  if (!chrome.storage || !chrome.storage.managed) return;
  try {
    chrome.storage.managed.get(null, async (managed) => {
      if (chrome.runtime.lastError || !managed || Object.keys(managed).length === 0) return;
      console.info('[SentinelX SW] Managed Enterprise policies loaded:', Object.keys(managed));
      await chrome.storage.local.set({
        managedPolicies: managed,
        sx_backend_url: managed.telemetryBackendUrl || DEFAULT_BACKEND_URL,
        strictDLP: managed.enforceStrictDLP !== false,
        // Cache managed config for content script injection
        sx_managed_config: {
          shannonEntropyThreshold: managed.shannonEntropyThreshold || 4.2,
          approvedAIDomains: managed.approvedAIDomains || [],
          restrictedDestinations: managed.restrictedDestinations || [],
          auditModeOnly: managed.auditModeOnly || false,
        },
      });
    });
  } catch (err) {
    // Managed storage not supported or unconfigured in non-managed environments
  }
}

if (chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'managed') {
      syncManagedPolicies();
    }
  });
}

// ------------------------------------------------------------------
// Message Handler
// ------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  switch (message.type) {

    // ── Badge Update ─────────────────────────────────────────────
    case 'UPDATE_BADGE': {
      const { decision } = message;
      const color = BADGE_COLORS[decision] || BADGE_COLORS.IDLE;
      const text  = { ALLOW: '+', WARN: '!', BLOCK: 'X' }[decision] || '';

      chrome.action.setBadgeBackgroundColor({ color });
      chrome.action.setBadgeText({ text });

      // Auto-clear badge after 4 seconds
      setTimeout(() => chrome.action.setBadgeText({ text: '' }), 4000);
      break;
    }

    // ── Security Event (from content script) ─────────────────────
    case 'SENTINEL_EVENT': {
      const event = message.payload;

      // Store event locally for popup display
      storeEventLocally(event);

      // Relay to backend (fire-and-forget, zero plaintext)
      relayToBackend(event);

      sendResponse({ ok: true });
      break;
    }

    // ── Get Recent Events (for popup) ────────────────────────────
    case 'GET_EVENTS': {
      chrome.storage.local.get(['sx_events'], (result) => {
        sendResponse({ events: result.sx_events || [] });
      });
      return true; // async response
    }

    // ── Clear Events ─────────────────────────────────────────────
    case 'CLEAR_EVENTS': {
      chrome.storage.local.set({ sx_events: [] });
      sendResponse({ ok: true });
      break;
    }

    // ── Trigger Policy Sync ──────────────────────────────────────
    case 'SYNC_POLICIES': {
      syncPoliciesFromBackend().then(() => sendResponse({ ok: true }));
      return true;
    }
  }
});

// ------------------------------------------------------------------
// Local Storage (Ring Buffer)
// ------------------------------------------------------------------

async function storeEventLocally(event) {
  try {
    const result = await chrome.storage.local.get(['sx_events']);
    const events = result.sx_events || [];
    events.unshift(event); // newest first
    if (events.length > MAX_LOCAL_EVENTS) {
      events.pop(); // maintain ring buffer size
    }
    await chrome.storage.local.set({ sx_events: events });
  } catch (e) {
    console.warn('[SentinelX SW] Failed to store event locally:', e);
  }
}

// ------------------------------------------------------------------
// Backend Telemetry Relay
// ------------------------------------------------------------------

async function relayToBackend(event) {
  try {
    const result = await chrome.storage.local.get(['sx_backend_url', 'sx_enabled', 'sx_api_key']);
    const backendUrl = result.sx_backend_url || DEFAULT_BACKEND_URL;
    const enabled    = result.sx_enabled !== false;
    const apiKey     = result.sx_api_key || '';

    if (!enabled) return;

    // Inject identity from managed enterprise policy cache
    const enrichedEvent = {
      ...event,
      employee_id:         _identityCache.employee_id,
      device_id:           _identityCache.device_id,
      browser_fingerprint: _identityCache.browser_fingerprint,
    };

    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) headers['X-SentinelX-API-Key'] = apiKey;

    await fetch(`${backendUrl}/events`, {
      method: 'POST',
      headers,
      body: JSON.stringify(enrichedEvent),
    });
  } catch (e) {
    // Backend offline — ignore silently
  }
}

// ------------------------------------------------------------------
// Lifecycle & Alarms
// ------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(({ reason }) => {
  chrome.storage.local.set({
    sx_enabled: true,
    sx_events: [],
    sx_backend_url: DEFAULT_BACKEND_URL,
    customPolicies: [],
  });

  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.IDLE });
  chrome.action.setBadgeText({ text: '' });

  syncManagedPolicies();
  syncPoliciesFromBackend();
  loadIdentityCache();

  if (reason === 'install') {
    console.info('[SentinelX] Extension installed. Shield is active.');
  }
});

chrome.runtime.onStartup.addListener(() => {
  syncManagedPolicies();
  syncPoliciesFromBackend();
  loadIdentityCache();
});
