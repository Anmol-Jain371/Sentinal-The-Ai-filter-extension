# SentinelX DLP — Threat Model (STRIDE Analysis)
**Version:** 2.0 | **Classification:** Internal — Security Architecture  
**Scope:** Chrome Browser Extension + FastAPI Telemetry Backend + SOC Dashboard

---

## 1. Trust Boundary Diagram

```
TB-A: Employee Endpoint
  Chrome (MDM-managed)
    Web Page DOM (untrusted) ──> SentinelX Content Script (capture-phase)
                                          |
                                  Zero-plaintext event
                                          |
                                 Service Worker (MV3, managed policy)

TB-A/TB-B boundary: HTTPS — metadata only. No plaintext content ever crosses.

TB-B: Internal Network
  FastAPI Backend ──> PostgreSQL / SQLite (metadata + SHA-256 only)
  SOC Dashboard (static, authenticated access)
```

---

## 2. Assets Protected

| Asset | Classification |
| :--- | :---: |
| Clipboard content (credentials, PII, IP) | Critical |
| Infrastructure secrets (DB URIs, API keys) | Critical |
| Employee identity in audit trail | High |
| SentinelX policy configuration | High |
| Telemetry metadata in backend DB | Medium |
| SOC dashboard access | Medium |

---

## 3. STRIDE Threat Matrix

### 3.1 Spoofing

| ID | Threat | Component | Mitigation | Risk |
| :--- | :--- | :--- | :--- | :---: |
| S-01 | Spoof extension ID to intercept events | Service Worker | Extension ID is derived from signing key — unforgeable without the private key | LOW |
| S-02 | Malicious page simulates HUD to trick user | Content Script | `attachShadow({ mode: 'closed' })` — page JS gets null; cannot read or simulate shadow root | LOW |
| S-03 | Forged events sent to backend to pollute analytics | Backend API | No ingest auth in dev version; **add X-SentinelX-API-Key header in production** | MEDIUM |
| S-04 | Spoofed `employee_id` in telemetry | Service Worker | `employee_id` from `chrome.storage.managed` (IT-only, GPO-enforced); employee cannot write to managed storage | LOW |

---

### 3.2 Tampering

| ID | Threat | Component | Mitigation | Risk |
| :--- | :--- | :--- | :--- | :---: |
| T-01 | User disables extension to bypass monitoring | Chrome Extension | MDM `ExtensionInstallForcelist` forces install; `ExtensionInstallBlocklist` prevents removal | LOW |
| T-02 | Page JS patches `addEventListener` prototype | Content Script | Extension runs in isolated JS world — page prototype patches do not propagate | LOW |
| T-03 | Page overrides `navigator.clipboard` to bypass detection | Monitor.js | SentinelX intercepts `paste` DOM event (input side), not clipboard write — bypass inapplicable | LOW |
| T-04 | `contenteditable` with custom handlers suppresses paste listener | Monitor.js | Capture-phase listener at document root fires before any element handlers | LOW |
| T-05 | Managed policy file tampered locally | Managed Policy | `chrome.storage.managed` is read-only from extension code | LOW |
| T-06 | Backend DB records deleted or modified by insider | Database | **Use INSERT-only PostgreSQL role for telemetry writer** | MEDIUM |

---

### 3.3 Repudiation

| ID | Threat | Component | Mitigation | Risk |
| :--- | :--- | :--- | :--- | :---: |
| R-01 | Employee denies a specific paste event | Backend | Immutable `event_id`, `timestamp`, `employee_id`, `device_id`, `payload_sha256_prefix` in every record | LOW |
| R-02 | SOC analyst denies viewing/exporting report | Dashboard | No dashboard access audit log in current version — **add in production** | MEDIUM |
| R-03 | Operator denies clearing event log | Backend | No immutable log for admin operations — **add audit trail for DELETE /events** | MEDIUM |

---

### 3.4 Information Disclosure

| ID | Threat | Component | Mitigation | Risk |
| :--- | :--- | :--- | :--- | :---: |
| I-01 | Raw clipboard content leaked to backend | Content Script | Core invariant: only SHA-256 prefix (16 hex chars) + tags + risk score transmitted. Zero plaintext schema. | LOW |
| I-02 | Employee email in SIEM webhook exposed | Webhook Relay | By design — SIEM endpoint must be internal and authenticated | LOW |
| I-03 | SQLite file readable by any local process | Database (dev) | Dev only. **Production requires PostgreSQL with RBAC + disk encryption** | MEDIUM |
| I-04 | Dashboard exposed without authentication | Dashboard | **Critical: deploy behind corporate SSO / VPN in production** | HIGH |
| I-05 | Extension source reverse-engineered to craft evasion | Extension | Accepted risk: deterministic rules are not the sole detection layer; entropy + semantic NLP are not easily evaded | LOW |

---

### 3.5 Denial of Service

| ID | Threat | Component | Mitigation | Risk |
| :--- | :--- | :--- | :--- | :---: |
| D-01 | Flood `/events` to exhaust backend | Backend API | No rate limiting in dev — **add 100 req/min per IP in production** | MEDIUM |
| D-02 | HUD blocks all paste, making browser unusable | Content Script | HUD shown only for risk >= 40; ALLOW decisions pass in < 2ms silently | LOW |
| D-03 | Repeated `/train-eval` floods CPU | Backend API | No throttle — **restrict to admin role, 1 req/min** | MEDIUM |

---

### 3.6 Elevation of Privilege

| ID | Threat | Component | Mitigation | Risk |
| :--- | :--- | :--- | :--- | :---: |
| E-01 | Extension gains overbroad tab access | Extension Manifest | Uses `activeTab` only + `clipboardRead`; no `tabs` or `<all_urls>` | LOW |
| E-02 | Leaked API key used to clear event logs | Backend | `DELETE /events` needs separate admin key — **enforce in production** | MEDIUM |
| E-03 | Malicious extension update via Chrome Web Store | Extension | Enterprise: pin CRX via GPO, disable auto-update from store | LOW |

---

## 4. Multi-Browser Bypass — Formal Position

**Threat:** Employee opens Firefox or Edge to avoid Chrome-exclusive DLP.  
**Severity:** Medium (insider threat, not external attacker)

**Defense-in-Depth Response:**

```
Layer 1 — Network (Zscaler / Prisma Access / Netskope)
  Browser-agnostic DNS/proxy blocking of unapproved destinations

Layer 2 — Endpoint MDM (Intune / Jamf)
  Application allowlist: only Chrome permitted; Firefox/Edge blocked via GPO

Layer 3 — Browser (SentinelX)  <── this system
  Real-time interception within managed Chrome, sub-5ms, zero-plaintext

Layer 4 — SIEM (Splunk / Microsoft Sentinel)
  Anomalous egress alerting even if Layers 1-3 bypassed
```

SentinelX is Layer 3 of a documented defense-in-depth architecture.  
The multi-browser gap is a **known, formally accepted, and architecturally addressed residual risk.**

---

## 5. Residual Risk Summary

| Level | Count | Key Items |
| :--- | :---: | :--- |
| HIGH | 1 | I-04 (dashboard unauthenticated) |
| MEDIUM | 7 | S-03, T-06, R-02, R-03, I-03, D-01/D-03, E-02 |
| LOW | 14 | All others |

### Production Deployment Checklist

- [ ] Dashboard behind SSO / VPN — eliminates I-04
- [ ] PostgreSQL with RBAC — eliminates I-03, mitigates T-06
- [ ] `X-SentinelX-API-Key` on `/events` ingest — mitigates S-03
- [ ] INSERT-only DB role for telemetry writer — mitigates T-06
- [ ] Rate limiting on `/events` (100/min) and `/train-eval` (1/min) — mitigates D-01/D-03
- [ ] Admin-only `DELETE /events` — mitigates E-02
- [ ] Dashboard access audit log — mitigates R-02/R-03

---
*STRIDE methodology: Shostack (2014). DREAD scoring and attack tree diagrams available on request.*
