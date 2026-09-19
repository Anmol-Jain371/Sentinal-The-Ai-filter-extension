# SENTINELX: Master Architecture & Engineering Specification
## AI-Powered Browser Security & Contextual Data Loss Prevention

**Tagline:** *Detect. Understand. Prevent.*  
**Project Classification:** Browser Security / Contextual DLP / Applied Information Theory / Privacy-Preserving Telemetry

---

# 1. Executive Summary & Vision

**SentinelX** is a privacy-first Chromium browser security extension (Manifest V3) designed to prevent accidental or malicious exposure of proprietary source code, secrets, customer PII, and financial data to external AI platforms (ChatGPT, Claude, Gemini, DeepSeek), unapproved SaaS tools, and web services.

Unlike traditional Data Loss Prevention (DLP) tools that rely on blunt regex and binary blocking, SentinelX operates on a contextual risk paradigm:

$$\text{Exposure Risk Score } (0\text{–}100) = f(\text{Data Sensitivity}, \text{Destination Trust}, \text{Data Volume}, \text{Action Vector}, \text{Workflow Context})$$

### The Foundational Principle:
> **"SentinelX does not simply ask 'Is this data sensitive?' It evaluates whether transmitting this data to this specific destination, in this specific context, is an acceptable security risk under organizational policy."**

---

# 2. Core Architectural Pillars (The 10/10 Security Engineering Model)

SentinelX integrates 5 cutting-edge engineering standards that elevate it from a basic prototype to an enterprise-grade security system:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SENTINELX RUNTIME SHIELD                                  │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│  1. Shannon Entropy Heuristics   │ Detects zero-day credentials & custom API tokens (H ≥ 4.2)│
│  2. Closed Shadow DOM Isolation  │ attachShadow({mode: 'closed'}) protects UI from DOM theft│
│  3. Semantic Smart Redaction     │ Replaces secrets with functional tokens [API_KEY_1]       │
│  4. Verifiable Zero-Knowledge    │ SHA-256 event fingerprinting with 0 bytes of content sent │
│  5. Adversarial Benchmark Matrix │ 7 automated attack vectors tested under < 5ms latency     │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Pillar 1: Shannon Entropy & Heuristic Secret Analysis
- **Problem with Traditional Regex:** Standard tools only catch known prefixes (`AKIA...`, `ghp_...`). Custom database passwords, internal tokens, and SSH keys slip through undetected.
- **SentinelX Solution:** Computes localized **Shannon Entropy**:
  $$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
  Combined with character-set density metrics (Base64, Hexadecimal, Alphanumeric + Special Characters). Any unstructured token with $H(X) \ge 4.2$ and high character density is immediately flagged as a heuristic high-entropy secret.

### Pillar 2: Tamper-Proof UI via Closed Shadow DOM
- **Problem with In-Page Modals:** Host page scripts (or compromised third-party web apps) can inspect injected DOM nodes, hide alerts, or programmatically trigger synthetic clicks on "Continue Anyway". Host CSS also destroys extension styling.
- **SentinelX Solution:** All in-page SentinelX dialogs (HUD, warnings, blocks, redaction pickers) are encapsulated inside a **Closed Shadow DOM** (`element.attachShadow({ mode: 'closed' })`). Host scripts cannot query, read, or manipulate SentinelX security buttons, ensuring complete UI security.

### Pillar 3: Semantic Context-Preserving Masking ("Smart Redact & Paste")
- **Problem with Binary Blocking:** Blocking outright disrupts developer workflow and encourages employees to find workarounds.
- **SentinelX Solution:** 1-Click Smart Redaction parses the payload and replaces sensitive data with structured semantic placeholders:
  - `sk_live_948291839218` $\rightarrow$ `[STRIPE_SECRET_KEY_1]`
  - `sarah.connor@cyberdyne.com` $\rightarrow$ `[CUSTOMER_EMAIL_1]`
  - `postgres://admin:p@ss123@10.0.4.1/prod` $\rightarrow$ `[INTERNAL_DB_URI]`
  The developer can paste the sanitized code/query into ChatGPT/Claude; the AI provides the answer cleanly, and no real credentials leave the browser.

### Pillar 4: Verifiable Zero-Knowledge Telemetry & In-Browser Audit Inspector
- **Problem with Privacy Claims:** "We process locally" is often unverifiable marketing fluff.
- **SentinelX Solution:** 
  1. **Strict Metadata Isolation:** The backend API accepts *only*:
     ```json
     {
       "event_id": "evt_7f8a9b",
       "timestamp": 1726388400000,
       "destination_category": "EXTERNAL_AI",
       "detected_tags": ["HIGH_ENTROPY_CREDENTIAL", "CUSTOMER_EMAIL"],
       "risk_score": 94,
       "action": "BLOCK",
       "content_length": 842,
       "payload_sha256_prefix": "a3f89e21..."
     }
     ```
  2. **Audit Inspector:** The extension popup and HUD include an interactive *"Audit Telemetry"* inspector showing the exact outgoing JSON payload and a byte comparison: `Raw Content: 842 bytes | Sent to Backend: 154 bytes (0 bytes plaintext)`.

### Pillar 5: Automated Benchmark Suite & Adversarial Matrix
- **Scientific Validation:** Includes an automated benchmark runner evaluating 7 real-world evasion vectors:
  1. **Plaintext Secrets:** Known credential signatures.
  2. **Base64 Obfuscation:** Encoded credentials (`QUtJQTEx...`).
  3. **Character Substitution & Leetspeak:** Deliberately spaced or mutated keys (`A-P-I_K-3-Y`).
  4. **Code-Embedded Secrets:** Credentials inside JSON objects, SQL strings, or Python comments.
  5. **Distributed Leakage:** Multi-step or multi-input field leaks.
  6. **Contextual Business Leakage:** Combined harmless phrases revealing confidential projects.
  7. **High-Volume Dumps:** Bulk customer/financial tabular data.
- **Latency Assurance:** Measures and displays execution duration for every inspection, guaranteeing $< 5\text{ms}$ latency on main threads.

---

# 3. Complete System Architecture

```text
                                  USER BROWSER (Chrome / Edge)
                                               │
                                               ▼
                              INTERCEPTED BROWSER EVENT
                     (Paste, Form Submit, Drag-and-Drop, File Upload)
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 SENTINELX CLIENT ENGINE                                     │
│                                                                                             │
│   ┌───────────────────────────┐    ┌──────────────────────────┐    ┌─────────────────────┐ │
│   │    Deterministic Engine   │    │  Shannon Entropy Engine  │    │ Destination Intel   │ │
│   │  (PII, Regex, Code, DB)   │    │  (H ≥ 4.2, Secret Trie)  │    │ (Approved/External) │ │
│   └─────────────┬─────────────┘    └────────────┬─────────────┘    └──────────┬──────────┘ │
│                 │                               │                             │             │
│                 └───────────────────────┬───────┴─────────────────────────────┘             │
│                                         ▼                                                   │
│                             CONTEXTUAL RISK CALCULATOR                                      │
│                                 Score: 0 to 100                                             │
│                                         │                                                   │
│                                         ▼                                                   │
│                              ORGANIZATION POLICY ENGINE                                     │
│                                (ALLOW / WARN / BLOCK)                                       │
│                                         │                                                   │
│                                         ▼                                                   │
│                         CLOSED SHADOW DOM SENTINEL HUD                                      │
│                  [ ALLOW ]   [ REDACT & PASTE ]   [ BLOCK ]                                 │
└─────────────────────────────────────────┬───────────────────────────────────────────────────┘
                                          │
                        Zero-Knowledge Anonymized Telemetry
                        (SHA-256 Signature + Metadata only)
                                          │
                                          ▼
                               FASTAPI TELEMETRY SERVER
                                          │
                                          ▼
                         POSTGRESQL / SQLITE AUDIT STORE
                                          │
                                          ▼
                             SECURITY ADMIN DASHBOARD
               (Real-Time Threat Radar, Policy Config, Risk Trends)
```

---

# 4. Contextual Risk Scoring Formula

The 0–100 score is computed using an explainable multi-factor formula:

$$\text{Risk} = \min\left(100, \; w_s \cdot S + w_d \cdot D + w_v \cdot V + w_a \cdot A + w_c \cdot C\right)$$

Where:
- **$S$ (Data Sensitivity, $0\text{–}100$):**
  - Public/Safe = 0
  - Internal Notes = 25
  - Source Code / Architecture = 60
  - Customer PII / Financial = 85
  - Credentials, Private Keys, High Entropy = 100
- **$D$ (Destination Risk, $0\text{–}100$):**
  - Internal Company Domain (`*.internal.corp`) = 10
  - Approved Enterprise AI (Azure OpenAI with zero-retention agreement) = 35
  - External Public AI (ChatGPT, Claude, Gemini free tiers) = 75
  - Unknown SaaS / Pastebins / Suspicious URLs = 95
- **$V$ (Data Volume Factor, $0\text{–}100$):** Logarithmic scale based on payload character count and record count.
- **$A$ (Action Vector, $0\text{–}100$):** Paste = 70, Form Submit = 60, File Upload = 80.
- **$C$ (Context Factor, $0\text{–}100$):** Developer workspace vs general browsing.

Default weights: $w_s = 0.40, \; w_d = 0.25, \; w_v = 0.15, \; w_a = 0.10, \; w_c = 0.10$.

---

# 5. Project Repository Layout

```text
sentinelx/
├── docs/
│   ├── MASTER_SPECIFICATION.md      # This master document
│   ├── ARCHITECTURE.md              # Deep-dive diagrams & design decisions
│   ├── THREAT_MODEL.md              # Adversarial attack modeling
│   └── PRIVACY_MANIFESTO.md        # Zero-knowledge telemetry proof
│
├── extension/                       # Chrome/Edge Manifest V3 Extension
│   ├── manifest.json
│   ├── background/
│   │   └── service-worker.js        # Rule sync, badge updates, telemetry relay
│   ├── content/
│   │   ├── monitor.js               # Capture-phase paste & input interceptor
│   │   └── shadow-hud.js            # Closed Shadow DOM UI Shield
│   ├── detectors/
│   │   ├── entropy.js               # Shannon Entropy & character density engine
│   │   ├── deterministic.js         # PII, API Keys, Database URIs, Code syntax
│   │   ├── destination.js           # Domain intelligence & trust scoring
│   │   └── redactor.js              # Semantic token replacement engine
│   ├── engine/
│   │   ├── risk-engine.js           # Multi-factor 0-100 risk calculator
│   │   └── policy-engine.js         # Configurable organizational rule evaluator
│   └── popup/
│       ├── popup.html               # Sleek glassmorphism status interface
│       ├── popup.js                 # Audit inspector & quick toggles
│       └── popup.css
│
├── test-harness/                    # Interactive Local Verification Studio
│   ├── index.html                   # Simulated AI Chat, Web Forms & Code Editor
│   ├── benchmark.js                 # 7-Attack Adversarial test runner & latency profiler
│   └── harness.css
│
├── backend/                         # Privacy-Preserving Telemetry & Policy API
│   ├── main.py                      # FastAPI application
│   ├── models.py                    # Pydantic schemas (Metadata only!)
│   ├── database.py                  # SQLite/PostgreSQL telemetry store
│   └── policies.json                # Organization security policies
│
├── dashboard/                       # SOC & Security Admin Dashboard
│   ├── index.html                   # Threat radar & live event stream
│   ├── dashboard.js                 # Analytics, charts, and policy editor
│   └── dashboard.css
│
└── ml/                              # Experimental Sensitivity Classification
    ├── dataset/synthetic_data.csv   # Labeled synthetic corpus
    ├── train.py                     # Scikit-learn / XGBoost comparison
    └── evaluate.py                  # Precision, Recall, F1 & PR-AUC analysis
```

---

# 6. Structured Execution Milestones

### Milestone 1: Core Extension & Tamper-Proof Engine (Day 1 POC)
- Manifest V3 extension with capture-phase paste interception.
- Closed Shadow DOM HUD with ALLOW / WARN / BLOCK / REDACT.
- Shannon Entropy engine ($H \ge 4.2$) + PII & Secrets detector.
- Interactive Test Harness with pre-built test cases and latency profiler.

### Milestone 2: Contextual Risk & Policy Engine
- Destination categorization (Internal, Approved AI, External AI, Suspicious).
- 0–100 Risk Scoring with explainable breakdown.
- Policy evaluator with custom rule definitions.

### Milestone 3: Telemetry Server & SOC Dashboard
- FastAPI endpoint receiving anonymized cryptographic telemetry.
- Real-time Admin Dashboard displaying event timeline, risk graphs, and redaction stats.

### Milestone 4: Machine Learning & Adversarial Evaluation
- 500+ sample synthetic dataset with zero real personal data.
- Comparison metrics: Rules vs Logistic Regression vs Random Forest.
- Automated evaluation across the 7 adversarial attack patterns.
