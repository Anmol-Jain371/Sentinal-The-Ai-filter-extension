# 🛡️ SentinelX — The Real-Time Privacy-Preserving AI & SaaS Browser DLP

<p align="center">
  <img src="docs/assets/demo_poster.png" alt="SentinelX Banner" width="100%" style="border-radius: 12px; box-shadow: 0 12px 40px rgba(0,0,0,0.4);" />
</p>

<p align="center">
  <strong>Client-Side Data Loss Prevention (DLP) at the Browser Event Boundary with Zero Plaintext Egress.</strong>
  <br>
  <em>Intercepts, analyzes, and neutralizes sensitive data leaks to LLMs (ChatGPT, Claude, DeepSeek) and SaaS endpoints in under 2ms.</em>
</p>

<p align="center">
  <a href="#-interactive-demo--video-showcase"><img src="https://img.shields.io/badge/Demo-Video%20Available-blueviolet?style=for-the-badge&logo=youtube" alt="Demo Video"></a>
  <a href="https://developer.chrome.com/docs/extensions/mv3/intro/"><img src="https://img.shields.io/badge/Manifest-V3%20Ready-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Manifest V3"></a>
  <a href="https://www.microsoft.com/edge"><img src="https://img.shields.io/badge/Browser-Chrome%20%7C%20Edge-0078D7?style=for-the-badge&logo=microsoftedge&logoColor=white" alt="Edge & Chrome"></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/Backend-FastAPI%20%2B%20Python-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"></a>
  <a href="#-ml-semantic-classifier-performance"><img src="https://img.shields.io/badge/ML%20Accuracy-97.0%25-brightgreen?style=for-the-badge&logo=scikitlearn&logoColor=white" alt="Accuracy 97%"></a>
  <a href="#-the-zero-plaintext-invariant"><img src="https://img.shields.io/badge/Privacy-Zero--Plaintext%20Invariant-success?style=for-the-badge&logo=shield" alt="Zero Plaintext"></a>
</p>

---

## 🎬 Interactive Demo & Video Showcase

Experience how SentinelX catches credentials and sensitive prompts the millisecond they are pasted, quarantining the payload before the DOM or remote LLMs can read it:

### 🎥 Watch the Technical Demonstration

https://github.com/user-attachments/assets/Anmol-Jain371-Sentinal-demo

<p align="center">
  <video src="SentinelX_Full_Technical_Title.mp4" width="100%" controls autoplay loop muted playsinline style="border-radius: 10px; max-height: 520px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
    <source src="SentinelX_Full_Technical_Title.mp4" type="video/mp4">
    Your browser does not support embedded HTML5 video. Click below to view or download.
  </video>
</p>

<p align="center">
  <a href="SentinelX_Full_Technical_Title.mp4">
    <img src="docs/assets/sentinelx_demo.gif" alt="SentinelX Real-Time Interception Live Demo" width="100%" style="border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); box-shadow: 0 8px 32px rgba(0,0,0,0.6);" />
  </a>
  <br>
  <em>▶️ <strong>Interactive Demo Reel</strong> (Full high-definition MP4 file available at: <a href="SentinelX_Full_Technical_Title.mp4"><code>SentinelX_Full_Technical_Title.mp4</code></a>)</em>
</p>

---

## ⚡ Why SentinelX? (The DLP Paradox)

```
Traditional Cloud Proxy DLP:
[Employee Endpoint] ──(Raw Plaintext over Internet)──> [Proxy / Cloud Vendor] ──> [Inspection] ──> [LLM]
⚠️ Flaw: You leak confidential corporate IP and keys to your security vendor to stop leaks.

SentinelX In-Memory Browser DLP:
[Employee Endpoint] ──(Pre-DOM Capture <2ms)──> [Local Engine: Regex + Entropy + ML] ──> [Decision HUD]
                                                           │
                                        (Zero Plaintext: SHA-256 + Risk Score only)
                                                           ▼
                                               [Internal SOC Dashboard]
✅ Invariant: 100% client-side inspection. Zero bytes of company plaintext ever leave the device.
```

Modern enterprises face an exponential security liability: employees routinely paste proprietary code, API tokens, database URIs, customer PII, and M&A documents into public generative AI tools (ChatGPT, Claude, Gemini, DeepSeek) and unsanctioned SaaS tools.

SentinelX stops this at the physical browser boundary:
1. **Zero-Plaintext Telemetry**: Only anonymized metadata (SHA-256 prefixes, rule tags, risk scores) leaves the machine.
2. **Pre-DOM Event Interception (`capture: true`)**: Intercepts events in the C++ capture phase before React, Draft.js, or Monaco Editor state can register the input.
3. **Sub-2ms Evaluation**: Blazing fast deterministic regex heuristics + Shannon entropy + TF-IDF ML classifier.
4. **Closed Shadow-DOM Isolation**: Tamper-proof UI rendered inside `#shadow-root (closed)` that host-page scripts cannot inspect or bypass.
5. **Smart Redact & Paste**: Generates context-aware, synthetic placeholder tokens (`[OPENAI_API_KEY_1]`, `[AWS_ACCESS_KEY_1]`) so developers can prompt safely without breaking formatting.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph Browser Endpoint [Untrusted Browser Context]
        A[User Pastes / Types / Drags Data] -->|Capture Phase Hook| B(SentinelX Event Quarantine)
        B --> C{Local Detection Pipeline}
        
        subgraph Detection Pipeline [< 2ms Execution]
            C --> D[Deterministic Engine: 25+ Regex Patterns]
            C --> E[Shannon Entropy: Zero-Day Secrets]
            C --> F[Semantic Classifier: TF-IDF + Logistic Regression]
            C --> G[Destination Risk: Domain Reputation]
        end
        
        D & E & F & G --> H[Risk Scoring Engine: Multi-Factor Formula]
        H --> I{Threshold Decision}
        
        I -->|Risk < 35| J[ALLOW: Seamless Passthrough]
        I -->|35 <= Risk < 65| K[WARN: Self-Service Justification Dialog]
        I -->|Risk >= 65| L[BLOCK: Hard Quarantine Isolation]
        
        K & L --> M[Closed Shadow-DOM HUD]
        M -->|User Click| N[Smart Redact & Paste Engine]
        N -->|Inject Safe Redacted Text| O[Target Input Field]
    end
    
    subgraph Local Telemetry Isolation [Zero-Plaintext Guarantee]
        H -.->|SHA-256 Prefix + Risk Score + Tags| P[MV3 Service Worker]
        P -.->|Encrypted HTTPS Header| Q[FastAPI SOC Gateway]
    end
    
    subgraph Enterprise SOC Infrastructure [Secure Enterprise Network]
        Q --> R[(PostgreSQL / SQLite Audit Store)]
        Q --> S[SOC Telemetry Dashboard]
        Q --> T[SIEM / Webhook Forwarder: Slack / Teams]
    end

    classDef secure fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef warning fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#fef3c7;
    classDef danger fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fee2e2;
    classDef neutral fill:#1e293b,stroke:#64748b,stroke-width:1px,color:#f1f5f9;
    
    class J secure;
    class K warning;
    class L danger;
    class C,D,E,F,G,H,M,N neutral;
```

---

## 🧮 Multi-Factor Risk Scoring Equation

SentinelX calculates an adaptive risk score between `0` and `100` dynamically computed per interaction:

$$\text{Risk} = \min\left(100, \; w_s S + w_d D + w_v V + w_a A + w_c C\right)$$

| Factor | Notation | Weight ($w$) | Description |
| :--- | :---: | :---: | :--- |
| **Sensitivity** | $S$ | $0.40$ | Severity weight of detected pattern (Credentials = 100, PII = 80, Strategic = 70) |
| **Destination** | $D$ | $0.25$ | Egress target risk rating (Public LLMs = 90, Unsanctioned SaaS = 70, Internal Git = 10) |
| **Volume** | $V$ | $0.15$ | Payload length and density of sensitive matches |
| **Anomaly** | $A$ | $0.10$ | Shannon entropy anomaly score ($H \ge 4.5$ indicates raw cryptographic keys) |
| **Compliance** | $C$ | $0.10$ | Strictness multiplier based on regulatory context (GDPR, HIPAA, PCI-DSS) |

### Action Enforcements:
* **`🟢 ALLOW` (Risk < 35)**: Action proceeds without employee interruption.
* **`🟡 WARN` (Risk 35 – 64)**: Shadow-DOM HUD appears with risk summary, requiring one-click manager justification or confirmation.
* **`🔴 BLOCK` (Risk $\ge$ 65)**: Action blocked instantly. User can either cancel or execute **Smart Redact & Paste**.

---

## 🔍 Supported Sensitive Data Detectors

SentinelX comes equipped with built-in zero-latency detectors across all major credential and data classifications:

| Category | Detectors & Signatures | Action Default |
| :--- | :--- | :---: |
| **AI Providers** | OpenAI (`sk-proj-`, `sk-`), Anthropic (`sk-ant-`), HuggingFace (`hf_`), Cohere | `🔴 BLOCK` |
| **Cloud Providers** | AWS Access Key (`AKIA`/`ASIA`), AWS Secret Keys, GCP Service Account JSON, Azure Connection Strings | `🔴 BLOCK` |
| **Developer & SaaS** | GitHub PAT (`ghp_`, `gho_`), GitLab Tokens (`glpat-`), Slack Bot/User Tokens (`xoxb-`, `xoxp-`), Stripe Live Keys (`sk_live_`), SendGrid, Twilio, npm tokens | `🔴 BLOCK` |
| **Database URIs** | PostgreSQL, MySQL, MongoDB, Redis, Kafka, Oracle connection strings with embedded passwords | `🔴 BLOCK` |
| **Financial** | Credit Cards (Visa, Mastercard, Amex with Luhn checksum validation), IBAN numbers | `🔴 BLOCK` |
| **PII** | US Social Security Numbers (SSN), RFC 5322 Email addresses, E.164 Phone numbers | `🟡 WARN` |
| **Cryptographic Keys** | RSA/OpenSSH Private Key headers (`BEGIN RSA PRIVATE KEY`, `BEGIN OPENSSH`), High-Entropy Base64 blobs | `🔴 BLOCK` |
| **Corporate IP** | Internal source code heuristics, M&A confidential tags, Salary/Equity distribution records | `🟡 WARN` |

---

## 🤖 ML Semantic Classifier Performance

For ambiguous payloads not matching static regular expressions, SentinelX includes a specialized local TF-IDF + Logistic Regression classifier trained on synthetic and real-world sensitive corporate disclosures:

```
======================================================================
              SENTINELX DLP ML EVALUATION METRICS REPORT
======================================================================
  Dataset Size:            165 samples (132 train / 33 test)
  Evaluation Protocol:     Stratified 80/20 train/test split + 5-fold CV
  Test Accuracy:           97.0%
  Precision:               1.000 (Zero False Positives on benign controls)
  Recall:                  0.923
  F1 Score:                0.960
  5-Fold CV F1:            0.946 ± 0.065
  Training Latency:        ~174 ms
  Inference Latency:       < 1.8 ms per payload
  Model Checkpoint:        backend/model_artifacts/sentinelx_dlp_model.pkl
======================================================================
```

---

## 🚀 Quick Start & Installation

### 1. Load the Browser Extension (Chrome or Microsoft Edge)

SentinelX works seamlessly in **Google Chrome**, **Microsoft Edge**, **Brave**, and any Chromium-based browser:

1. Open your browser's extension manager:
   - **Microsoft Edge**: Navigate to `edge://extensions/`
   - **Google Chrome**: Navigate to `chrome://extensions/`
2. Toggle **Developer mode** on (top right or bottom left toggle).
3. Click **Load unpacked**.
4. Select the `extension/` directory inside this repository.
5. The **SentinelX DLP** icon will appear in your toolbar!

> **💡 Note**: Whenever code changes occur, simply click the **↻ Reload** button on the extension card in `edge://extensions/` or `chrome://extensions/`.

---

### 2. Launch the Test Workbench

We provide a built-in interactive workbench to test real-world scenarios:

1. Open `test-harness/index.html` in your browser.
2. Click any of the pre-loaded test scenario cards:
   - **OpenAI Project Key** (`sk-proj-...`) $\rightarrow$ triggers **BLOCK**
   - **AWS Cloud Key** (`AKIA...`) $\rightarrow$ triggers **BLOCK**
   - **Customer Credit Card** $\rightarrow$ triggers **BLOCK**
   - **Benign Code Snippet** $\rightarrow$ triggers **ALLOW**
3. Paste into the simulation fields or into **ChatGPT** / **Claude** to watch the real-time closed Shadow-DOM HUD appear!
4. Click **Smart Redact & Paste** to verify safe placeholder replacement.

---

### 3. Start the Backend & SOC Dashboard

SentinelX includes a full FastAPI telemetry server and SOC administration dashboard:

```bash
# Clone repository
git clone https://github.com/Anmol-Jain371/Sentinal-The-Ai-filter-extension.git
cd Sentinal-The-Ai-filter-extension

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Run the backend server
uvicorn backend.main:app --reload --port 8000
```

* **SOC Telemetry Dashboard**: Open [`http://localhost:8000/dashboard`](http://localhost:8000/dashboard)
* **Interactive API Documentation**: Open [`http://localhost:8000/api/docs`](http://localhost:8000/api/docs)
* **Default Admin Credentials**:
  - **Password**: `sentinelx-admin-2024` (Configurable via `ADMIN_PASSWORD`)
  - **Extension API Key**: `sx-dev-api-key-change-in-production`

---

### 4. Production Deployment with Docker Compose

Deploy the complete multi-container stack with PostgreSQL, FastAPI, and the SOC Console in one command:

```bash
cp .env.example .env
docker compose up -d --build
```

---

## 🏢 Enterprise MDM & Fleet Deployment

SentinelX supports automated zero-touch push deployment across enterprise fleets:

* **Windows Active Directory / GPO**:
  Deploy via Group Policy using `enterprise/sentinelx_gpo_policy.reg`. Enforces mandatory extension installation via Chrome/Edge `ExtensionInstallForcelist`.
* **Microsoft Intune MDM**:
  Import `enterprise/sentinelx_intune_policy.xml` into your Microsoft Endpoint Manager / Intune portal for centralized device configuration.
* **Managed Configuration Schema**:
  Supports `extension/managed_schema.json` to push locked corporate policies (API endpoint, SIEM webhooks, custom prohibited domains) directly via MDM without user alteration.

---

## 🔒 Security & Threat Model (STRIDE)

SentinelX's security boundary is architected according to the STRIDE threat model:

* **Spoofing**: Identity injection via `chrome.storage.managed` binds events cryptographically to enrolled employee IDs and hardware UUIDs.
* **Tampering**: UI dialog runs strictly in an isolated closed Shadow-DOM (`mode: "closed"`). Host-page DOM manipulation cannot alter warning dialogs.
* **Repudiation**: Append-only event store with high-entropy event IDs, cryptographic timestamps, and employee signatures.
* **Information Disclosure**: **Zero-Plaintext Invariant**. Raw sensitive strings are never sent to backend or third-party servers. Only truncated SHA-256 prefixes and risk scores are retained.
* **Denial of Service**: Pre-DOM interception execution bounded to $<2\text{ms}$; asynchronous background telemetry dispatch never blocks UI threads.
* **Elevation of Privilege**: JWT-authenticated SOC endpoints with strict role-based access control (RBAC).

For the full 22-threat analysis, read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## 📂 Repository Structure

```
Sentinal-The-Ai-filter-extension/
├── extension/                       # Manifest V3 Browser Extension (Chrome / Edge)
│   ├── manifest.json                # MV3 extension manifest
│   ├── background/                  # Service worker (telemetry dispatch, identity injection)
│   │   └── service-worker.js
│   ├── content/                     # Content scripts (Pre-DOM interceptor & HUD)
│   │   ├── monitor.js               # Capture-phase paste/keydown/drag listener
│   │   └── shadow-hud.js            # Closed Shadow-DOM security dialog
│   ├── detectors/                   # Client-side detection engines (<2ms)
│   │   ├── deterministic.js         # 25+ regular expression pattern extractors
│   │   ├── entropy.js               # Shannon entropy calculations (H >= 4.5)
│   │   ├── redactor.js              # Smart Redact & synthetic token generator
│   │   ├── classifier.js            # Heuristic text classifier
│   │   ├── semantic.js              # Local vocabulary analyzer
│   │   └── destination.js           # Domain risk scoring (LLMs vs. SaaS vs. Internal)
│   ├── engine/                      # Policy & multi-factor risk computation
│   │   ├── policy-engine.js         # Enterprise policy evaluator
│   │   └── risk-engine.js           # Mathematical risk equation implementation
│   ├── icons/                       # Extension branding & toolbar icons
│   └── popup/                       # Extension status popup interface
├── backend/                         # FastAPI Telemetry & SOC Gateway Server
│   ├── main.py                      # REST API endpoints, dual DB support (PostgreSQL/SQLite)
│   ├── auth.py                      # JWT authentication & API key authorization
│   ├── train_eval.py                # ML training pipeline (TF-IDF + Logistic Regression)
│   ├── requirements.txt             # Python runtime dependencies
│   ├── model_artifacts/             # Serialized model checkpoint & benchmark metrics
│   └── tests/                       # Automated pytest suite (29 tests)
├── dashboard/                       # SOC Administration Console
│   ├── index.html                   # Threat intelligence, real-time events, analytics
│   ├── login.html                   # SOC authentication gate
│   ├── dashboard.css                # Glassmorphism dark security UI
│   └── dashboard.js                 # Real-time event streaming & charts
├── enterprise/                      # Fleet Deployment Templates
│   ├── sentinelx_gpo_policy.reg     # Active Directory Group Policy deployment
│   └── sentinelx_intune_policy.xml  # Microsoft Intune MDM deployment
├── test-harness/                    # Interactive Workbench & Testing Environment
│   ├── index.html                   # DLP test harness with pre-loaded scenarios
│   ├── harness.css                  # Modern interactive workbench styling
│   └── benchmark.js                 # Live detection latency and accuracy runner
├── docs/                            # Deep Technical Documentation
│   ├── assets/                      # Video poster frames & animated demo preview
│   ├── MASTER_SPECIFICATION.md      # Comprehensive technical architectural spec
│   └── THREAT_MODEL.md              # 22 STRIDE threat analysis & mitigations
├── SentinelX_Full_Technical_Title.mp4 # Full 1080p Technical Video Demonstration
├── Dockerfile                       # Production container definition
├── docker-compose.yml               # Multi-container orchestration (FastAPI + Postgres)
├── .env.example                     # Environment template (secrets omitted)
└── .gitignore                       # Strict ignore rules for .env, secrets, and caches
```

---

## 🛠️ Configuration & Environment Variables

SentinelX is designed around secure defaults. For production deployments, copy `.env.example` to `.env`:

| Variable | Description | Default (Dev) | Production Recommendation |
| :--- | :--- | :--- | :--- |
| `ADMIN_PASSWORD` | SOC dashboard admin password | `sentinelx-admin-2024` | Generate a 32+ character random secret |
| `SENTINELX_API_KEY` | Ingest API key used by extension | `sx-dev-api-key-change-in-production` | High-entropy random alphanumeric token |
| `JWT_SECRET` | Secret key used to sign SOC JWT tokens | Built-in dev secret | 256-bit cryptographically secure string |
| `DATABASE_URL` | PostgreSQL connection string | `sqlite:///./backend/sentinelx.db` | `postgresql://user:pass@host:5432/sentinelx` |
| `SENTINELX_SIEM_WEBHOOK` | SIEM, Slack, or Teams alerting webhook | `""` (Disabled) | Your corporate SIEM ingestion endpoint |

---

## 🤝 Contributing

Contributions to expand detector coverage, improve ML classifications, and enhance enterprise integrations are welcome!

1. Fork the Project: `git checkout -b feature/NewDetector`
2. Commit your Changes: `git commit -m 'Add support for Custom Internal Secrets'`
3. Push to the Branch: `git push origin feature/NewDetector`
4. Open a Pull Request

---

## 📜 License & Acknowledgments

* **Author**: [Anmol Jain](https://github.com/Anmol-Jain371)
* **Repository**: [Anmol-Jain371/Sentinal-The-Ai-filter-extension](https://github.com/Anmol-Jain371/Sentinal-The-Ai-filter-extension)
* **License**: Distributed under the MIT License. See `LICENSE` for more details.

<p align="center">
  <sub>Engineered with precision for the modern AI-enabled enterprise. Keep your sensitive data where it belongs.</sub>
</p>
