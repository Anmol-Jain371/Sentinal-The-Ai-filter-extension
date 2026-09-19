/**
 * SentinelX — Deterministic Detection Engine
 *
 * Categorizes sensitive data using precise regex patterns and structural
 * heuristics. Covers: PII, API Keys, Cloud Credentials, Database URIs,
 * Private Keys, Source Code indicators, Financial data.
 *
 * Each detector returns: { detected: boolean, category: string, sensitivity: number (0–100), tags: string[] }
 */

'use strict';

window.SentinelXDeterministic = (() => {

  // ------------------------------------------------------------------
  // Detection Pattern Library

  //
  // PURPOSE: Detect data that should NOT leave the user's browser and
  // go to an untrusted destination (AI chatbots, unknown SaaS, external APIs).
  //
  // WHAT WE CATCH (High Recall targets):
  //   - Cloud credentials: AWS, GCP, Azure, GitHub, GitLab, Bitbucket
  //   - AI provider keys: OpenAI, Anthropic, HuggingFace, Cohere
  //   - Payment credentials: Stripe, PayPal, Square
  //   - Communication tokens: Slack, Twilio, SendGrid, Mailgun
  //   - Auth tokens: JWT, OAuth, session tokens
  //   - Infrastructure: DB connection strings, SSH keys, PEM certs
  //   - PII: Email, Phone, Credit Card, SSN, IBAN, Passport
  //   - Config files: .env files, config.yaml with secrets
  //   - Bulk data: CSV dumps with PII columns
  //
  // WHAT WE DO NOT CATCH (to avoid false positives):
  //   - Normal English prose / chat messages
  //   - Code snippets without embedded secrets
  //   - Public URLs without credentials
  //   - Regular form fills (login pages) — those are intentional
  //   - Simple numbers, dates, short text
  // ------------------------------------------------------------------

  const PATTERNS = {

    // ════════════════════════════════════════════════════════════════
    // CLOUD CREDENTIALS
    // ════════════════════════════════════════════════════════════════

    AWS_ACCESS_KEY: {
      regex: /\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'AWS Access Key',
      tags: ['AWS', 'CREDENTIAL', 'CLOUD'],
    },
    AWS_SECRET_KEY: {
      // Catches: aws_secret_access_key = "wJalr..." OR export VAR=wJalr...
      regex: /(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+]{40})["']?/gi,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'AWS Secret Access Key',
      tags: ['AWS', 'CREDENTIAL', 'CLOUD', 'SECRET'],
    },
    GCP_API_KEY: {
      regex: /AIza[0-9A-Za-z\-_]{35}/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'Google Cloud API Key',
      tags: ['GCP', 'CREDENTIAL', 'API_KEY'],
    },
    AZURE_STORAGE_KEY: {
      // Azure storage account key: 88-char base64 ending in ==
      regex: /(?:AccountKey|AZURE_STORAGE_KEY|storage_key)\s*[:=]\s*["']?([A-Za-z0-9+/]{86}==)["']?/gi,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'Azure Storage Account Key',
      tags: ['AZURE', 'CREDENTIAL', 'CLOUD'],
    },

    // ════════════════════════════════════════════════════════════════
    // AI PROVIDER KEYS  (biggest miss for developers!)
    // ════════════════════════════════════════════════════════════════

    OPENAI_KEY: {
      // OpenAI format: sk- followed by 48+ alphanumeric chars
      // Also catches project keys: sk-proj-...
      regex: /\bsk-(?:proj-)?[A-Za-z0-9\-_]{40,}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'OpenAI API Key',
      tags: ['OPENAI', 'CREDENTIAL', 'AI_KEY', 'API_KEY'],
    },
    ANTHROPIC_KEY: {
      // Anthropic Claude: sk-ant-api03-...
      regex: /\bsk-ant-(?:api\d+-)?[A-Za-z0-9\-_]{40,}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'Anthropic / Claude API Key',
      tags: ['ANTHROPIC', 'CREDENTIAL', 'AI_KEY', 'API_KEY'],
    },
    HUGGINGFACE_TOKEN: {
      // HuggingFace: hf_... (typically 37 chars)
      regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 95,
      label: 'HuggingFace API Token',
      tags: ['HUGGINGFACE', 'CREDENTIAL', 'AI_KEY'],
    },
    COHERE_KEY: {
      // Cohere: 40-char alphanumeric after COHERE_API_KEY= or co_ prefix
      regex: /\bco_[A-Za-z0-9]{36,}\b|(?:COHERE_API_KEY|cohere_key)\s*[:=]\s*["']?([A-Za-z0-9]{40,})["']?/gi,
      category: 'CREDENTIAL',
      sensitivity: 95,
      label: 'Cohere API Key',
      tags: ['COHERE', 'CREDENTIAL', 'AI_KEY'],
    },

    // ════════════════════════════════════════════════════════════════
    // VERSION CONTROL TOKENS
    // ════════════════════════════════════════════════════════════════

    GITHUB_TOKEN: {
      regex: /\b(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{36,}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'GitHub Token',
      tags: ['GITHUB', 'CREDENTIAL', 'TOKEN'],
    },
    GITLAB_TOKEN: {
      regex: /\bglpat-[A-Za-z0-9\-_]{20}\b|(?:GITLAB_TOKEN|gitlab_token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{20,})["']?/gi,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'GitLab Personal Access Token',
      tags: ['GITLAB', 'CREDENTIAL', 'TOKEN'],
    },
    NPM_TOKEN: {
      // npm access tokens: npm_... (36 chars)
      regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 95,
      label: 'npm Access Token',
      tags: ['NPM', 'CREDENTIAL', 'TOKEN'],
    },

    // ════════════════════════════════════════════════════════════════
    // PAYMENT CREDENTIALS
    // ════════════════════════════════════════════════════════════════

    STRIPE_SECRET: {
      regex: /\b(sk_live_|sk_test_|pk_live_|pk_test_|rk_live_)[A-Za-z0-9]{20,}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'Stripe API Key',
      tags: ['STRIPE', 'CREDENTIAL', 'PAYMENT', 'FINANCIAL'],
    },
    PAYPAL_SECRET: {
      regex: /(?:PAYPAL_SECRET|paypal_client_secret|paypal_secret)\s*[:=]\s*["']?([A-Za-z0-9\-_]{30,})["']?/gi,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'PayPal Client Secret',
      tags: ['PAYPAL', 'CREDENTIAL', 'PAYMENT', 'FINANCIAL'],
    },
    SQUARE_TOKEN: {
      regex: /\bEAAA[A-Za-z0-9]{60,}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'Square Access Token',
      tags: ['SQUARE', 'CREDENTIAL', 'PAYMENT'],
    },

    // ════════════════════════════════════════════════════════════════
    // COMMUNICATION / SaaS TOKENS
    // ════════════════════════════════════════════════════════════════

    SLACK_TOKEN: {
      // xoxb = bot token, xoxp = user token, xoxa = app token, xoxs = workspace token
      regex: /\b(xoxb|xoxp|xoxa|xoxs|xoxe|xoxr)-[0-9A-Za-z\-]{10,}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'Slack API Token',
      tags: ['SLACK', 'CREDENTIAL', 'TOKEN'],
    },
    TWILIO_CREDENTIALS: {
      // Twilio Account SID: AC + 32 hex chars | Auth token: 32 hex chars
      regex: /\bAC[a-f0-9]{32}\b|(?:TWILIO_AUTH_TOKEN|twilio_token)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
      category: 'CREDENTIAL',
      sensitivity: 95,
      label: 'Twilio Credentials',
      tags: ['TWILIO', 'CREDENTIAL', 'COMMUNICATION'],
    },
    SENDGRID_KEY: {
      // SendGrid API key: SG. followed by 69 chars
      regex: /\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 95,
      label: 'SendGrid API Key',
      tags: ['SENDGRID', 'CREDENTIAL', 'EMAIL_PROVIDER'],
    },
    MAILGUN_KEY: {
      regex: /\bkey-[a-f0-9]{32}\b|(?:MAILGUN_API_KEY|mailgun_key)\s*[:=]\s*["']?([A-Za-z0-9\-]{30,})["']?/gi,
      category: 'CREDENTIAL',
      sensitivity: 95,
      label: 'Mailgun API Key',
      tags: ['MAILGUN', 'CREDENTIAL', 'EMAIL_PROVIDER'],
    },
    DISCORD_TOKEN: {
      // Discord bot token: MTxxxxxx.xxxxxx.xxxxxxx
      regex: /\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}\b/g,
      category: 'CREDENTIAL',
      sensitivity: 95,
      label: 'Discord Bot Token',
      tags: ['DISCORD', 'CREDENTIAL', 'TOKEN'],
    },

    // ════════════════════════════════════════════════════════════════
    // AUTH TOKENS
    // ════════════════════════════════════════════════════════════════

    JWT_TOKEN: {
      regex: /\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g,
      category: 'CREDENTIAL',
      sensitivity: 95,
      label: 'JWT Token',
      tags: ['JWT', 'CREDENTIAL', 'AUTH_TOKEN'],
    },

    // ════════════════════════════════════════════════════════════════
    // PRIVATE KEYS & CERTIFICATES
    // ════════════════════════════════════════════════════════════════

    PRIVATE_KEY_PEM: {
      regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
      category: 'CREDENTIAL',
      sensitivity: 100,
      label: 'Private Key (PEM)',
      tags: ['PRIVATE_KEY', 'CREDENTIAL', 'CRYPTOGRAPHIC'],
    },
    SSH_PUBLIC_KEY: {
      // SSH public key exported from keygen — also sensitive (reveals host fingerprint)
      regex: /\bssh-(?:rsa|ed25519|dsa|ecdsa)\s+AAAA[A-Za-z0-9+/]{100,}/g,
      category: 'CREDENTIAL',
      sensitivity: 75,
      label: 'SSH Public Key',
      tags: ['SSH', 'CREDENTIAL', 'CRYPTOGRAPHIC'],
    },

    // ════════════════════════════════════════════════════════════════
    // DATABASE CONNECTION STRINGS
    // ════════════════════════════════════════════════════════════════

    DB_POSTGRES: {
      regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
      category: 'INFRASTRUCTURE',
      sensitivity: 95,
      label: 'PostgreSQL Connection String',
      tags: ['DATABASE', 'CREDENTIAL', 'INFRASTRUCTURE'],
    },
    DB_MONGODB: {
      regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
      category: 'INFRASTRUCTURE',
      sensitivity: 95,
      label: 'MongoDB Connection String',
      tags: ['DATABASE', 'CREDENTIAL', 'INFRASTRUCTURE'],
    },
    DB_MYSQL: {
      regex: /mysql:\/\/[^:]+:[^@]+@[^\s"']+/gi,
      category: 'INFRASTRUCTURE',
      sensitivity: 95,
      label: 'MySQL Connection String',
      tags: ['DATABASE', 'CREDENTIAL', 'INFRASTRUCTURE'],
    },
    DB_REDIS: {
      regex: /redis(?:s)?:\/\/(?:[^:]+:[^@]+@)?[^\s"']{8,}/gi,
      category: 'INFRASTRUCTURE',
      sensitivity: 85,
      label: 'Redis Connection String',
      tags: ['DATABASE', 'CREDENTIAL', 'INFRASTRUCTURE'],
    },
    DB_MSSQL: {
      regex: /(?:mssql|sqlserver):\/\/[^:]+:[^@]+@[^\s"']+|Server\s*=\s*[^;]+;\s*.*Password\s*=\s*[^;]+/gi,
      category: 'INFRASTRUCTURE',
      sensitivity: 95,
      label: 'MSSQL / SQL Server Connection',
      tags: ['DATABASE', 'CREDENTIAL', 'INFRASTRUCTURE'],
    },

    // ════════════════════════════════════════════════════════════════
    // .ENV FILE FORMAT  (critical real-world leak vector)
    // ════════════════════════════════════════════════════════════════

    ENV_FILE: {
      // Matches .env file content: multiple KEY=VALUE lines
      // Triggers when 3+ all-caps KEY=value lines are present
      regex: /^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+(?:\n[A-Z][A-Z0-9_]{2,}\s*=\s*\S+){2,}/m,
      category: 'CREDENTIAL',
      sensitivity: 90,
      label: '.env Configuration File',
      tags: ['ENV_FILE', 'CREDENTIAL', 'CONFIG'],
    },

    // ════════════════════════════════════════════════════════════════
    // GENERIC SECRETS (catches what specific patterns miss)
    // ════════════════════════════════════════════════════════════════

    GENERIC_SECRET: {
      // Key=value assignment where value is 8+ mixed-char string
      regex: /(?:password|passwd|secret|token|api_?key|access_?key|auth_?key|private_?key|client_?secret|app_?secret)\s*[:=]\s*["']?([A-Za-z0-9!@#$%^&*()\-_+=/]{8,})["']?/gi,
      category: 'CREDENTIAL',
      sensitivity: 90,
      label: 'Generic Secret / Password Assignment',
      tags: ['CREDENTIAL', 'SECRET', 'GENERIC'],
    },

    // ════════════════════════════════════════════════════════════════
    // PII — PERSONAL IDENTIFIABLE INFORMATION
    // ════════════════════════════════════════════════════════════════

    EMAIL: {
      regex: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
      category: 'PII',
      sensitivity: 70,
      label: 'Email Address',
      tags: ['PII', 'EMAIL', 'PERSONAL_DATA'],
    },
    PHONE: {
      // Requires separator characters between digit groups
      regex: /(?:\+?[0-9]{1,3}[\s\-.])?(?:\(?[0-9]{3}\)?[\s\-.][0-9]{3}[\s\-.][0-9]{4})\b/g,
      category: 'PII',
      sensitivity: 65,
      label: 'Phone Number',
      tags: ['PII', 'PHONE', 'PERSONAL_DATA'],
    },
    CREDIT_CARD: {
      regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
      category: 'FINANCIAL',
      sensitivity: 100,
      label: 'Credit Card Number',
      tags: ['PCI', 'FINANCIAL', 'CREDIT_CARD'],
    },
    SSN: {
      // US Social Security Number: XXX-XX-XXXX or XXX XX XXXX
      regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
      category: 'PII',
      sensitivity: 100,
      label: 'US Social Security Number',
      tags: ['PII', 'SSN', 'PERSONAL_DATA', 'GOVERNMENT_ID'],
    },
    IBAN: {
      // International Bank Account Number: 2-letter country code + 2 check digits + up to 30 alphanumeric
      regex: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}\b(?=\s|$|[,;])/g,
      category: 'FINANCIAL',
      sensitivity: 90,
      label: 'IBAN Bank Account Number',
      tags: ['PII', 'FINANCIAL', 'BANK_ACCOUNT', 'IBAN'],
    },
    PASSPORT_NUMBER: {
      // Generic passport: 1-2 letters followed by 6-9 digits (many countries)
      regex: /\b(?:passport|passport\s*no|passport\s*number|pass\s*no)\s*[:=]?\s*([A-Z]{1,2}[0-9]{6,9})\b/gi,
      category: 'PII',
      sensitivity: 95,
      label: 'Passport Number',
      tags: ['PII', 'PASSPORT', 'GOVERNMENT_ID', 'PERSONAL_DATA'],
    },

    // ════════════════════════════════════════════════════════════════
    // INFRASTRUCTURE
    // ════════════════════════════════════════════════════════════════

    PRIVATE_IP: {
      regex: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
      category: 'INFRASTRUCTURE',
      sensitivity: 55,
      label: 'Private IP Address',
      tags: ['INFRASTRUCTURE', 'IP', 'INTERNAL_NETWORK'],
    },

    // ════════════════════════════════════════════════════════════════
    // SOURCE CODE WITH SECRETS (code itself is OK, code WITH secrets is not)
    // ════════════════════════════════════════════════════════════════

    PYTHON_IMPORT: {
      regex: /^(?:import|from)\s+[a-zA-Z_][a-zA-Z0-9_.]*\s+(?:import\s+[a-zA-Z_].*)?$/m,
      category: 'SOURCE_CODE',
      sensitivity: 50,
      label: 'Python Source Code',
      tags: ['SOURCE_CODE', 'PYTHON', 'TECHNICAL'],
    },
    JS_CODE: {
      // Require 2+ structural code patterns (not just keywords in prose)
      regex: /(?:(?:const|let|var)\s+[a-zA-Z_$][\w$]*\s*=|function\s+[a-zA-Z_$][\w$]*\s*\(|=>\s*[{(]|class\s+[A-Z][\w$]*\s*(?:extends)?|import\s+(?:\{|\*|[A-Z])|export\s+(?:default|const|function|class))/g,
      category: 'SOURCE_CODE',
      sensitivity: 50,
      label: 'JavaScript / TypeScript Code',
      tags: ['SOURCE_CODE', 'JAVASCRIPT', 'TECHNICAL'],
    },
    SHEBANG_SCRIPT: {
      regex: /^#!\/(?:usr\/bin\/env\s+)?(?:python|bash|sh|node|ruby)/m,
      category: 'SOURCE_CODE',
      sensitivity: 55,
      label: 'Script / Shell Code',
      tags: ['SOURCE_CODE', 'SCRIPT', 'TECHNICAL'],
    },

    // ════════════════════════════════════════════════════════════════
    // FINANCIAL DATA
    // ════════════════════════════════════════════════════════════════

    FINANCIAL_AMOUNT: {
      // Requires actual currency symbol to avoid false positives on counts/amounts
      regex: /(?:revenue|salary|budget|profit|loss|transaction|invoice)\s*[:=]?\s*[$£€₹]\s*[\d,]+(?:\.\d{2})?|[$£€₹]\s*[\d,]+(?:\.\d{2})?\s*(?:million|billion|M|B)\b/gi,
      category: 'FINANCIAL',
      sensitivity: 75,
      label: 'Financial Amount / Record',
      tags: ['FINANCIAL', 'SENSITIVE_BUSINESS'],
    },
    CSV_BULK_DATA: {
      // 5+ rows of 4+ comma-separated values = likely PII dump
      regex: /(?:[^,\n]+,){3,}[^,\n]+(?:\n(?:[^,\n]+,){3,}[^,\n]+){4,}/g,
      category: 'BULK_DATA',
      sensitivity: 85,
      label: 'Bulk Tabular / CSV Data',
      tags: ['BULK_DATA', 'PII', 'HIGH_VOLUME'],
    },
  };


  // ------------------------------------------------------------------
  // Luhn Algorithm (Credit Card Validation)
  // ------------------------------------------------------------------

  function luhnCheck(numStr) {
    const digits = numStr.replace(/\D/g, '');
    let sum = 0;
    let alternate = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = parseInt(digits[i], 10);
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }

  // ------------------------------------------------------------------
  // Run Detection
  // ------------------------------------------------------------------

  /**
   * Runs all deterministic detectors on the given text.
   * @param {string} text
   * @returns {{
   *   detected: boolean,
   *   categories: string[],
   *   maxSensitivity: number,
   *   findings: Array<{ detector: string, label: string, category: string, sensitivity: number, tags: string[], count: number }>
   * }}
   */
  function analyze(text) {
    if (!text || text.trim().length === 0) {
      return { detected: false, categories: [], maxSensitivity: 0, findings: [] };
    }

    const findings = [];
    const categories = new Set();
    let maxSensitivity = 0;

    for (const [key, pattern] of Object.entries(PATTERNS)) {
      // Reset regex lastIndex for global patterns
      if (pattern.regex.global) pattern.regex.lastIndex = 0;

      const matches = text.match(pattern.regex);

      if (matches && matches.length > 0) {
        // Extra validation for credit cards
        if (key === 'CREDIT_CARD') {
          const valid = matches.filter(m => luhnCheck(m));
          if (valid.length === 0) continue;
        }

        // JS code needs at least 2 structural code pattern hits to confirm it's real code
        if ((key === 'JS_CODE') && matches.length < 2) continue;

        findings.push({
          detector: key,
          label: pattern.label,
          category: pattern.category,
          sensitivity: pattern.sensitivity,
          tags: pattern.tags,
          count: matches.length,
        });

        categories.add(pattern.category);
        if (pattern.sensitivity > maxSensitivity) {
          maxSensitivity = pattern.sensitivity;
        }
      }
    }

    return {
      detected: findings.length > 0,
      categories: [...categories],
      maxSensitivity,
      findings,
    };
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return {
    analyze,
    PATTERNS,
  };

})();
