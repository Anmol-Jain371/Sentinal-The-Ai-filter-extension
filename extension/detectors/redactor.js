/**
 * SentinelX — Semantic Context-Preserving Redaction Engine
 *
 * Replaces detected sensitive data with structured semantic placeholders
 * that preserve code/JSON/document formatting so the AI can still answer
 * the user's question without seeing any real sensitive data.
 *
 * Examples:
 *   sk_live_x4Ab9GhQpZs9 → [STRIPE_SECRET_KEY_1]
 *   john.doe@company.com  → [CUSTOMER_EMAIL_1]
 *   postgres://admin:pass@10.0.0.1/db → [DB_CONNECTION_URI]
 *   AKIAIOSFODNN7EXAMPLE  → [AWS_ACCESS_KEY_1]
 */

'use strict';

window.SentinelXRedactor = (() => {

  // ------------------------------------------------------------------
  // Redaction Rule Set
  // (Ordered by specificity — more specific patterns first)
  // ------------------------------------------------------------------

  const REDACTION_RULES = [
    // ── AI Provider API Keys (highest priority — longest prefix first) ──
    {
      id: 'OPENAI_KEY',
      regex: /\bsk-proj-[A-Za-z0-9\-_]{40,}\b/g,
      label: 'OPENAI_API_KEY',
    },
    {
      id: 'OPENAI_KEY_LEGACY',
      regex: /\bsk-[A-Za-z0-9]{48,}\b/g,
      label: 'OPENAI_API_KEY',
    },
    {
      id: 'ANTHROPIC_KEY',
      regex: /\bsk-ant-[A-Za-z0-9\-_]{40,}\b/g,
      label: 'ANTHROPIC_API_KEY',
    },
    {
      id: 'HUGGINGFACE_TOKEN',
      regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
      label: 'HUGGINGFACE_TOKEN',
    },

    // ── Cloud Credentials ──────────────────────────────────────────
    {
      id: 'AWS_ACCESS_KEY',
      regex: /\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/g,
      label: 'AWS_ACCESS_KEY',
    },
    {
      id: 'AWS_SECRET',
      regex: /(?<=(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["']?)[A-Za-z0-9/+]{40}(?=["']?)/gi,
      label: 'AWS_SECRET_KEY',
    },
    {
      id: 'GCP_API_KEY',
      regex: /AIza[0-9A-Za-z\-_]{35}/g,
      label: 'GCP_API_KEY',
    },
    {
      id: 'AZURE_STORAGE_KEY',
      regex: /AccountKey=[A-Za-z0-9+/]{86}==/g,
      label: 'AZURE_STORAGE_KEY',
    },

    // ── VCS / Dev Tokens ─────────────────────────────────────────
    {
      id: 'GITHUB_TOKEN',
      regex: /\b(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{36,}\b/g,
      label: 'GITHUB_TOKEN',
    },
    {
      id: 'GITLAB_TOKEN',
      regex: /\bglpat-[A-Za-z0-9\-_]{20,}\b/g,
      label: 'GITLAB_TOKEN',
    },
    {
      id: 'NPM_TOKEN',
      regex: /\bnpm_[A-Za-z0-9]{36,}\b/g,
      label: 'NPM_TOKEN',
    },

    // ── Payment ───────────────────────────────────────────────────
    {
      id: 'STRIPE_KEY',
      regex: /\b(sk_live_|sk_test_|pk_live_|pk_test_|rk_live_)[A-Za-z0-9]{20,}\b/g,
      label: 'STRIPE_KEY',
    },

    // ── Communication Tokens ─────────────────────────────────────
    {
      id: 'SLACK_TOKEN',
      regex: /\b(xoxb-|xoxp-|xoxa-|xoxr-)[A-Za-z0-9\-]{20,}\b/g,
      label: 'SLACK_TOKEN',
    },
    {
      id: 'SENDGRID_KEY',
      regex: /\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b/g,
      label: 'SENDGRID_API_KEY',
    },
    {
      id: 'TWILIO_TOKEN',
      regex: /(?<=(?:TWILIO_AUTH_TOKEN|twilio_auth_token)\s*[:=]\s*["']?)[a-f0-9]{32}(?=["']?)/gi,
      label: 'TWILIO_AUTH_TOKEN',
    },
    {
      id: 'DISCORD_TOKEN',
      regex: /\b[A-Za-z0-9_\-]{23,28}\.[A-Za-z0-9_\-]{6,7}\.[A-Za-z0-9_\-]{27,}\b/g,
      label: 'DISCORD_BOT_TOKEN',
    },

    // ── Auth Tokens ───────────────────────────────────────────────
    {
      id: 'JWT',
      regex: /\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g,
      label: 'JWT_TOKEN',
    },
    {
      id: 'PRIVATE_KEY',
      regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----([\s\S]*?)-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
      label: 'PRIVATE_KEY_BLOCK',
    },

    // ── Database URIs ──────────────────────────────────────────────
    {
      id: 'DB_URI',
      regex: /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|mssql):\/\/[^:]+:[^@]+@[^\s"'\n]+/gi,
      label: 'DB_CONNECTION_URI',
    },

    // ── Generic Secret Assignments ─────────────────────────────────
    // Replaces the value part only, preserving the key name
    {
      id: 'GENERIC_SECRET_VALUE',
      regex: /(?<=(password|passwd|secret|token|api_?key|access_?key|auth_?key|private_?key)\s*[:=]\s*["']?)[A-Za-z0-9!@#$%^&*()\-_+=/]{8,}(?=["']?)/gi,
      label: 'SECRET_VALUE',
    },

    // ── PII ────────────────────────────────────────────────────────
    {
      id: 'EMAIL',
      regex: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
      label: 'CUSTOMER_EMAIL',
    },
    {
      id: 'PHONE',
      regex: /(?:\+?[0-9]{1,3}[\s\-.]?)?\(?[0-9]{3}\)?[\s\-.][0-9]{3}[\s\-.][0-9]{4}\b/g,
      label: 'PHONE_NUMBER',
    },
    {
      id: 'CREDIT_CARD',
      regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
      label: 'CREDIT_CARD',
    },

    // ── Infrastructure ─────────────────────────────────────────────
    {
      id: 'PRIVATE_IP',
      regex: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
      label: 'INTERNAL_IP',
    },
  ];

  // ------------------------------------------------------------------
  // Counter Registry (ensures unique placeholder tokens per session)
  // ------------------------------------------------------------------

  const counters = {};

  function nextIndex(label) {
    counters[label] = (counters[label] || 0) + 1;
    return counters[label];
  }

  function resetCounters() {
    Object.keys(counters).forEach(k => delete counters[k]);
  }

  // ------------------------------------------------------------------
  // Core Redaction
  // ------------------------------------------------------------------

  /**
   * Applies all redaction rules to the input text.
   * @param {string} text — original clipboard/input text
   * @returns {{
   *   redacted: string,       — sanitized text safe to transmit
   *   replacements: Array<{ original: string, placeholder: string, rule: string }>,
   *   totalReplacements: number
   * }}
   */
  function redact(text) {
    if (!text || text.trim().length === 0) {
      return { redacted: text, replacements: [], totalReplacements: 0 };
    }

    resetCounters();

    let redacted = text;
    const replacements = [];

    for (const rule of REDACTION_RULES) {
      // Reset regex state for global patterns
      rule.regex.lastIndex = 0;

      redacted = redacted.replace(rule.regex, (match) => {
        const idx = nextIndex(rule.label);
        const placeholder = `[${rule.label}_${idx}]`;
        replacements.push({
          original: match.substring(0, 8) + '***',  // Truncate for logging safety
          placeholder,
          rule: rule.id,
        });
        return placeholder;
      });
    }

    return {
      redacted,
      replacements,
      totalReplacements: replacements.length,
    };
  }

  /**
   * Returns a human-readable summary of what was redacted.
   * @param {Array} replacements
   * @returns {string[]}
   */
  function summarizeReplacements(replacements) {
    const groups = {};
    for (const r of replacements) {
      groups[r.rule] = (groups[r.rule] || 0) + 1;
    }
    return Object.entries(groups).map(([rule, count]) =>
      `${count}× ${rule.replace(/_/g, ' ')}`
    );
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return {
    redact,
    summarizeReplacements,
  };

})();
