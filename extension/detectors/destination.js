/**
 * SentinelX — Destination Intelligence Engine
 *
 * Classifies the current browser tab's destination into trust tiers.
 * Trust tier directly influences the contextual risk score.
 *
 * Tiers (ascending risk):
 *   INTERNAL       → 10 (company-owned infrastructure)
 *   APPROVED_AI    → 35 (enterprise AI with DPA/zero-retention agreements)
 *   APPROVED_SAAS  → 40 (known enterprise tools)
 *   EXTERNAL_AI    → 75 (consumer AI services)
 *   UNKNOWN_SAAS   → 85 (unknown or unclassified SaaS)
 *   SUSPICIOUS     → 95 (pastebin, file-sharing, or flagged domains)
 */

'use strict';

window.SentinelXDestination = (() => {

  // ------------------------------------------------------------------
  // Destination Trust Registry
  // ------------------------------------------------------------------

  const TRUST_TIERS = {
    INTERNAL:      { score: 10,  label: 'Internal Infrastructure',           color: '#10b981' },
    APPROVED_AI:   { score: 35,  label: 'Approved Enterprise AI',            color: '#3b82f6' },
    APPROVED_SAAS: { score: 40,  label: 'Approved SaaS Tool',                color: '#6366f1' },
    EXTERNAL_AI:   { score: 75,  label: 'External AI Service (Public Tier)', color: '#f59e0b' },
    UNKNOWN_SAAS:  { score: 85,  label: 'Unknown SaaS / Unclassified',       color: '#ef4444' },
    SUSPICIOUS:    { score: 95,  label: 'High-Risk / Suspicious Domain',     color: '#dc2626' },
  };

  // ── Internal / Localhost Patterns ──────────────────────────────────
  const INTERNAL_PATTERNS = [
    /^localhost$/i,
    /^127\./,
    /^192\.168\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /\.internal$/i,
    /\.local$/i,
    /\.corp$/i,
    /\.intranet$/i,
  ];

  // ── Approved Enterprise AI (zero-retention / DPA signed) ──────────
  const APPROVED_AI_DOMAINS = new Set([
    'azure.com',
    'openai.azure.com',
    'copilot.microsoft.com',
    'bing.com',                     // MS Copilot
    'teams.microsoft.com',
    'microsoftonline.com',
  ]);

  // ── Approved SaaS (standard enterprise tools) ──────────────────────
  const APPROVED_SAAS_DOMAINS = new Set([
    'github.com',
    'gitlab.com',
    'bitbucket.org',
    'atlassian.net',
    'jira.atlassian.net',
    'confluence.atlassian.net',
    'slack.com',
    'notion.so',
    'google.com',
    'docs.google.com',
    'sheets.google.com',
    'drive.google.com',
    'office.com',
    'sharepoint.com',
    'outlook.com',
    'microsoftonline.com',
    'zoom.us',
    'figma.com',
    'linear.app',
    'asana.com',
    'trello.com',
    'monday.com',
  ]);

  // ── External AI (public consumer services) ─────────────────────────
  const EXTERNAL_AI_DOMAINS = new Set([
    'chat.openai.com',
    'chatgpt.com',
    'openai.com',
    'claude.ai',
    'anthropic.com',
    'gemini.google.com',
    'bard.google.com',
    'perplexity.ai',
    'poe.com',
    'character.ai',
    'huggingface.co',
    'replicate.com',
    'mistral.ai',
    'cohere.com',
    'together.ai',
    'deepseek.com',
    'groq.com',
    'you.com',
    'phind.com',
    'cursor.sh',
    'v0.dev',
    'replit.com',
    'codeium.com',
    'tabnine.com',
    'copilot.github.com',
  ]);

  // ── Suspicious / High-Risk Domains ────────────────────────────────
  const SUSPICIOUS_DOMAINS = new Set([
    'pastebin.com',
    'paste.ee',
    'hastebin.com',
    'ghostbin.com',
    'controlc.com',
    'rentry.co',
    'dpaste.org',
    'justpaste.it',
    'filebin.net',
    'temp.sh',
    'file.io',
    'transfer.sh',
    'tmpfiles.org',
    'anonfiles.com',
    'gofile.io',
    'uploadfiles.io',
    'wetransfer.com',
  ]);

  // ------------------------------------------------------------------
  // Domain Extraction
  // ------------------------------------------------------------------

  /**
   * Extracts the registrable domain (eTLD+1) from a full hostname.
   * Example: "chat.openai.com" → "openai.com"
   * @param {string} hostname
   * @returns {string}
   */
  function extractRootDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.toLowerCase().replace(/^www\./, '').split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return hostname.toLowerCase();
  }

  /**
   * Gets the full hostname from the current page's URL.
   * @returns {string}
   */
  function getCurrentHostname(targetElement) {
    // Check if running inside test harness / sandbox with simulated destination
    if (targetElement && typeof targetElement.closest === 'function') {
      const simCard = targetElement.closest('.env-card');
      if (simCard) {
        const urlEl = simCard.querySelector('.env-url');
        if (urlEl) {
          const text = urlEl.textContent.trim();
          const match = text.match(/([a-z0-9.-]+\.[a-z]{2,})/i);
          if (match) return match[1].toLowerCase();
        }
      }
    }

    try {
      return window.location.hostname.toLowerCase();
    } catch (e) {
      return '';
    }
  }

  // ------------------------------------------------------------------
  // Classification Engine
  // ------------------------------------------------------------------

  /**
   * Classifies a hostname into a trust tier.
   * @param {string} hostname — full hostname (e.g., "chat.openai.com")
   * @returns {{
   *   tier: string,
   *   score: number,
   *   label: string,
   *   color: string,
   *   hostname: string,
   *   rootDomain: string
   * }}
   */
  function classifyHostname(hostname) {
    const rootDomain = extractRootDomain(hostname);

    // 1. Internal / localhost
    for (const pattern of INTERNAL_PATTERNS) {
      if (pattern.test(hostname)) {
        return { tier: 'INTERNAL', ...TRUST_TIERS.INTERNAL, hostname, rootDomain };
      }
    }

    // 2. Suspicious / high-risk file-sharing
    if (SUSPICIOUS_DOMAINS.has(hostname) || SUSPICIOUS_DOMAINS.has(rootDomain)) {
      return { tier: 'SUSPICIOUS', ...TRUST_TIERS.SUSPICIOUS, hostname, rootDomain };
    }

    // 3. External public AI services
    if (EXTERNAL_AI_DOMAINS.has(hostname) || EXTERNAL_AI_DOMAINS.has(rootDomain)) {
      return { tier: 'EXTERNAL_AI', ...TRUST_TIERS.EXTERNAL_AI, hostname, rootDomain };
    }

    // 4. Approved enterprise AI
    if (APPROVED_AI_DOMAINS.has(hostname) || APPROVED_AI_DOMAINS.has(rootDomain)) {
      return { tier: 'APPROVED_AI', ...TRUST_TIERS.APPROVED_AI, hostname, rootDomain };
    }

    // 5. Approved SaaS
    if (APPROVED_SAAS_DOMAINS.has(hostname) || APPROVED_SAAS_DOMAINS.has(rootDomain)) {
      return { tier: 'APPROVED_SAAS', ...TRUST_TIERS.APPROVED_SAAS, hostname, rootDomain };
    }

    // 6. Default: unknown external SaaS
    return { tier: 'UNKNOWN_SAAS', ...TRUST_TIERS.UNKNOWN_SAAS, hostname, rootDomain };
  }

  /**
   * Classifies the current page's destination.
   * @param {HTMLElement} [targetElement] — optional target element to inspect for simulated sandbox cards
   * @returns {{ tier: string, score: number, label: string, color: string, hostname: string, rootDomain: string }}
   */
  function classifyCurrentPage(targetElement) {
    return classifyHostname(getCurrentHostname(targetElement));
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return {
    classifyCurrentPage,
    classifyHostname,
    extractRootDomain,
    TRUST_TIERS,
  };

})();
