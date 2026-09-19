/**
 * SentinelX — Organization Policy Engine
 *
 * Evaluates hard-coded and configurable security rules AFTER the risk
 * score is computed. Policy rules take precedence over risk score thresholds.
 *
 * Rule format:
 *   { conditions: { ... }, action: 'ALLOW' | 'WARN' | 'BLOCK', reason: string }
 *
 * Evaluation order:
 *   1. BLOCK rules first (most restrictive wins if matched)
 *   2. WARN rules second
 *   3. ALLOW rules last
 *   4. Fallback: trust the risk engine decision
 */

'use strict';

window.SentinelXPolicyEngine = (() => {

  // ------------------------------------------------------------------
  // Built-in Security Policies (immutable base rules)
  // ------------------------------------------------------------------

  const BUILT_IN_POLICIES = [

    // ── Absolute Block Rules ──────────────────────────────────────────
    {
      id: 'POLICY_001',
      name: 'Block credentials to any external destination',
      action: 'BLOCK',
      conditions: {
        detectedCategories: ['CREDENTIAL'],
        destinationTiers: ['EXTERNAL_AI', 'UNKNOWN_SAAS', 'SUSPICIOUS'],
      },
      reason: 'Organizational policy prohibits transmitting credentials to external services.',
    },
    {
      id: 'POLICY_002',
      name: 'Block credentials to suspicious destinations',
      action: 'BLOCK',
      conditions: {
        detectedCategories: ['CREDENTIAL'],
        destinationTiers: ['SUSPICIOUS'],
      },
      reason: 'Target domain is classified as suspicious or high-risk.',
    },
    {
      id: 'POLICY_003',
      name: 'Block PCI financial data to external AI',
      action: 'BLOCK',
      conditions: {
        detectedTags: ['PCI'],
        destinationTiers: ['EXTERNAL_AI', 'UNKNOWN_SAAS', 'SUSPICIOUS'],
      },
      reason: 'Payment card data cannot be transmitted to external AI or SaaS services.',
    },
    {
      id: 'POLICY_004',
      name: 'Block bulk data to unknown/suspicious destinations',
      action: 'BLOCK',
      conditions: {
        detectedCategories: ['BULK_DATA'],
        destinationTiers: ['UNKNOWN_SAAS', 'SUSPICIOUS'],
      },
      reason: 'Bulk data transmission to unclassified destinations is not permitted.',
    },
    {
      id: 'POLICY_005',
      name: 'Block private keys unconditionally',
      action: 'BLOCK',
      conditions: {
        detectedTags: ['PRIVATE_KEY'],
        destinationTiers: ['EXTERNAL_AI', 'UNKNOWN_SAAS', 'SUSPICIOUS', 'APPROVED_SAAS'],
      },
      reason: 'Private cryptographic keys must never be transmitted outside internal systems.',
    },
    {
      id: 'POLICY_006',
      name: 'Block non-public strategic business data to external services',
      action: 'BLOCK',
      conditions: {
        detectedCategories: ['STRATEGIC_BUSINESS', 'FINANCIAL_PROJECTION', 'CONFIDENTIAL_PROJECT'],
        destinationTiers: ['EXTERNAL_AI', 'UNKNOWN_SAAS', 'SUSPICIOUS'],
      },
      reason: 'Organizational compliance strictly prohibits transmitting non-public strategic narratives or roadmap data to external services.',
    },

    // ── Warn Rules ────────────────────────────────────────────────────
    {
      id: 'POLICY_010',
      name: 'Warn for source code to external AI',
      action: 'WARN',
      conditions: {
        detectedCategories: ['SOURCE_CODE'],
        destinationTiers: ['EXTERNAL_AI'],
      },
      reason: 'Proprietary source code is being sent to an external AI service.',
    },
    {
      id: 'POLICY_011',
      name: 'Warn for PII to external AI',
      action: 'WARN',
      conditions: {
        detectedCategories: ['PII'],
        destinationTiers: ['EXTERNAL_AI'],
      },
      reason: 'Personal data is being transmitted to an external AI service.',
    },
    {
      id: 'POLICY_012',
      name: 'Warn for financial data to unknown SaaS',
      action: 'WARN',
      conditions: {
        detectedCategories: ['FINANCIAL'],
        destinationTiers: ['UNKNOWN_SAAS'],
      },
      reason: 'Financial data is being sent to an unclassified external service.',
    },

    // ── Allow Rules ───────────────────────────────────────────────────
    {
      id: 'POLICY_020',
      name: 'Allow safe content anywhere',
      action: 'ALLOW',
      conditions: {
        maxRiskScore: 20,
      },
      reason: 'Content assessed as non-sensitive.',
    },
    {
      id: 'POLICY_021',
      name: 'Allow all content to internal destinations',
      action: 'ALLOW',
      conditions: {
        destinationTiers: ['INTERNAL'],
      },
      reason: 'Destination is an internal company system.',
    },
  ];

  // ------------------------------------------------------------------
  // Dynamic Remote Policy Sync (Two-Way SOC Dashboard Sync)
  // ------------------------------------------------------------------

  let dynamicPolicies = [];

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['customPolicies'], (res) => {
      if (res && Array.isArray(res.customPolicies)) {
        dynamicPolicies = res.customPolicies;
      }
    });

    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes.customPolicies) {
        dynamicPolicies = changes.customPolicies.newValue || [];
      }
    });
  }

  // ------------------------------------------------------------------
  // Condition Evaluator
  // ------------------------------------------------------------------

  /**
   * Evaluates whether a single policy rule matches the current context.
   * @param {object} rule
   * @param {object} context — { detectedCategories, detectedTags, destinationTier, riskScore }
   * @returns {boolean}
   */
  function matchesConditions(rule, context) {
    const cond = rule.conditions;

    // Category check: at least one detected category must be in the rule's list
    if (cond.detectedCategories && cond.detectedCategories.length > 0) {
      const overlap = cond.detectedCategories.some(c =>
        context.detectedCategories.includes(c)
      );
      if (!overlap) return false;
    }

    // Tag check: at least one detected tag must be in the rule's list
    if (cond.detectedTags && cond.detectedTags.length > 0) {
      const overlap = cond.detectedTags.some(t =>
        context.detectedTags.includes(t)
      );
      if (!overlap) return false;
    }

    // Destination tier check: current tier must be in the rule's list
    if (cond.destinationTiers && cond.destinationTiers.length > 0) {
      if (!cond.destinationTiers.includes(context.destinationTier)) return false;
    }

    // Max risk score check
    if (cond.maxRiskScore !== undefined) {
      if (context.riskScore > cond.maxRiskScore) return false;
    }

    return true;
  }

  // ------------------------------------------------------------------
  // Policy Evaluation
  // ------------------------------------------------------------------

  /**
   * Evaluates all policies against the current detection context.
   * BLOCK rules evaluated first, then WARN, then ALLOW.
   * @param {{
   *   detectedCategories: string[],
   *   detectedTags: string[],
   *   destinationTier: string,
   *   riskScore: number,
   *   riskDecision: string,    — from risk engine: 'ALLOW' | 'WARN' | 'BLOCK'
   * }} context
   * @returns {{
   *   finalDecision: string,
   *   matchedPolicy: object | null,
   *   policyOverride: boolean,
   *   reason: string
   * }}
   */
  function evaluate(context) {
    // If no sensitive categories or tags were detected, unconditionally ALLOW
    if ((!context.detectedCategories || context.detectedCategories.length === 0) &&
        (!context.detectedTags || context.detectedTags.length === 0)) {
      return {
        finalDecision: 'ALLOW',
        matchedPolicy: null,
        policyOverride: false,
        reason: 'Clean input — no sensitive data detected.',
      };
    }

    const allPolicies = [...dynamicPolicies, ...BUILT_IN_POLICIES];

    // Evaluate in priority order: BLOCK → WARN → ALLOW
    for (const priority of ['BLOCK', 'WARN', 'ALLOW']) {
      for (const rule of allPolicies) {
        if (rule.action !== priority) continue;
        if (matchesConditions(rule, context)) {
          const policyOverride = rule.action !== context.riskDecision;
          return {
            finalDecision: rule.action,
            matchedPolicy: rule,
            policyOverride,
            reason: rule.reason,
          };
        }
      }
    }

    // No policy matched — fall back to risk engine decision
    return {
      finalDecision: context.riskDecision,
      matchedPolicy: null,
      policyOverride: false,
      reason: `Risk score ${context.riskScore}/100 — no explicit policy rule matched.`,
    };
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return {
    evaluate,
    BUILT_IN_POLICIES,
  };

})();
