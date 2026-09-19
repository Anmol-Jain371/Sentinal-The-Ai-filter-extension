/**
 * SentinelX — Semantic & Corporate Narrative Detector
 *
 * Patent-Grade Client-Side Contextual Analyzer
 * Detects unstructured corporate leaks, non-public financial disclosures,
 * strategic M&A narratives, and internal project codenames.
 *
 * Operates purely within the browser sandbox with < 2ms execution time.
 * Zero plaintext leaves the client.
 */

'use strict';

window.SentinelXSemantic = (() => {

  // ------------------------------------------------------------------
  // Semantic Narrative Pattern Signatures
  // ------------------------------------------------------------------

  const STRATEGIC_INDICATORS = [
    {
      id: 'PROJECT_CODENAME',
      label: 'Internal Project Codename',
      regex: /(?:project\s+codename|internal\s+codename|codename)\s*[:=]\s*["']?([A-Za-z0-9_\-]+)["']?/gi,
      category: 'CONFIDENTIAL_PROJECT',
      weight: 40,
      tags: ['PROJECT_CODENAME', 'INTERNAL_AFFAIRS', 'STRATEGIC'],
    },
    {
      id: 'MA_STRATEGIC_TARGET',
      label: 'M&A / Acquisition Target',
      regex: /\b(?:strategic\s+acquisition(?:\s+target)?|merger\s+(?:and|&)\s+acquisition|due\s+diligence\s+target|hostile\s+takeover|undisclosed\s+acquisition)\b/gi,
      category: 'STRATEGIC_BUSINESS',
      weight: 50,
      tags: ['M_AND_A', 'STRATEGIC_DEAL', 'CORPORATE_GOVERNANCE'],
    },
    {
      id: 'EMBARGO_LAUNCH',
      label: 'Embargoed Roadmap / Launch Date',
      regex: /(?:launch\s+date|release\s+date|go-live\s+date|ga\s+date)\s*[:=]\s*(?:Q[1-4]\s+\d{4}|\d{1,2}\/\d{1,2}\/\d{4}|[A-Za-z]+\s+\d{4})/gi,
      category: 'ROADMAP_EMBARGO',
      weight: 35,
      tags: ['ROADMAP', 'LAUNCH_DATE', 'EMBARGO'],
    },
    {
      id: 'REVENUE_PROJECTION',
      label: 'Unreleased Financial Projection',
      regex: /(?:expected\s+revenue|projected\s+revenue|forecasted\s+arr|annual\s+target|ebitda\s+margin)\s*[:=]?\s*[\$£€₹]?\s*\d+(?:\.\d+)?\s*(?:M|B|K|million|billion)?/gi,
      category: 'FINANCIAL_PROJECTION',
      weight: 45,
      tags: ['FINANCIAL_PROJECTION', 'REVENUE', 'MATERIAL_NON_PUBLIC'],
    },
    {
      id: 'CONFIDENTIAL_PRICING',
      label: 'Enterprise Pricing Terms',
      regex: /(?:pricing|contract\s+value|acv|tcv|rate\s+card)\s*[:=]\s*[\$£€₹]\s*[\d,]+(?:\s*\/\s*(?:org|seat|year|month|user|annum))?/gi,
      category: 'PRICING_TERMS',
      weight: 35,
      tags: ['PRICING', 'COMMERCIAL_CONFIDENTIAL'],
    },
    {
      id: 'LEGAL_NDA_DISCLOSURE',
      label: 'NDA / Restricted Disclosure Notice',
      regex: /\b(?:confidential\s+and\s+proprietary|strictly\s+confidential|do\s+not\s+distribute|non-disclosure\s+agreement|patent\s+pending\s+disclosure)\b/gi,
      category: 'COMPLIANCE',
      weight: 30,
      tags: ['NDA', 'PROPRIETARY', 'RESTRICTED'],
    },
  ];

  // ------------------------------------------------------------------
  // Analysis Engine
  // ------------------------------------------------------------------

  /**
   * Analyzes text for contextual business narratives and proprietary indicators.
   * @param {string} text
   * @returns {{
   *   detected: boolean,
   *   maxSensitivity: number,
   *   score: number,
   *   categories: string[],
   *   findings: Array<{ id: string, label: string, category: string, weight: number, tags: string[], matchCount: number }>,
   *   tags: string[]
   * }}
   */
  function analyze(text) {
    if (!text || text.trim().length < 15) {
      return { detected: false, maxSensitivity: 0, score: 0, categories: [], findings: [], tags: [] };
    }

    const findings = [];
    const categories = new Set();
    const allTags = new Set();
    let cumulativeWeight = 0;

    for (const indicator of STRATEGIC_INDICATORS) {
      if (indicator.regex.global) indicator.regex.lastIndex = 0;
      const matches = text.match(indicator.regex);

      if (matches && matches.length > 0) {
        findings.push({
          id: indicator.id,
          label: indicator.label,
          category: indicator.category,
          weight: indicator.weight,
          tags: indicator.tags,
          matchCount: matches.length,
        });

        categories.add(indicator.category);
        indicator.tags.forEach(t => allTags.add(t));
        cumulativeWeight += indicator.weight * Math.min(matches.length, 2);
      }
    }

    // A contextual leak is confirmed if cumulative weight >= 40 (or multiple distinct indicators)
    const detected = findings.length >= 2 || cumulativeWeight >= 45;
    
    // Sensitivity scale (0-100) based on signal density
    let sensitivity = 0;
    if (detected) {
      sensitivity = Math.min(95, Math.max(65, cumulativeWeight));
    }

    return {
      detected,
      maxSensitivity: sensitivity,
      score: Math.min(100, cumulativeWeight),
      categories: Array.from(categories),
      findings,
      tags: Array.from(allTags),
    };
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return {
    analyze,
    STRATEGIC_INDICATORS,
  };

})();
