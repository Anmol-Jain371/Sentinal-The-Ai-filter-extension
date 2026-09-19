/**
 * SentinelX — Contextual Risk Scoring Engine
 *
 * Computes the 0–100 Exposure Risk Score from five factors:
 *
 *   Risk = min(100, ws·S + wd·D + wv·V + wa·A + wc·C)
 *
 *   S = Data Sensitivity     (0–100)  weight: 0.40
 *   D = Destination Risk     (0–100)  weight: 0.25
 *   V = Data Volume          (0–100)  weight: 0.15
 *   A = Action Vector        (0–100)  weight: 0.10
 *   C = Context Risk         (0–100)  weight: 0.10
 *
 * Decision boundaries:
 *   0  – 25 → ALLOW  (green)
 *   26 – 59 → WARN   (amber)
 *   60 – 100 → BLOCK (red)
 */

'use strict';

window.SentinelXRiskEngine = (() => {

  // ------------------------------------------------------------------
  // Scoring Weights
  // ------------------------------------------------------------------

  const WEIGHTS = {
    sensitivity:  0.40,
    destination:  0.25,
    volume:       0.15,
    action:       0.10,
    context:      0.10,
  };

  // ------------------------------------------------------------------
  // Sensitivity Score (from detection results)
  // ------------------------------------------------------------------

  /**
   * Maps detected data categories to sensitivity scores.
   * Uses the maximum sensitivity across all detected findings.
   * Now also incorporates the ML classifier's probability score.
   * @param {object} deterministicResult  — from SentinelXDeterministic.analyze()
   * @param {object} entropyResult        — from SentinelXEntropy.analyzeText()
   * @param {object} [semanticResult]     — from SentinelXSemantic.analyze()
   * @param {object} [mlResult]           — from SentinelXClassifier.classify()
   * @returns {number} 0–100
   */
  function computeSensitivityScore(deterministicResult, entropyResult, semanticResult, mlResult) {
    let score = 0;

    // Use the max sensitivity from deterministic findings
    if (deterministicResult && deterministicResult.detected) {
      score = Math.max(score, deterministicResult.maxSensitivity);
    }

    // Semantic / corporate narrative findings
    if (semanticResult && semanticResult.detected) {
      score = Math.max(score, semanticResult.maxSensitivity);
    }

    // High-entropy secrets = critical
    if (entropyResult && entropyResult.hasSecrets) {
      const entropyScore = Math.min(100, 70 + (entropyResult.findings.length * 10));
      score = Math.max(score, entropyScore);
    }

    // ML Classifier — augments sensitivity when it fires with meaningful confidence.
    // Only applies when HIGH or MEDIUM confidence to avoid false positive inflation.
    if (mlResult && mlResult.sensitive && mlResult.confidence !== 'LOW') {
      score = Math.max(score, mlResult.sensitivityScore);
    }

    return score;
  }

  // ------------------------------------------------------------------
  // Volume Score (logarithmic scale)
  // ------------------------------------------------------------------

  /**
   * Converts text length into a logarithmic volume risk score.
   * Small paste: low volume risk. Bulk dump: high volume risk.
   * @param {number} textLength — character count
   * @returns {number} 0–100
   */
  function computeVolumeScore(textLength) {
    if (textLength <= 100)    return 10;   // Quick short snippet
    if (textLength <= 500)    return 25;
    if (textLength <= 2000)   return 45;
    if (textLength <= 5000)   return 65;
    if (textLength <= 20000)  return 80;
    return 95;                             // Bulk dump
  }

  // ------------------------------------------------------------------
  // Action Vector Score
  // ------------------------------------------------------------------

  const ACTION_SCORES = {
    'paste':        70,
    'form_submit':  60,
    'file_upload':  85,
    'drag_drop':    75,
    'input':        50,
    'unknown':      55,
  };

  function computeActionScore(actionType) {
    return ACTION_SCORES[actionType] || ACTION_SCORES.unknown;
  }

  // ------------------------------------------------------------------
  // Context Risk Score (cross-correlation)
  // ------------------------------------------------------------------

  /**
   * Evaluates the specific risk multiplier based on destination + data type.
   * e.g., Credentials to External AI = critical risk multiplier.
   * @param {string} destinationTier
   * @param {string[]} categories
   * @returns {number} 0–100
   */
  function computeContextScore(destinationTier, categories) {
    let score = 30; // Baseline neutral context

    const isExternal = ['EXTERNAL_AI', 'UNKNOWN_SAAS', 'SUSPICIOUS'].includes(destinationTier);
    const hasCreds   = categories.includes('CREDENTIAL');
    const hasPII     = categories.includes('PII');
    const hasFin     = categories.includes('FINANCIAL') || categories.includes('FINANCIAL_PROJECTION');
    const hasStrat   = categories.includes('STRATEGIC_BUSINESS') || categories.includes('CONFIDENTIAL_PROJECT');

    // High-risk combinations
    if (isExternal && hasCreds) {
      score = 100; // Critical policy violation
    } else if (isExternal && (hasFin || hasStrat)) {
      score = 90;
    } else if (isExternal && hasPII) {
      score = 80;
    } else if (destinationTier === 'SUSPICIOUS') {
      score = 95;
    }
    // Approved tools lower contextual risk
    else if (['INTERNAL', 'APPROVED_AI'].includes(destinationTier)) {
      score = 20;
    }

    return score;
  }

  // ------------------------------------------------------------------
  // Decision Mapping
  // ------------------------------------------------------------------

  /**
   * Maps a numeric risk score to a ALLOW / WARN / BLOCK decision.
   * @param {number} score
   * @returns {{ decision: string, color: string, icon: string, label: string }}
   */
  function scoreToDecision(score) {
    if (score <= 25) {
      return {
        decision: 'ALLOW',
        color:    '#00E5A0',
        bgColor:  '#05281E',
        icon:     '+',
        label:    'Safe to Send',
      };
    } else if (score <= 59) {
      return {
        decision: 'WARN',
        color:    '#F5A623',
        bgColor:  '#2E1E05',
        icon:     '!',
        label:    'Proceed with Caution',
      };
    } else {
      return {
        decision: 'BLOCK',
        color:    '#FF3D5A',
        bgColor:  '#2E080F',
        icon:     'X',
        label:    'Action Blocked',
      };
    }
  }

  // ------------------------------------------------------------------
  // Master Risk Calculator
  // ------------------------------------------------------------------

  /**
   * Computes the full contextual risk assessment.
   * @param {{
   *   deterministicResult: object,
   *   entropyResult: object,
   *   semanticResult?: object,
   *   destinationResult: object,
   *   textLength: number,
   *   actionType: string
   * }} params
   * @returns {{
   *   score: number,
   *   decision: string,
   *   color: string,
   *   breakdown: object,
   *   factors: object
   * }}
   */
  function calculate(params) {
    const { deterministicResult, entropyResult, semanticResult, mlResult, destinationResult, textLength, actionType } = params;

    const S = computeSensitivityScore(deterministicResult, entropyResult, semanticResult, mlResult);
    const D = destinationResult.score;
    const V = computeVolumeScore(textLength);
    const A = computeActionScore(actionType);

    const allCategories = [
      ...(deterministicResult ? (deterministicResult.categories || []) : []),
      ...(semanticResult ? (semanticResult.categories || []) : []),
    ];

    const C = computeContextScore(destinationResult.tier, allCategories);

    let rawScore = 0;
    // If no sensitive data is detected at all (S === 0), the paste is benign.
    // Exfiltration risk requires sensitive content; scale environmental factors to baseline ALLOW (<= 15).
    if (S === 0) {
      rawScore = Math.min(10, Math.round(0.04 * D + 0.05 * V));
    } else {
      rawScore =
        WEIGHTS.sensitivity * S +
        WEIGHTS.destination * D +
        WEIGHTS.volume      * V +
        WEIGHTS.action      * A +
        WEIGHTS.context     * C;
    }

    const score = Math.min(100, Math.round(rawScore));
    const decision = scoreToDecision(score);

    return {
      score,
      ...decision,
      factors: { S, D, V, A, C },
      breakdown: {
        'Data Sensitivity':  `${S}/100 × ${WEIGHTS.sensitivity}`,
        'Destination Risk':  `${D}/100 × ${WEIGHTS.destination}`,
        'Data Volume':       `${V}/100 × ${WEIGHTS.volume}`,
        'Action Vector':     `${A}/100 × ${WEIGHTS.action}`,
        'Context Risk':      `${C}/100 × ${WEIGHTS.context}`,
        'Final Score':       `${score}/100`,
      },
    };
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return {
    calculate,
    scoreToDecision,
    computeVolumeScore,
    WEIGHTS,
  };

})();
