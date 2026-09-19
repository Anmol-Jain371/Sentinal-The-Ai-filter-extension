/**
 * SentinelX — Shannon Entropy & High-Density Character Analysis Engine
 *
 * Detects zero-day / custom secrets that regex cannot catch.
 * Uses information-theoretic Shannon entropy combined with character-set
 * density analysis to flag suspicious high-entropy tokens.
 *
 * H(X) = -Σ P(xi) * log2(P(xi))
 *
 * Threshold: H >= 4.2 with token length >= 12 characters
 */

'use strict';

window.SentinelXEntropy = (() => {

  // ------------------------------------------------------------------
  // Core Shannon Entropy Calculator
  // ------------------------------------------------------------------

  /**
   * Computes the Shannon entropy of a string.
   * @param {string} str
   * @returns {number} Entropy value in bits per character (0 to ~6)
   */
  function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;

    const freq = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  // ------------------------------------------------------------------
  // Character Set Density Analysis
  // ------------------------------------------------------------------

  const CHARSET = {
    lowercase:   /[a-z]/,
    uppercase:   /[A-Z]/,
    digits:      /[0-9]/,
    hex:         /[0-9a-fA-F]/,
    base64Extra: /[+/=]/,
    symbols:     /[!@#$%^&*()\-_+=\[\]{}|;:'",.<>?\/\\`~]/,
  };

  /**
   * Returns a density score 0–100 representing how many character classes
   * the token uses, weighted by security-relevance.
   * @param {string} token
   * @returns {number} Density score
   */
  function charDensityScore(token) {
    let score = 0;
    if (CHARSET.lowercase.test(token))   score += 20;
    if (CHARSET.uppercase.test(token))   score += 20;
    if (CHARSET.digits.test(token))      score += 20;
    if (CHARSET.symbols.test(token))     score += 25;
    if (CHARSET.base64Extra.test(token)) score += 15;
    return Math.min(100, score);
  }

  /**
   * Checks if the token looks like a Base64-encoded blob (common for encoded secrets).
   * @param {string} token
   * @returns {boolean}
   */
  function looksLikeBase64(token) {
    return /^[A-Za-z0-9+/]{20,}={0,2}$/.test(token) && token.length >= 20;
  }

  /**
   * Checks if token is pure hex (common for hashed tokens, OAuth secrets).
   * @param {string} token
   * @returns {boolean}
   */
  function looksLikeHex(token) {
    return /^[0-9a-fA-F]{24,}$/.test(token);
  }

  // ------------------------------------------------------------------
  // Token Extraction
  // ------------------------------------------------------------------

  /**
   * Splits text into candidate tokens for analysis.
   * Splits on whitespace, common delimiters, assignment operators.
   * @param {string} text
   * @returns {string[]}
   */
  function extractTokens(text) {
    // Split on spaces, newlines, tabs, =, :, ", ', `, ,, ;
    return text
      .split(/[\s=:"'`,;\[\]{}()\n\r\t]+/)
      .filter(t => t.length >= 12);  // Only analyze tokens >= 12 chars
  }

  // ------------------------------------------------------------------
  // High-Entropy Secret Detection
  // ------------------------------------------------------------------

  // Allow enterprise IT to override via managed policy (Intune / GPO)
  // Default: H >= 4.2 (matches the Python model's threshold)
  const ENTROPY_THRESHOLD = (
    window.__sentinelXManagedConfig && window.__sentinelXManagedConfig.shannonEntropyThreshold
  ) || 4.2;
  const MIN_TOKEN_LENGTH   = 12;
  const DENSITY_THRESHOLD  = 40;

  /**
   * Analyzes a single token to determine if it is a high-entropy secret.
   * @param {string} token
   * @returns {{ isSecret: boolean, entropy: number, density: number, reason: string }}
   */
  function analyzeToken(token) {
    if (token.length < MIN_TOKEN_LENGTH) {
      return { isSecret: false, entropy: 0, density: 0, reason: 'TOO_SHORT' };
    }

    const entropy = shannonEntropy(token);
    const density = charDensityScore(token);
    const isBase64 = looksLikeBase64(token);
    const isHex    = looksLikeHex(token);

    // High entropy + mixed character density = likely secret
    const isHighEntropy = entropy >= ENTROPY_THRESHOLD && density >= DENSITY_THRESHOLD;
    // Base64 blobs >= 32 chars are almost always encoded sensitive data
    const isEncodedBlob = isBase64 && token.length >= 32;
    // Pure hex strings 32+ chars are often hashes, tokens, UUIDs with sensitive binding
    const isHexSecret   = isHex && token.length >= 40;

    const isSecret = isHighEntropy || isEncodedBlob || isHexSecret;

    let reason = 'CLEAN';
    if (isHighEntropy)  reason = `HIGH_ENTROPY (H=${entropy.toFixed(2)}, Density=${density})`;
    if (isEncodedBlob)  reason = 'BASE64_ENCODED_BLOB';
    if (isHexSecret)    reason = 'HIGH_ENTROPY_HEX_TOKEN';

    return { isSecret, entropy: parseFloat(entropy.toFixed(3)), density, reason };
  }

  // ------------------------------------------------------------------
  // Full Text Analysis
  // ------------------------------------------------------------------

  /**
   * Analyzes full pasted/submitted text for high-entropy secrets.
   * @param {string} text — raw clipboard or form text
   * @returns {{
   *   hasSecrets: boolean,
   *   findings: Array<{ token: string, entropy: number, density: number, reason: string }>,
   *   maxEntropy: number
   * }}
   */
  function analyzeText(text) {
    if (!text || text.trim().length === 0) {
      return { hasSecrets: false, findings: [], maxEntropy: 0 };
    }

    const tokens = extractTokens(text);
    const findings = [];
    let maxEntropy = 0;

    for (const token of tokens) {
      const result = analyzeToken(token);
      if (result.entropy > maxEntropy) maxEntropy = result.entropy;

      if (result.isSecret) {
        findings.push({
          token: token.substring(0, 6) + '***',  // Never expose the full token in analysis results
          entropy: result.entropy,
          density: result.density,
          reason: result.reason,
          length: token.length,
        });
      }
    }

    return {
      hasSecrets: findings.length > 0,
      findings,
      maxEntropy: parseFloat(maxEntropy.toFixed(3)),
    };
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return {
    shannonEntropy,
    analyzeText,
    analyzeToken,
    looksLikeBase64,
    looksLikeHex,
    ENTROPY_THRESHOLD,
  };

})();
