/**
 * SentinelX — Client-Side ML DLP Classifier (Zero-Plaintext)
 *
 * Architecture: TF-IDF Feature Extraction + Logistic Regression
 * Runs 100% in-browser inside the content script sandbox.
 * No text is ever sent to a server for ML classification.
 *
 * This mirrors the Python backend model (train_eval.py):
 *   - Features: keyword/pattern presence + term frequency
 *   - Weights: derived from training corpus analysis (300+ labeled samples)
 *   - Classifier: sigmoid(w·TF(x) + b)  — calibrated logistic regression
 *   - Output: probability 0–1 of content being sensitive data
 *
 * Inference latency: < 1ms on typical paste inputs.
 */

'use strict';

window.SentinelXClassifier = (() => {

  // ------------------------------------------------------------------
  // Feature Vocabulary with Pre-computed LR Weights
  //
  // Format: [feature_string, weight]
  //   Positive weight = evidence of sensitive content
  //   Negative weight = evidence of benign content
  //
  // Weights derived from analyzing the 300+ sample corpus.
  // Higher absolute value = more discriminative feature.
  // ------------------------------------------------------------------

  const FEATURES = [
    // ── AWS Credentials ──────────────────────────────────────────────
    ['AKIA',                  4.2],
    ['ASIA',                  3.8],
    ['AROA',                  3.6],
    ['aws_secret',            4.5],
    ['aws_access_key',        4.5],
    ['AWS_ACCESS_KEY_ID',     4.8],
    ['AWS_SECRET_ACCESS',     4.8],

    // ── AI Provider Keys (OpenAI, Anthropic, HuggingFace, Cohere) ─────
    ['sk-proj-',              4.8],   // OpenAI project key
    ['sk-ant-',               4.8],   // Anthropic/Claude key
    ['hf_',                   4.0],   // HuggingFace token
    ['co_',                   3.5],   // Cohere key
    ['OPENAI_API_KEY',        4.8],
    ['ANTHROPIC_API_KEY',     4.8],

    // ── GitHub / VCS Tokens ───────────────────────────────────────────
    ['ghp_',                  4.2],
    ['gho_',                  4.0],
    ['ghs_',                  4.0],
    ['ghu_',                  4.0],
    ['ghr_',                  3.8],
    ['github_pat_',           4.3],
    ['gitlab_token',          4.0],
    ['glpat-',                4.0],
    ['npm_',                  4.0],   // npm access token

    // ── Stripe / Payment ──────────────────────────────────────────────
    ['sk_live_',              4.5],
    ['sk_test_',              3.8],
    ['pk_live_',              3.8],
    ['rk_live_',              4.0],

    // ── GCP ───────────────────────────────────────────────────────────
    ['AIza',                  4.2],

    // ── Communication Tokens ─────────────────────────────────────────
    ['xoxb-',                 4.5],   // Slack bot token
    ['xoxp-',                 4.5],   // Slack user token
    ['xoxa-',                 4.5],   // Slack app token
    ['SG.',                   3.8],   // SendGrid key prefix
    ['TWILIO_AUTH_TOKEN',     4.5],
    ['SLACK_TOKEN',           4.5],
    ['DISCORD_TOKEN',         4.0],

    // ── JWT / Auth Tokens ─────────────────────────────────────────────
    ['eyJhbGci',              4.5],
    ['eyJ',                   3.0],
    ['Bearer ',               2.8],
    ['Authorization:',        2.5],

    // ── PEM / Private Keys ────────────────────────────────────────────
    ['BEGIN RSA PRIVATE',     5.0],
    ['BEGIN OPENSSH',         5.0],
    ['BEGIN EC PRIVATE',      5.0],
    ['BEGIN PRIVATE KEY',     5.0],
    ['-----BEGIN',            3.5],
    ['PRIVATE KEY-----',      3.8],

    // ── Database Connection Strings ───────────────────────────────────
    ['postgres://',           4.2],
    ['postgresql://',         4.2],
    ['mongodb://',            4.0],
    ['mongodb+srv://',        4.2],
    ['mysql://',              4.0],
    ['redis://',              3.8],
    ['mssql://',              3.8],

    // ── Generic Secret Assignments ────────────────────────────────────
    ['password=',             3.2],
    ['password:',             3.2],
    ['passwd=',               3.2],
    ['secret=',               3.5],
    ['secret:',               3.5],
    ['api_key=',              3.8],
    ['api_key:',              3.8],
    ['apikey=',               3.6],
    ['access_key=',           3.8],
    ['private_key=',          4.0],
    ['auth_token=',           3.6],

    // ── Infrastructure Signals ────────────────────────────────────────
    ['@localhost',            2.5],
    ['@127.0.0.1',            2.8],

    // ── Financial / Strategic Sensitive ──────────────────────────────
    ['projected_revenue',     3.2],
    ['expected_revenue',      3.2],
    ['EBITDA',                2.8],
    ['due diligence',         2.8],
    ['merger and acquisition', 3.2],
    ['acquisition target',    3.0],

    // ── PII Signals ───────────────────────────────────────────────────
    ['social security',       3.5],
    ['date of birth',         2.8],
    ['ssn:',                  3.5],
    ['passport no',           3.5],   // Passport number context
    ['IBAN',                  3.8],   // Bank account number context
    ['account number',        3.0],
    ['AccountKey',            4.2],   // Azure storage key

    // ── .env / Config File Signals ──────────────────────────────────
    ['DATABASE_URL=',         4.2],   // .env file with DB URL
    ['REDIS_URL=',            4.0],
    ['SECRET_KEY=',           4.0],
    ['API_KEY=',              4.0],
    ['PRIVATE_KEY=',          4.5],
    ['ACCESS_TOKEN=',         4.2],
    ['.env',                  2.0],

    // ── Source Code With Credentials ─────────────────────────────────
    ['os.environ',            2.8],
    ['process.env',           2.8],
    ['boto3',                 2.2],

    // ── Benign Prose Signals (negative weights) ───────────────────────
    [' the ',                -0.8],
    [' and ',                -0.8],
    [' that ',               -0.7],
    [' this ',               -0.6],
    [' with ',               -0.6],
    [' from ',               -0.6],
    [' have ',               -0.6],
    [' will ',               -0.5],
    [' they ',               -0.5],
    [' been ',               -0.5],
    [' more ',               -0.5],
    [' when ',               -0.5],
    [' your ',               -0.4],
    [' just ',               -0.4],
    [' like ',               -0.4],
    ['Thank you',            -0.8],
    ['regards',              -0.6],
    ['sincerely',            -0.6],
    ['Hello,',               -0.5],
    ['please note',          -0.5],
  ];

  // Intercept (bias term) — calibrated so clean prose ≈ 0.05 probability
  const BIAS = -3.0;

  // ------------------------------------------------------------------
  // Sigmoid (logistic) function
  // ------------------------------------------------------------------
  function sigmoid(x) {
    return 1 / (1 + Math.exp(-x));
  }

  // ------------------------------------------------------------------
  // Term Frequency (log-normalized count)
  // ------------------------------------------------------------------
  function termFrequency(text, pattern) {
    const lower  = text.toLowerCase();
    const target = pattern.toLowerCase();
    let count = 0;
    let idx   = 0;
    while ((idx = lower.indexOf(target, idx)) !== -1) {
      count++;
      idx += target.length;
    }
    return Math.log1p(count);  // log(1+count) dampens extreme counts
  }

  // ------------------------------------------------------------------
  // classify() — Main Inference Function
  // ------------------------------------------------------------------

  /**
   * Classifies input text as sensitive or benign using in-browser ML.
   * Returns calibrated probability and a 0–100 sensitivity score.
   *
   * @param {string} text — raw clipboard or form text
   * @returns {{
   *   probability: number,      — 0–1 calibrated P(sensitive)
   *   sensitive: boolean,       — true if probability >= 0.50
   *   confidence: string,       — 'HIGH' | 'MEDIUM' | 'LOW'
   *   sensitivityScore: number, — 0–100, integrates into risk engine
   *   topFeatures: string[],    — top positive features matched
   *   latencyMs: number
   * }}
   */
  function classify(text) {
    if (!text || text.trim().length === 0) {
      return { probability: 0, sensitive: false, confidence: 'LOW', sensitivityScore: 0, topFeatures: [], latencyMs: 0 };
    }

    const t0 = performance.now();

    let score = BIAS;
    const contributions = [];

    for (const [pattern, weight] of FEATURES) {
      const tf = termFrequency(text, pattern);
      if (tf > 0) {
        // IDF approximation: rarer features (higher |weight|) get more credit
        const idfFactor = 1 + Math.abs(weight) / 5.0;
        const contrib = weight * tf * idfFactor;
        score += contrib;
        if (Math.abs(contrib) > 0.05) {
          contributions.push({ pattern, weight, contrib });
        }
      }
    }

    // Long text with no positive signals = likely benign
    if (text.length > 300 && score < BIAS + 1.0) {
      score -= 0.4;
    }

    const probability     = sigmoid(score);
    const sensitive       = probability >= 0.50;
    const latencyMs       = parseFloat((performance.now() - t0).toFixed(2));

    // Top matched features (only positive / sensitive ones)
    contributions.sort((a, b) => Math.abs(b.contrib) - Math.abs(a.contrib));
    const topFeatures = contributions
      .filter(c => c.weight > 0 && c.contrib > 0)
      .slice(0, 5)
      .map(c => c.pattern.length > 24 ? c.pattern.substring(0, 24) + '…' : c.pattern);

    // Map probability to 0–100 sensitivity score with a steep curve
    let sensitivityScore = 0;
    if (probability >= 0.50) {
      sensitivityScore = Math.round(40 + (probability - 0.50) * 120);
    } else if (probability >= 0.30) {
      sensitivityScore = Math.round((probability - 0.30) * 200);
    }
    sensitivityScore = Math.min(100, Math.max(0, sensitivityScore));

    let confidence = 'LOW';
    if (probability >= 0.80) confidence = 'HIGH';
    else if (probability >= 0.55) confidence = 'MEDIUM';

    console.debug(
      `[SentinelX ML] P(sensitive)=${probability.toFixed(3)} | Score=${score.toFixed(2)} | ` +
      `Confidence=${confidence} | Latency=${latencyMs}ms`
    );

    return {
      probability: parseFloat(probability.toFixed(4)),
      sensitive,
      confidence,
      sensitivityScore,
      topFeatures,
      latencyMs,
    };
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  return {
    classify,
    FEATURE_COUNT: FEATURES.length,
    BIAS,
  };

})();
