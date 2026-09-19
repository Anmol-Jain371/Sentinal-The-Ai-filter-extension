/**
 * SentinelX — Content Script: Capture-Phase Paste & Input Monitor
 *
 * This is the entry point for all browser event interception.
 * Uses capture-phase event listeners (passive: false) to intercept
 * paste events BEFORE they reach the host page's React/Slate/Draft.js handlers.
 *
 * Pipeline:
 *   1. Capture paste event
 *   2. Extract clipboard text
 *   3. Run detection pipeline (< 5ms target)
 *   4. Build risk assessment
 *   5. Evaluate policy
 *   6. Show HUD (if needed)
 *   7. Execute action: ALLOW / WARN / BLOCK / REDACT
 *
 * For REDACT: cancels original paste and injects sanitized text programmatically
 * For BLOCK:  cancels paste event entirely
 * For ALLOW:  does nothing — paste proceeds normally
 */

'use strict';

(function initSentinelXMonitor() {

  // Guard: Don't initialize in iframes (only top-level page)
  if (window.self !== window.top) return;

  // Guard: Don't double-initialize
  if (window.__sentinelXActive) return;
  window.__sentinelXActive = true;

  // ------------------------------------------------------------------
  // Detection Pipeline
  // ------------------------------------------------------------------

  /**
   * Runs the full SentinelX analysis pipeline on intercepted text.
   * Designed to complete in under 5ms for typical inputs.
   *
   * @param {string} text — raw clipboard or sampled file text
   * @param {HTMLElement} [targetElement] — target DOM element
   * @param {string} [actionType='paste'] — 'paste' | 'file_upload' | 'drag_drop'
   * @returns {object} Full analysis result
   */
  function runPipeline(text, targetElement, actionType = 'paste') {
    const t0 = performance.now();

    // 1. Deterministic detection
    const deterministicResult = window.SentinelXDeterministic.analyze(text);

    // 2. Shannon entropy analysis
    const entropyResult = window.SentinelXEntropy.analyzeText(text);

    // 3. Semantic / corporate narrative detection
    const semanticResult = window.SentinelXSemantic
      ? window.SentinelXSemantic.analyze(text)
      : { detected: false, maxSensitivity: 0, score: 0, categories: [], findings: [], tags: [] };

    // 4. ML Classifier (client-side TF-IDF + Logistic Regression, zero-plaintext)
    const mlResult = window.SentinelXClassifier
      ? window.SentinelXClassifier.classify(text)
      : { probability: 0, sensitive: false, confidence: 'LOW', sensitivityScore: 0, topFeatures: [] };

    // 5. Destination classification
    const destinationResult = window.SentinelXDestination.classifyCurrentPage(targetElement);

    // 6. Risk scoring (incorporates all 4 detection signals)
    const riskResult = window.SentinelXRiskEngine.calculate({
      deterministicResult,
      entropyResult,
      semanticResult,
      mlResult,
      destinationResult,
      textLength: text.length,
      actionType,
    });

    // 7. Policy evaluation
    const detectedTags = [
      ...deterministicResult.findings.flatMap(f => f.tags || []),
      ...(semanticResult.tags || []),
      ...(mlResult.sensitive && mlResult.topFeatures.length > 0 ? ['ML_SENSITIVE'] : []),
    ];
    const allCategories = [
      ...deterministicResult.categories,
      ...semanticResult.categories,
    ];

    const policyResult = window.SentinelXPolicyEngine.evaluate({
      detectedCategories: allCategories,
      detectedTags,
      destinationTier: destinationResult.tier,
      riskScore: riskResult.score,
      riskDecision: riskResult.decision,
    });

    const latency = performance.now() - t0;

    console.debug(
      `[SentinelX] Pipeline complete in ${latency.toFixed(2)}ms | ` +
      `Risk: ${riskResult.score}/100 | Decision: ${policyResult.finalDecision} | ` +
      `ML: P=${mlResult.probability.toFixed(3)} (${mlResult.confidence})`
    );

    return {
      rawText: text,
      textLength: text.length,
      deterministicResult,
      entropyResult,
      semanticResult,
      mlResult,
      destinationResult,
      riskResult,
      policyResult,
      latencyMs: parseFloat(latency.toFixed(2)),
    };
  }


  // ------------------------------------------------------------------
  // Smart Redact & Re-Insert
  // ------------------------------------------------------------------

  /**
   * Inserts sanitized (redacted) text into the focused element.
   * Compatible with:
   *   - Standard <textarea> / <input>
   *   - contenteditable divs (React, Slate, Draft.js, ProseMirror)
   *
   * @param {string} sanitizedText — redacted text to insert
   * @param {Element} targetElement — the element that was pasted into
   */
  function insertRedactedText(sanitizedText, targetElement) {
    if (!targetElement) {
      targetElement = document.activeElement;
    }
    if (!targetElement) return;

    // Set guard to prevent re-interception of our own insertion
    window.__sx_redacting = true;
    try {
      _doInsert(sanitizedText, targetElement);
    } finally {
      // Clear guard after a short delay (enough for event dispatch to complete)
      setTimeout(() => { window.__sx_redacting = false; }, 80);
    }
  }

  function _doInsert(sanitizedText, targetElement) {
    const isContentEditable = targetElement.isContentEditable || targetElement.contentEditable === 'true';
    const isInputOrTextarea = targetElement.tagName === 'TEXTAREA' || targetElement.tagName === 'INPUT';

    if (isInputOrTextarea) {
      try {
        const start = targetElement.selectionStart !== null && targetElement.selectionStart !== undefined
          ? targetElement.selectionStart
          : (targetElement.value || '').length;
        const end = targetElement.selectionEnd !== null && targetElement.selectionEnd !== undefined
          ? targetElement.selectionEnd
          : start;
        const current = targetElement.value || '';
        targetElement.value = current.slice(0, start) + sanitizedText + current.slice(end);
        targetElement.selectionStart = targetElement.selectionEnd = start + sanitizedText.length;

        // Correct prototype setter per element type (prevents Illegal invocation)
        const proto = targetElement.tagName === 'INPUT'
          ? window.HTMLInputElement.prototype
          : window.HTMLTextAreaElement.prototype;
        const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
        if (descriptor && descriptor.set) {
          descriptor.set.call(targetElement, targetElement.value);
        }
      } catch (err) {
        try { targetElement.value = sanitizedText; } catch (_) {}
      }

      try {
        targetElement.dispatchEvent(new Event('input', { bubbles: true }));
        targetElement.dispatchEvent(new Event('change', { bubbles: true }));
      } catch (_) {}

    } else if (isContentEditable) {
      targetElement.focus();
      let inserted = false;
      try {
        inserted = document.execCommand('insertText', false, sanitizedText);
      } catch (_) {
        inserted = false;
      }

      if (!inserted) {
        try {
          const selection = window.getSelection();
          if (selection && selection.rangeCount > 0) {
            const range = selection.getRangeAt(0);
            range.deleteContents();
            const textNode = document.createTextNode(sanitizedText);
            range.insertNode(textNode);
            range.setStartAfter(textNode);
            range.collapse(true);
            selection.removeAllRanges();
            selection.addRange(range);
          } else {
            targetElement.textContent = (targetElement.textContent || '') + sanitizedText;
          }
        } catch (_) {
          targetElement.innerText = sanitizedText;
        }
      }

      try {
        targetElement.dispatchEvent(new InputEvent('input', {
          bubbles: true,
          cancelable: true,
          inputType: 'insertText',
          data: sanitizedText,
        }));
      } catch (_) {}
    }
  }

  // ------------------------------------------------------------------
  // Telemetry Relay (to background service worker)
  // ------------------------------------------------------------------

  function sendTelemetry(analysis) {
    try {
      const payload = window.SentinelXHUD.buildTelemetryPayload(analysis);
      chrome.runtime.sendMessage({
        type: 'SENTINEL_EVENT',
        payload,
      });
    } catch (e) {
      // Extension context may be invalidated — ignore silently
    }
  }

  // ------------------------------------------------------------------
  // Main Paste Handler
  // ------------------------------------------------------------------

  async function handlePaste(event) {
    // Skip if we are inserting our own redacted text (avoid re-interception loop)
    if (window.__sx_redacting) return;

    // Skip if not a user-initiated paste or no clipboard data
    const clipboardData = event.clipboardData;
    if (!clipboardData) return;

    const text = clipboardData.getData('text/plain');
    if (!text || text.trim().length === 0) return;

    const targetElement = event.target;

    // Run the synchronous detection pipeline FIRST (before any preventDefault)
    const analysis = runPipeline(text, targetElement);
    const decision = analysis.policyResult.finalDecision;

    // Update extension badge
    try {
      chrome.runtime.sendMessage({
        type: 'UPDATE_BADGE',
        decision,
      });
    } catch { /* ignore */ }

    // ── ALLOW: Let browser handle it natively — no interception needed ──
    if (decision === 'ALLOW') {
      sendTelemetry(analysis);
      return; // paste proceeds naturally, don't preventDefault
    }

    // ── WARN / BLOCK: Cancel the event first, then show HUD ────────────
    event.preventDefault();
    event.stopImmediatePropagation();

    let userAction;
    try {
      userAction = await window.SentinelXHUD.show(analysis, event);
    } catch (e) {
      console.error('[SentinelX] HUD error:', e);
      // NEVER fail open on BLOCK decisions! Keep sensitive data secure!
      if (decision === 'BLOCK') {
        console.warn('[SentinelX] Blocked exfiltration attempt quarantined.');
        return;
      }
      insertRedactedText(text, targetElement);
      return;
    }

    sendTelemetry(analysis);

    switch (userAction) {
      case 'ALLOW':
      case 'CONTINUE': {
        // Only WARN actions can be acknowledged with continue; BLOCK is non-negotiable
        if (decision === 'BLOCK') {
          console.warn('[SentinelX] Blocked payload cannot be transmitted.');
          break;
        }
        insertRedactedText(text, targetElement);
        break;
      }
      case 'REDACT': {
        // Smart redact and paste sanitized version
        const { redacted, replacements } = window.SentinelXRedactor.redact(text);
        insertRedactedText(redacted, targetElement);
        console.info(
          `[SentinelX] Redacted ${replacements.length} sensitive item(s):`,
          window.SentinelXRedactor.summarizeReplacements(replacements)
        );
        break;
      }
      case 'CANCEL':
      default: {
        // Do nothing — paste is cancelled
        break;
      }
    }
  }

  // ------------------------------------------------------------------
  // File Upload & Drag-and-Drop DLP Interceptor
  // ------------------------------------------------------------------

  const RESTRICTED_EXTENSIONS = new Set([
    '.env', '.pem', '.key', '.pkcs12', '.pfx', '.id_rsa', '.id_ed25519', '.kdbx', '.credentials', '.cert'
  ]);

  async function inspectAndInterceptFile(file, targetElement, event, actionType = 'file_upload') {
    if (!file) return;

    const destinationResult = window.SentinelXDestination.classifyCurrentPage(targetElement);
    const isExternal = ['EXTERNAL_AI', 'UNKNOWN_SAAS', 'SUSPICIOUS'].includes(destinationResult.tier);

    // 1. Immediate file extension quarantine check
    const fileName = (file.name || '').toLowerCase();
    const ext = fileName.includes('.') ? fileName.substring(fileName.lastIndexOf('.')) : '';

    if (RESTRICTED_EXTENSIONS.has(ext) && isExternal) {
      event.preventDefault();
      event.stopImmediatePropagation();

      const analysis = {
        rawText: `[Restricted File: ${file.name}]`,
        textLength: file.size,
        deterministicResult: {
          detected: true,
          categories: ['CREDENTIAL'],
          maxSensitivity: 100,
          findings: [{ detector: 'FILE_EXTENSION', label: `Sensitive File (${file.name})`, category: 'CREDENTIAL', sensitivity: 100, tags: ['FILE_TRANSFER', 'KEY_FILE', 'CREDENTIAL'], count: 1 }],
        },
        entropyResult: { hasSecrets: false, findings: [] },
        semanticResult: { detected: false, maxSensitivity: 0, categories: [], findings: [], tags: [] },
        destinationResult,
        riskResult: { score: 100, decision: 'BLOCK', factors: { S: 100, D: destinationResult.score, V: 80, A: 85, C: 100 } },
        policyResult: { finalDecision: 'BLOCK', reason: `High-risk file extension (${ext}) blocked from external upload.` },
        latencyMs: 1.0,
      };

      try {
        await window.SentinelXHUD.show(analysis, event);
      } catch (e) {
        console.error('[SentinelX] HUD error on file drop:', e);
      }
      sendTelemetry(analysis);
      return;
    }

    // 2. Sample content inspection for text/code/csv files
    const textLike = /\.(txt|csv|json|py|js|ts|sql|yaml|yml|sh|md|env)$/i.test(fileName) || (file.type && file.type.startsWith('text/'));
    if (textLike && file.size > 0 && isExternal) {
      try {
        const slice = file.slice(0, 65536);
        const sampleText = await slice.text();

        if (sampleText && sampleText.trim().length > 0) {
          const analysis = runPipeline(sampleText, targetElement, actionType);
          const decision = analysis.policyResult.finalDecision;

          if (decision === 'BLOCK' || decision === 'WARN') {
            event.preventDefault();
            event.stopImmediatePropagation();

            // Override label with filename
            analysis.rawText = `[File: ${file.name}]`;
            let userAction = 'CANCEL';
            try {
              userAction = await window.SentinelXHUD.show(analysis, event);
            } catch (e) {
              console.error('[SentinelX] HUD error on file content:', e);
            }

            sendTelemetry(analysis);

            if (userAction === 'CANCEL' || decision === 'BLOCK') {
              if (targetElement && targetElement.tagName === 'INPUT' && targetElement.type === 'file') {
                targetElement.value = '';
              }
            }
          }
        }
      } catch (e) {
        // Ignore read errors
      }
    }
  }

  // Handle Drag-and-Drop files
  async function handleDrop(event) {
    if (!event.dataTransfer || !event.dataTransfer.files || event.dataTransfer.files.length === 0) return;
    const file = event.dataTransfer.files[0];
    await inspectAndInterceptFile(file, event.target, event, 'drag_drop');
  }

  // Handle <input type="file"> selection
  async function handleFileInput(event) {
    const target = event.target;
    if (!target || target.type !== 'file' || !target.files || target.files.length === 0) return;
    const file = target.files[0];
    await inspectAndInterceptFile(file, target, event, 'file_upload');
  }

  // ------------------------------------------------------------------
  // Sliding-Window Keystroke & Submission DLP Interceptor
  // ------------------------------------------------------------------

  let typingDebounceTimer = null;
  const inspectedElements = new WeakSet();

  function getElementText(el) {
    if (!el) return '';
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
      return el.value || '';
    }
    if (el.isContentEditable || el.getAttribute('contenteditable') === 'true') {
      return el.innerText || el.textContent || '';
    }
    return '';
  }

  async function interceptTypingSubmission(target, event) {
    const text = getElementText(target);
    if (!text || text.trim().length < 8) return;

    const destinationResult = window.SentinelXDestination.classifyCurrentPage(target);
    if (destinationResult.tier === 'INTERNAL') return;

    // Run pipeline
    const analysis = runPipeline(text, target, 'keystroke_typing');
    const decision = analysis.policyResult.finalDecision;

    if (decision === 'BLOCK' || (decision === 'WARN' && analysis.riskResult.score >= 70)) {
      event.preventDefault();
      event.stopImmediatePropagation();

      let userAction;
      try {
        userAction = await window.SentinelXHUD.show(analysis, event);
      } catch (e) {
        console.error('[SentinelX] HUD error on typing interception:', e);
        return;
      }

      sendTelemetry(analysis);

      if (userAction === 'REDACT') {
        const { redacted } = window.SentinelXRedactor.redact(text);
        insertRedactedText(redacted, target);
      } else if (userAction === 'CANCEL' || decision === 'BLOCK') {
        // Clear or leave unsubmitted
      }
    }
  }

  function handleKeydown(event) {
    // Intercept Enter key submissions on external prompts
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      const target = event.target;
      if (target && (target.tagName === 'TEXTAREA' || target.tagName === 'INPUT' || target.isContentEditable)) {
        interceptTypingSubmission(target, event);
      }
    }
  }

  // ------------------------------------------------------------------
  // Event Registration
  // ------------------------------------------------------------------

  // Capture phase (true) ensures we intercept BEFORE host page handlers
  window.addEventListener('paste', handlePaste, {
    capture: true,
    passive: false,
  });

  document.addEventListener('paste', handlePaste, {
    capture: true,
    passive: false,
  });

  document.addEventListener('drop', handleDrop, {
    capture: true,
    passive: false,
  });

  document.addEventListener('change', handleFileInput, {
    capture: true,
    passive: false,
  });

  document.addEventListener('keydown', handleKeydown, {
    capture: true,
    passive: false,
  });

  console.info('[SentinelX] Shield active on', window.location.hostname);

})();
