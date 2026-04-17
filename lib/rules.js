/**
 * DeIDGuard – lib/rules.js
 * Rule-Based Review Engine  |  Version 1.2.0
 *
 * PURPOSE:
 *   Scans de-identified (or raw) text against locally stored rule packs and
 *   returns flagged matches with severity levels and human-readable messages.
 *
 * IMPORTANT DISCLAIMER:
 *   This is a pattern-matching review assistant only. It does NOT provide
 *   legal advice, compliance certification, or guaranteed regulatory review.
 *   Final review and judgment remain the user's responsibility.
 *
 * MODES (v1.2.0):
 *   - basic         : General-purpose flags (scope of practice, sensitive terms)
 *   - healthcare_pro: Healthcare-specific flags (clinical, lab, Rx language)
 *                     Now includes Texas RAIA (eff. Jan 1, 2026) AI disclosure rules
 *   - ftc_hipra     : FTC Health Breach Notification + HIPRA (Nov 2025) rules
 *                     for non-HIPAA health apps, wellness practitioners, coaches
 *   - custom        : User-defined rules stored in chrome.storage.local
 *
 * Rule Object Shape:
 * {
 *   id:       string   — unique identifier
 *   label:    string   — short display name
 *   pattern:  string   — regex pattern string (NOT a RegExp object, for storage serialization)
 *   flags:    string   — regex flags, e.g. 'gi'
 *   message:  string   — human-readable explanation shown to user
 *   severity: 'high' | 'medium' | 'low'
 * }
 *
 * Flag Result Object Shape:
 * {
 *   ruleId:   string
 *   label:    string
 *   message:  string
 *   severity: string
 *   matches:  string[]   — array of actual matched text snippets
 *   count:    number
 * }
 */

'use strict';

// ─── Storage Keys ─────────────────────────────────────────────────────────────

const RULE_STORAGE_KEYS = {
  basic:          'deidguard_rules_basic',
  healthcare_pro: 'deidguard_rules_healthcare_pro',
  ftc_hipra:      'deidguard_rules_ftc_hipra',   // v1.2.0
  custom:         'deidguard_rules_custom',
};

// ─── Fallback Seeded Rules ────────────────────────────────────────────────────
// These are used if storage is unavailable (e.g., first load before background
// seeding completes). They mirror the seeds in background.js.

const FALLBACK_RULES = {
  basic: [
    {
      id: 'b1',
      label: 'Diagnostic claim',
      pattern: '\\bdiagnos(e|es|ed|ing|is|tic)\\b',
      flags: 'gi',
      message: 'Contains diagnostic language. Verify this is appropriate context.',
      severity: 'high',
    },
    {
      id: 'b2',
      label: 'Treatment claim',
      pattern: '\\btreat(s|ed|ing|ment)?\\b',
      flags: 'gi',
      message: 'Contains treatment language. Review for appropriate framing.',
      severity: 'high',
    },
    {
      id: 'b3',
      label: 'Prescribe / Prescription',
      pattern: '\\bprescri(be|bes|bed|bing|ption|ptions)\\b',
      flags: 'gi',
      message: 'Contains prescribing language. Ensure scope-of-practice compliance.',
      severity: 'high',
    },
    {
      id: 'b4',
      label: 'Cure claim',
      pattern: '\\bcure(s|d|ing)?\\b',
      flags: 'gi',
      message: 'Contains cure language. This may violate FDA guidelines if used with a product or condition.',
      severity: 'high',
    },
    {
      id: 'b5',
      label: '"Patient" terminology',
      pattern: '\\bpatient(s)?\\b',
      flags: 'gi',
      message: '"Patient" implies a clinical relationship. Consider "client," "individual," or "person."',
      severity: 'medium',
    },
    {
      id: 'b6',
      label: 'Residual SSN-like pattern',
      pattern: '\\b\\d{3}[-\\s]\\d{2}[-\\s]\\d{4}\\b',
      flags: 'gi',
      message: 'Possible Social Security Number pattern remains in text.',
      severity: 'high',
    },
  ],
  healthcare_pro: [
    {
      id: 'h1',
      label: 'Lab interpretation',
      pattern: '\\blab\\s+(result|value|interpret|review|finding)\\b',
      flags: 'gi',
      message: 'Lab interpretation language may imply clinical lab services. Use "educational lab contextualization."',
      severity: 'medium',
    },
    {
      id: 'h2',
      label: 'Clinical qualifier',
      pattern: '\\bclinical(ly)?\\b',
      flags: 'gi',
      message: '"Clinical" language may imply a licensed clinical service. Consider "educational" or "functional."',
      severity: 'medium',
    },
    {
      id: 'h3',
      label: 'HIPAA reference',
      pattern: '\\bHIPAA\\b',
      flags: 'gi',
      message: 'HIPAA reference detected. Verify applicability — not all health professionals are HIPAA Covered Entities.',
      severity: 'medium',
    },
    {
      id: 'h4',
      label: 'Drug interaction claim',
      pattern: '\\b(drug\\s+interaction|contraindication)s?\\b',
      flags: 'gi',
      message: 'Drug interaction or contraindication language. Verify clinical vs. educational context.',
      severity: 'medium',
    },
    {
      id: 'h5',
      label: 'Medication adjustment advice',
      pattern: '\\b(stop|start|increase|decrease|taper|adjust)\\s+(your\\s+)?(medication|dose|dosage|drug|med)\\b',
      flags: 'gi',
      message: 'Medication adjustment language detected. This may exceed non-prescriber scope of practice.',
      severity: 'high',
    },
    {
      id: 'h6',
      label: 'Disease reversal claim',
      pattern: '\\b(reverse|reversal|reversed)\\b',
      flags: 'gi',
      message: '"Reverse" disease claims may violate FDA guidelines. Use "support" or "improve" instead.',
      severity: 'high',
    },
    {
      id: 'h7',
      label: '"Appointment" language',
      pattern: '\\bappointment(s)?\\b',
      flags: 'gi',
      message: '"Appointment" implies a clinical visit. Consider "session" or "clarity call."',
      severity: 'low',
    },
    {
      id: 'h8',
      label: 'Guarantee language',
      pattern: '\\b(guarantee(d|s)?|promise(d|s)?|ensur(e|es|ed))\\b',
      flags: 'gi',
      message: 'Guarantee language in health context may violate FTC requirements. Results must include appropriate caveats.',
      severity: 'medium',
    },
    {
      id: 'h9',
      label: 'Diagnose (verb form)',
      pattern: '\\bdiagnos(e|es|ed|ing|is|tic)\\b',
      flags: 'gi',
      message: 'Diagnostic language detected. Review for appropriate scope.',
      severity: 'high',
    },
    {
      id: 'h10',
      label: 'Prescription drug reference',
      pattern: '\\b(Rx|prescription[-\\s]?only|prescription[-\\s]?drug)\\b',
      flags: 'gi',
      message: 'Prescription drug reference. Verify appropriate framing for non-prescribing context.',
      severity: 'medium',
    },
    {
      id: 'h11',
      label: 'Cure claim',
      pattern: '\\bcure(s|d|ing)?\\b',
      flags: 'gi',
      message: '"Cure" language may violate FDA DSHEA guidelines. Use "support" or "promote" instead.',
      severity: 'high',
    },
    {
      id: 'h12',
      label: 'Prevent disease claim',
      pattern: '\\bpreven(t|ts|ted|ting|tion)\\b',
      flags: 'gi',
      message: '"Prevent" disease claims require FDA review. Use "reduce the risk of" or "support" instead.',
      severity: 'high',
    },
    // ── Texas Responsible AI Governance Act (eff. Jan 1, 2026) ──
    // Requires disclosure when AI supports healthcare decisions.
    // Prohibits AI from independently diagnosing or making treatment decisions
    // without clinician review. These rules flag language that may imply
    // autonomous AI clinical decision-making without that disclosure.
    {
      id: 'tx1',
      label: 'Texas RAIA — AI decision without disclosure',
      pattern: '\\b(?:AI|artificial intelligence|algorithm|model|machine learning|ML)\\s+(?:determined|found|diagnosed|recommends?|suggests?|advises?|concludes?|identifies?|detects?)\\b',
      flags: 'gi',
      message: 'Texas RAIA (eff. Jan 1 2026): Content implying AI made a clinical determination without human oversight. Add: "This AI-assisted assessment was reviewed and approved by [Clinician Name, Credentials]."',
      severity: 'high',
    },
    {
      id: 'tx2',
      label: 'Texas RAIA — AI clinical output without review statement',
      pattern: '\\b(?:generated by AI|AI-generated|created by AI|produced by AI|written by AI)\\b',
      flags: 'gi',
      message: 'Texas RAIA: AI-generated content in clinical context requires patient notification and clinician review. Ensure disclosure language is included.',
      severity: 'medium',
    },
  ],

  // ── FTC / HIPRA Mode ─────────────────────────────────────────────────────────
  // For: non-HIPAA entities — health coaches, functional medicine practitioners,
  //      wellness apps, health educators, non-prescribers.
  //
  // Sources:
  //   - FTC Health Breach Notification Rule (updated 2024, expanded to health apps)
  //   - FTC Section 5 (deceptive or unfair practices)
  //   - HIPRA — Health Information Privacy Reform Act (introduced Nov 2025)
  //             targets tech companies and apps collecting non-PHI health data
  //   - FTC Enforcement actions: BetterHelp, GoodRx, Premom (2023-2025)
  ftc_hipra: [
    {
      id: 'ftc1',
      label: 'FTC — Health data sharing disclosure',
      pattern: '\\b(?:share|sharing|sell|selling|provide|providing|transfer|transferring)\\s+(?:your\\s+)?(?:health|medical|wellness|fitness|mental health|personal)\\s+(?:data|information|info|details|records)\\b',
      flags: 'gi',
      message: 'FTC HBNR (2024): Sharing user health data requires clear upfront disclosure and authorization. Ensure privacy policy and consent language is explicit and prominent.',
      severity: 'high',
    },
    {
      id: 'ftc2',
      label: 'FTC — Unsubstantiated health claim',
      pattern: '\\b(?:proven|scientifically proven|clinically proven|studies show|research shows|backed by science|evidence-based)\\b',
      flags: 'gi',
      message: 'FTC Section 5: Claims like "clinically proven" or "studies show" require competent and reliable scientific evidence. Ensure you can substantiate this claim with specific, citable research.',
      severity: 'high',
    },
    {
      id: 'ftc3',
      label: 'FTC — Weight loss / body change guarantee',
      pattern: '\\b(?:lose|lost|loss|drop|shed)\\s+\\d+\\s+(?:pounds?|lbs?|kilos?|kg)\\b',
      flags: 'gi',
      message: 'FTC Weight Loss Advertising Guidance: Specific weight loss claims (e.g., "lose 30 pounds") require: (1) disclosure of typical results, (2) scientific substantiation. Add: "Results not typical. Individual results vary."',
      severity: 'high',
    },
    {
      id: 'ftc4',
      label: 'FTC — Testimonial without typical results disclosure',
      pattern: '\\b(?:client|customer|patient|member)\s+(?:said|told me|shared|reported|experienced|achieved|lost|gained|reversed|eliminated)\\b',
      flags: 'gi',
      message: 'FTC Endorsement Guides (2023): Testimonials implying typical outcomes require a clear and conspicuous disclosure of typical results. Add: "Results not typical. Individual results vary."',
      severity: 'medium',
    },
    {
      id: 'ftc5',
      label: 'FTC — Free claim with conditions',
      pattern: '\\bfree\\b',
      flags: 'gi',
      message: 'FTC "Free" Guidelines: If "free" has any conditions (signup, purchase, subscription), those conditions must be clearly disclosed immediately adjacent to the "free" claim.',
      severity: 'low',
    },
    {
      id: 'ftc6',
      label: 'HIPRA — Personal health data collection reference',
      pattern: '\\b(?:collect|collecting|store|storing|track|tracking|gather|gathering)\\s+(?:your\\s+)?(?:health|medical|wellness|mental health|fitness|biometric|genetic|genomic|reproductive)\\s+(?:data|information|info|details)\\b',
      flags: 'gi',
      message: 'HIPRA (Nov 2025, if enacted): Health data collection by non-HIPAA entities (apps, coaches, wellness platforms) will require explicit consent, clear data use disclosure, and opt-out rights. Ensure your privacy policy is comprehensive and accessible.',
      severity: 'medium',
    },
    {
      id: 'ftc7',
      label: 'HIPRA — Mental health data reference',
      pattern: '\\b(?:mental health|anxiety|depression|therapy|counseling|psychiatric|psychological)\\s+(?:data|information|records|history|assessment|screening)\\b',
      flags: 'gi',
      message: 'HIPRA (if enacted) includes mental health data as a protected category for non-HIPAA entities. If you collect or reference this data type, ensure enhanced consent and privacy disclosures.',
      severity: 'medium',
    },
    {
      id: 'ftc8',
      label: 'HIPRA — Reproductive / fertility data reference',
      pattern: '\\b(?:fertility|reproductive|menstrual|cycle tracking|pregnancy|ovulation|contraceptive)\\s+(?:data|tracking|information|history|app)\\b',
      flags: 'gi',
      message: 'HIPRA (if enacted) specifically protects reproductive health data. This category received heightened attention post-Dobbs (2022). Ensure explicit consent and review state-level laws (CA, IL, WA, NY) before collecting or referencing this data.',
      severity: 'high',
    },
    {
      id: 'ftc9',
      label: 'FTC — Earnings / income claim',
      pattern: '\\b(?:earn|earning|make|making|income of|revenue of)\\s+\\$?\\d[\\d,]*(?:\\.\\d+)?(?:\\s*(?:per|a)\\s+(?:month|year|week|day))?\\b',
      flags: 'gi',
      message: 'FTC Income Disclosure: Specific income claims require substantiation with actual earnings data and disclosure of typical/atypical results. This applies to business opportunity and coaching program marketing.',
      severity: 'medium',
    },
    {
      id: 'ftc10',
      label: 'FTC — "Doctor-approved" / "Physician-recommended" language',
      pattern: '\\b(?:doctor[- ]approved|physician[- ]recommended|medically[- ]reviewed|clinician[- ]endorsed|healthcare[- ]approved)\b',
      flags: 'gi',
      message: 'FTC Section 5: "Doctor-approved" or "physician-recommended" endorsement language requires that the endorser (a real physician) actually approved the specific product or claim — not a generic professional review. Ensure endorsement is genuine and documentable.',
      severity: 'high',
    },
  ],

  custom: [],
};

// ─── Rule Runner ──────────────────────────────────────────────────────────────

/**
 * runRuleCheck()
 * Applies a set of rules to the provided text.
 *
 * @param {string} text       - Text to scan
 * @param {Object[]} rules    - Array of rule objects
 * @returns {Object[]}        - Array of flag result objects (only for rules that matched)
 */
function runRuleCheck(text, rules) {
  if (!text || !rules || rules.length === 0) return [];

  const flags = [];

  for (const rule of rules) {
    try {
      const regex = new RegExp(rule.pattern, rule.flags || 'gi');
      const matches = [];
      let m;
      let iterations = 0;
      const MAX_ITERATIONS = 100; // Safety guard against catastrophic backtracking

      while ((m = regex.exec(text)) !== null && iterations < MAX_ITERATIONS) {
        iterations++;
        // Capture a short snippet of context around the match
        const start = Math.max(0, m.index - 20);
        const end = Math.min(text.length, m.index + m[0].length + 20);
        const snippet = (start > 0 ? '…' : '') +
          text.slice(start, m.index) +
          '«' + m[0] + '»' +
          text.slice(m.index + m[0].length, end) +
          (end < text.length ? '…' : '');
        matches.push(snippet.replace(/\n/g, ' '));

        // Prevent infinite loops on zero-width matches
        if (m.index === regex.lastIndex) regex.lastIndex++;
      }

      if (matches.length > 0) {
        flags.push({
          ruleId:   rule.id,
          label:    rule.label,
          message:  rule.message,
          severity: rule.severity || 'medium',
          matches:  matches.slice(0, 5), // Show max 5 snippets per rule
          count:    matches.length,
        });
      }
    } catch (e) {
      // If a user-defined regex is invalid, skip it gracefully
      console.warn(`[DeIDGuard] Rule "${rule.id}" has invalid pattern: ${e.message}`);
    }
  }

  // Sort by severity: high → medium → low
  const severityOrder = { high: 0, medium: 1, low: 2 };
  flags.sort((a, b) => (severityOrder[a.severity] ?? 1) - (severityOrder[b.severity] ?? 1));

  return flags;
}

// ─── Storage Helpers ──────────────────────────────────────────────────────────

/**
 * loadRules()
 * Loads the rule pack for the given mode from chrome.storage.local.
 * Falls back to FALLBACK_RULES if storage is unavailable.
 *
 * In 'healthcare_pro' mode, basic rules are merged in automatically.
 *
 * @param {string} mode - 'basic' | 'healthcare_pro' | 'custom'
 * @returns {Promise<Object[]>}
 */
async function loadRules(mode = 'basic') {
  try {
    const key = RULE_STORAGE_KEYS[mode] || RULE_STORAGE_KEYS.basic;
    const result = await chrome.storage.local.get([
      key,
      RULE_STORAGE_KEYS.basic,
    ]);

    const basicRules = result[RULE_STORAGE_KEYS.basic] || FALLBACK_RULES.basic;

    if (mode === 'basic') {
      return basicRules;
    }

    if (mode === 'healthcare_pro') {
      const proRules = result[key] || FALLBACK_RULES.healthcare_pro;
      // Merge basic + pro, dedup by id
      const combined = [...basicRules];
      for (const rule of proRules) {
        if (!combined.find(r => r.id === rule.id)) {
          combined.push(rule);
        }
      }
      return combined;
    }

    if (mode === 'ftc_hipra') {
      // FTC/HIPRA mode: basic rules + FTC/HIPRA rules merged, dedup by id
      const ftcRules = result[key] || FALLBACK_RULES.ftc_hipra;
      const combined = [...basicRules];
      for (const rule of ftcRules) {
        if (!combined.find(r => r.id === rule.id)) {
          combined.push(rule);
        }
      }
      return combined;
    }

    if (mode === 'custom') {
      const customRules = result[key] || [];
      return customRules;
    }

    return basicRules;
  } catch (e) {
    console.warn('[DeIDGuard] Could not load rules from storage, using fallback.', e);
    return FALLBACK_RULES[mode] || FALLBACK_RULES.basic;
  }
}

/**
 * saveCustomRules()
 * Saves user-defined custom rules to chrome.storage.local.
 *
 * @param {Object[]} rules
 * @returns {Promise<void>}
 */
async function saveCustomRules(rules) {
  await chrome.storage.local.set({
    [RULE_STORAGE_KEYS.custom]: rules,
  });
}

/**
 * validateRule()
 * Checks whether a rule object has a valid regex pattern.
 *
 * @param {Object} rule
 * @returns {{ valid: boolean, error: string|null }}
 */
function validateRule(rule) {
  if (!rule.pattern || typeof rule.pattern !== 'string') {
    return { valid: false, error: 'Pattern must be a non-empty string.' };
  }
  try {
    new RegExp(rule.pattern, rule.flags || 'gi');
    return { valid: true, error: null };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

// ─── Severity Badge Helper ────────────────────────────────────────────────────

/**
 * severityLabel()
 * Returns display label and CSS class for a severity level.
 *
 * @param {string} severity
 * @returns {{ label: string, cssClass: string }}
 */
function severityLabel(severity) {
  switch (severity) {
    case 'high':   return { label: 'HIGH',   cssClass: 'severity-high' };
    case 'medium': return { label: 'MED',    cssClass: 'severity-medium' };
    case 'low':    return { label: 'LOW',    cssClass: 'severity-low' };
    default:       return { label: 'INFO',   cssClass: 'severity-info' };
  }
}

// ─── Global Export ────────────────────────────────────────────────────────────

if (typeof window !== 'undefined') {
  window.DeIDGuard = window.DeIDGuard || {};
  window.DeIDGuard.runRuleCheck    = runRuleCheck;
  window.DeIDGuard.loadRules       = loadRules;
  window.DeIDGuard.saveCustomRules = saveCustomRules;
  window.DeIDGuard.validateRule    = validateRule;
  window.DeIDGuard.severityLabel   = severityLabel;
  window.DeIDGuard.FALLBACK_RULES  = FALLBACK_RULES;
}
