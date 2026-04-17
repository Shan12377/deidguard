/**
 * DeIDGuard – background.js
 * Service Worker (Manifest V3)
 *
 * Responsibilities:
 *  - Listen for extension install/update events
 *  - Seed default settings and rule packs into chrome.storage.local on first install
 *  - Relay messages between popup and content contexts if needed
 *
 * Privacy guarantee:
 *  - No network requests are made here
 *  - No text data is ever transmitted off-device
 *  - All storage is chrome.storage.local only
 */

'use strict';

// ─── Default Settings ───────────────────────────────────────────────────────

const DEFAULT_SETTINGS = {
  reviewMode: 'basic',           // 'basic' | 'healthcare_pro' | 'ftc_hipra' | 'custom'
  useClientLabel: false,         // false = "Patient X" | true = "Client X"
  dateGranularity: 'year',       // 'year' | 'month_year'
  showPrivacyBadge: true,        // show privacy notice in popup
};

// ─── Seeded Rule Packs ───────────────────────────────────────────────────────
// These seed rules are loaded on first install so the extension works
// immediately without any user configuration.

const SEEDED_RULES = {
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
      label: 'SSN / ID number pattern',
      pattern: '\\b\\d{3}[-\\s]\\d{2}[-\\s]\\d{4}\\b',
      flags: 'gi',
      message: 'Possible Social Security Number pattern detected.',
      severity: 'high',
    },
  ],

  healthcare_pro: [
    // Inherits all basic rules, plus:
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
      label: 'Clinical claim',
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
      label: 'Medication advice',
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
      label: 'Guarantee / promise language',
      pattern: '\\b(guarantee(d|s)?|promise(d|s)?|ensur(e|es|ed))\\b',
      flags: 'gi',
      message: 'Guarantee language in health context may violate FTC requirements. Results must include appropriate caveats.',
      severity: 'medium',
    },
  ],

  // ── FTC / HIPRA Mode (v1.2.0) ────────────────────────────────────────────────
  // For non-HIPAA entities: health coaches, wellness apps, functional medicine
  // practitioners, non-prescribers. Based on FTC HBNR (2024 expansion) and
  // HIPRA (Health Information Privacy Reform Act, introduced Nov 2025).
  ftc_hipra: [
    {
      id: 'ftc1',
      label: 'FTC — Health data sharing disclosure',
      pattern: '\\b(?:share|sharing|sell|selling|provide|providing|transfer|transferring)\\s+(?:your\\s+)?(?:health|medical|wellness|fitness|mental health|personal)\\s+(?:data|information|info|details|records)\\b',
      flags: 'gi',
      message: 'FTC HBNR (2024): Sharing user health data requires clear upfront disclosure and authorization. Ensure your privacy policy and consent language are explicit and prominent.',
      severity: 'high',
    },
    {
      id: 'ftc2',
      label: 'FTC — Unsubstantiated health claim',
      pattern: '\\b(?:proven|scientifically proven|clinically proven|studies show|research shows|backed by science|evidence-based)\\b',
      flags: 'gi',
      message: 'FTC Section 5: Claims like "clinically proven" require competent and reliable scientific evidence. Ensure you can cite specific research to support this claim.',
      severity: 'high',
    },
    {
      id: 'ftc3',
      label: 'FTC — Specific weight loss claim',
      pattern: '\\b(?:lose|lost|loss|drop|shed)\\s+\\d+\\s+(?:pounds?|lbs?|kilos?|kg)\\b',
      flags: 'gi',
      message: 'FTC Weight Loss Advertising Guidance: Specific weight loss claims require scientific substantiation and disclosure of typical results. Add: "Results not typical. Individual results vary."',
      severity: 'high',
    },
    {
      id: 'ftc4',
      label: 'FTC — Testimonial without typical-results disclosure',
      pattern: '\\b(?:client|customer|patient|member)\\s+(?:said|told me|shared|reported|experienced|achieved|lost|gained|reversed|eliminated)\\b',
      flags: 'gi',
      message: 'FTC Endorsement Guides (2023): Testimonials implying typical outcomes require a clear disclosure. Add: "Results not typical. Individual results vary."',
      severity: 'medium',
    },
    {
      id: 'ftc5',
      label: 'FTC — Free claim with potential conditions',
      pattern: '\\bfree\\b',
      flags: 'gi',
      message: 'FTC "Free" Guidelines: If "free" has any conditions (signup, purchase, subscription), those conditions must be clearly disclosed immediately adjacent to the claim.',
      severity: 'low',
    },
    {
      id: 'ftc6',
      label: 'HIPRA — Personal health data collection',
      pattern: '\\b(?:collect|collecting|store|storing|track|tracking|gather|gathering)\\s+(?:your\\s+)?(?:health|medical|wellness|mental health|fitness|biometric|genetic|genomic|reproductive)\\s+(?:data|information|info|details)\\b',
      flags: 'gi',
      message: 'HIPRA (introduced Nov 2025): Health data collection by non-HIPAA entities will require explicit consent, clear data use disclosure, and opt-out rights. Ensure your privacy policy covers this.',
      severity: 'medium',
    },
    {
      id: 'ftc7',
      label: 'HIPRA — Mental health data',
      pattern: '\\b(?:mental health|anxiety|depression|therapy|counseling|psychiatric|psychological)\\s+(?:data|information|records|history|assessment|screening)\\b',
      flags: 'gi',
      message: 'HIPRA (if enacted): Mental health data is a protected category for non-HIPAA entities. Ensure enhanced consent and privacy disclosures for this data type.',
      severity: 'medium',
    },
    {
      id: 'ftc8',
      label: 'HIPRA — Reproductive / fertility data',
      pattern: '\\b(?:fertility|reproductive|menstrual|cycle tracking|pregnancy|ovulation|contraceptive)\\s+(?:data|tracking|information|history|app)\\b',
      flags: 'gi',
      message: 'HIPRA specifically protects reproductive health data. State laws (CA, IL, WA, NY) add additional protections. Ensure explicit consent and compliance with applicable state laws.',
      severity: 'high',
    },
    {
      id: 'ftc9',
      label: 'FTC — Specific income / earnings claim',
      pattern: '\\b(?:earn|earning|make|making|income of|revenue of)\\s+\\$?\\d[\\d,]*(?:\\.\\d+)?(?:\\s*(?:per|a)\\s+(?:month|year|week|day))?\\b',
      flags: 'gi',
      message: 'FTC Income Disclosure: Specific income claims require substantiation with actual earnings data and disclosure of typical/atypical results.',
      severity: 'medium',
    },
    {
      id: 'ftc10',
      label: 'FTC — Endorsement claim without documented approval',
      pattern: '\\b(?:doctor[- ]approved|physician[- ]recommended|medically[- ]reviewed|clinician[- ]endorsed|healthcare[- ]approved)\\b',
      flags: 'gi',
      message: 'FTC Section 5: Endorsement language like "doctor-approved" requires that a real physician actually approved this specific claim — not a generic professional review. Ensure the endorsement is genuine and documentable.',
      severity: 'high',
    },
    // Texas RAIA rules (also included in healthcare_pro, repeated here for standalone access)
    {
      id: 'tx1',
      label: 'Texas RAIA — AI clinical decision without disclosure',
      pattern: '\\b(?:AI|artificial intelligence|algorithm|model|machine learning|ML)\\s+(?:determined|found|diagnosed|recommends?|suggests?|advises?|concludes?|identifies?|detects?)\\b',
      flags: 'gi',
      message: 'Texas RAIA (eff. Jan 1 2026): AI-assisted clinical determinations require patient notification and clinician review. Add: "This AI-assisted assessment was reviewed and approved by [Clinician Name, Credentials]."',
      severity: 'high',
    },
  ],

  custom: [], // Populated by user via settings
};

// ─── Install / Update Handler ─────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    // First install — seed settings and rules
    await chrome.storage.local.set({
      deidguard_settings: DEFAULT_SETTINGS,
      deidguard_rules_basic: SEEDED_RULES.basic,
      deidguard_rules_healthcare_pro: SEEDED_RULES.healthcare_pro,
      deidguard_rules_ftc_hipra: SEEDED_RULES.ftc_hipra,
      deidguard_rules_custom: SEEDED_RULES.custom,
      deidguard_history: [],
    });

    console.log('[DeIDGuard] Extension installed. Default settings and rules seeded.');
  } else if (details.reason === 'update') {
    // Preserve user settings/rules on update, only patch if keys missing
    const stored = await chrome.storage.local.get([
      'deidguard_settings',
      'deidguard_rules_basic',
      'deidguard_rules_healthcare_pro',
      'deidguard_rules_ftc_hipra',
    ]);

    const patches = {};
    if (!stored.deidguard_settings) patches.deidguard_settings = DEFAULT_SETTINGS;
    if (!stored.deidguard_rules_basic) patches.deidguard_rules_basic = SEEDED_RULES.basic;
    if (!stored.deidguard_rules_healthcare_pro) patches.deidguard_rules_healthcare_pro = SEEDED_RULES.healthcare_pro;
    if (!stored.deidguard_rules_ftc_hipra) patches.deidguard_rules_ftc_hipra = SEEDED_RULES.ftc_hipra;

    if (Object.keys(patches).length > 0) {
      await chrome.storage.local.set(patches);
    }

    console.log('[DeIDGuard] Extension updated to v' + chrome.runtime.getManifest().version);
  }
});

// ─── Side Panel: Open on Toolbar Click ───────────────────────────────────────
// Research finding (2025-2026): The Chrome Side Panel API provides a persistent,
// spacious UI that stays open across navigations — ideal for a workflow tool
// like DeIDGuard where users need to reference cleaned text while browsing.
//
// When the toolbar icon is clicked, we open the side panel for the active tab.
// This is superior to a popup which closes as soon as focus leaves it.

chrome.action.onClicked.addListener(async (tab) => {
  try {
    await chrome.sidePanel.open({ tabId: tab.id });
  } catch (e) {
    // sidePanel.open() may fail on restricted pages (chrome://, file://)
    // — fail silently; the user will see no panel open on those pages.
    console.warn('[DeIDGuard] Could not open side panel on this page:', e.message);
  }
});

// ─── Side Panel: Enable per-tab (required by Chrome sidePanel API) ────────────
// chrome.sidePanel.setPanelBehavior ensures the panel is openable
// without needing a separate user gesture each time.

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true })
    .catch((e) => console.warn('[DeIDGuard] setPanelBehavior:', e));
});

// ─── Keyboard Shortcut: open_side_panel command ──────────────────────────────

chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'open_side_panel') {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      try {
        await chrome.sidePanel.open({ tabId: tab.id });
      } catch (e) {
        console.warn('[DeIDGuard] Keyboard shortcut: could not open side panel:', e.message);
      }
    }
  }
});

// ─── Message Relay ────────────────────────────────────────────────────────────
// The popup/panel handles most logic directly. Background only relays if needed.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'DEIDGUARD_PING') {
    // Health check for panel self-test
    sendResponse({ status: 'ok', version: chrome.runtime.getManifest().version });
    return true;
  }
});
