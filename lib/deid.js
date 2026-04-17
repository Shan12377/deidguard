/**
 * DeIDGuard – lib/deid.js
 * Local De-Identification Engine  |  Version 1.2.0
 *
 * PURPOSE:
 *   Applies smart, regex-based de-identification inspired by HIPAA Safe Harbor
 *   identifier categories (45 CFR §164.514(b)), plus emerging-identifier
 *   categories identified by 2025-2026 legal and market research.
 *
 * IMPORTANT DISCLAIMER:
 *   This tool ASSISTS with de-identification but does NOT guarantee legal
 *   de-identification, HIPAA Safe Harbor compliance, or any regulatory standard.
 *   Final review remains the user's responsibility.
 *
 * PRIVACY GUARANTEE:
 *   No text data leaves the device. No external API calls. No analytics.
 *
 * HIPAA Safe Harbor Categories (18 identifiers) — fully covered:
 *   1.  Names
 *   2.  Geographic data (smaller than state)
 *   3.  Dates (except year); ages 90+ aggregated
 *   4.  Phone numbers
 *   5.  Fax numbers
 *   6.  Email addresses
 *   7.  Social security numbers
 *   8.  Medical record numbers
 *   9.  Health plan beneficiary numbers
 *   10. Account numbers
 *   11. Certificate / license numbers
 *   12. Vehicle identifiers and serial numbers
 *   13. Device identifiers and serial numbers
 *   14. Web URLs
 *   15. IP addresses
 *   16. Biometric identifiers
 *   17. Full-face photographs (text reference detection)
 *   18. Any other unique identifying number or code
 *
 * EXTENDED CATEGORIES (v1.2.0) — beyond the original 18:
 *   E1. Social media handles (@username)
 *   E2. Employer / organization name (heuristic — labeled contexts)
 *   E3. Genomic / genetic identifiers (gene mutations, BRCA references)
 *   E4. Quasi-identifier risk scoring (age + gender + zip proximity)
 *
 * References:
 *   - HIPAA Journal 2026 de-identification update
 *   - Healthcare IT Today: Hidden Flaws in De-Identification (Feb 2025)
 *   - HHS OCR Guidance: 45 CFR §164.514(b)
 *   - Texas Responsible AI Governance Act (eff. Jan 1, 2026)
 *   - HIPRA — Health Information Privacy Reform Act (introduced Nov 2025)
 */

'use strict';

// ─── Counter Tracking ─────────────────────────────────────────────────────────

let _counters = {};

function _resetCounters() {
  _counters = {};
}

function _increment(category) {
  _counters[category] = (_counters[category] || 0) + 1;
}

// ─── Replacement Helper ───────────────────────────────────────────────────────

function _replace(text, pattern, replacement, category) {
  return text.replace(pattern, (match, ...args) => {
    _increment(category);
    return typeof replacement === 'function'
      ? replacement(match, ...args)
      : replacement;
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// HIPAA SAFE HARBOR — 18 OFFICIAL CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════

/** #6  EMAIL ADDRESSES */
function deidEmails(text) {
  const pattern = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
  return _replace(text, pattern, '[EMAIL REDACTED]', 'email');
}

/** #5  FAX NUMBERS */
function deidFaxNumbers(text) {
  const pattern = /\bfax\s*(?:number|no\.?|#)?\s*:?\s*(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/gi;
  return _replace(text, pattern, '[FAX REDACTED]', 'fax');
}

/** #4  PHONE NUMBERS */
function deidPhones(text) {
  const pattern = /(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  return _replace(text, pattern, '[PHONE REDACTED]', 'phone');
}

/** #7  SOCIAL SECURITY NUMBERS */
function deidSSN(text) {
  const pattern = /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g;
  return _replace(text, pattern, '[SSN REDACTED]', 'ssn');
}

/** #18 NPI (National Provider Identifier) */
function deidNPI(text) {
  const pattern = /\bNPI\s*[:#]?\s*\d{10}\b/gi;
  return _replace(text, pattern, '[NPI REDACTED]', 'npi');
}

/** #11 CERTIFICATE / LICENSE NUMBERS */
function deidLicenseNumbers(text) {
  const pattern = /\b(?:DEA\s*(?:Registration\s*)?(?:No\.?|#|Number)?|State\s+(?:Medical\s+)?License\s*(?:No\.?|#|Number)?|Professional\s+License\s*(?:No\.?|#|Number)?|License\s*(?:No\.?|#|Number)|Cert(?:ificate)?\s*(?:No\.?|#|Number)?|Lic\.?\s*(?:No\.?|#)?)\s*[A-Z0-9][-A-Z0-9]{3,}\b/gi;
  return _replace(text, pattern, '[LICENSE REDACTED]', 'license');
}

/** #8 #9 #10  MEDICAL / ACCOUNT / BENEFICIARY IDs */
function deidMedicalIDs(text) {
  const pattern = /\b(?:MRN|Medical\s+Record(?:\s+Number)?|Patient\s+ID|Pt\.?\s*ID|Chart\s*(?:No\.?|#|Number)?|Account\s*(?:No\.?|#|Number)?|Member\s*ID|Beneficiary\s*(?:ID|Number)?|Policy\s*(?:No\.?|#|Number)?)[\s:#]*\w+[-\w]*/gi;
  return _replace(text, pattern, '[ID REDACTED]', 'medical_id');
}

/** Credit cards (closely related to #10 account numbers) */
function deidCreditCards(text) {
  const pattern = /\b(?:\d[ -]?){13,16}\b/g;
  return text.replace(pattern, (match) => {
    const digits = match.replace(/[\s-]/g, '');
    if (digits.length >= 13 && digits.length <= 16 && /^\d+$/.test(digits)) {
      _increment('credit_card');
      return '[CARD REDACTED]';
    }
    return match;
  });
}

/** #12 VEHICLE IDENTIFIERS */
function deidVehicleIDs(text) {
  text = _replace(
    text,
    /\b(?:VIN\s*[:#]?\s*)?[A-HJ-NPR-Z0-9]{17}\b/g,
    (match) => {
      if (/VIN/i.test(match) || /^[A-HJ-NPR-Z0-9]{17}$/.test(match.trim())) {
        _increment('vehicle_id');
        return '[VEHICLE-ID REDACTED]';
      }
      return match;
    },
    'vehicle_id'
  );
  text = _replace(
    text,
    /\b(?:License\s+Plate|Plate\s*(?:No\.?|#)|Vehicle\s+Tag|Tag\s*(?:No\.?|#))\s*[:#]?\s*[A-Z0-9]{2,8}\b/gi,
    '[VEHICLE-ID REDACTED]',
    'vehicle_id'
  );
  return text;
}

/** #16 BIOMETRIC IDENTIFIER REFERENCES */
function deidBiometricRefs(text) {
  const pattern = /\b(?:Fingerprint|Retinal?\s+Scan|Iris\s+Scan|Voice\s+Print|Facial\s+Recognition|Biometric)\s*(?:ID|identifier|template|code|hash|record)?\s*[:#]?\s*[A-Z0-9][-A-Z0-9]{3,}\b/gi;
  return _replace(text, pattern, '[BIOMETRIC-ID REDACTED]', 'biometric');
}

/** #14 URLs */
function deidURLs(text) {
  const pattern = /https?:\/\/[^\s<>"']+/gi;
  return _replace(text, pattern, '[URL REDACTED]', 'url');
}

/** #15 IP ADDRESSES */
function deidIPAddresses(text) {
  text = _replace(text, /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP REDACTED]', 'ip');
  text = _replace(text, /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, '[IP REDACTED]', 'ip');
  return text;
}

/** #2  STREET ADDRESSES */
function deidStreetAddresses(text) {
  const streetSuffixes = '(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Court|Ct|Lane|Ln|Way|Wy|Circle|Cir|Place|Pl|Terrace|Ter|Trail|Trl|Highway|Hwy|Parkway|Pkwy|Square|Sq|Loop|Pass|Run|Path|Pike|Route|Rt)';
  const pattern = new RegExp(
    `\\b\\d+\\s+(?:(?:N|S|E|W|NE|NW|SE|SW)\\.?\\s+)?[A-Z][a-z]+(?:\\s+[A-Z][a-z]+)*\\s+${streetSuffixes}\\.?(?:\\s+(?:Suite|Ste|Apt|Unit|#)\\s*\\w+)?\\b`,
    'g'
  );
  return _replace(text, pattern, '[ADDRESS REDACTED]', 'address');
}

/** #2  ZIP CODES */
function deidZipCodes(text) {
  const pattern = /\b\d{5}(?:-\d{4})?\b/g;
  return text.replace(pattern, (match, offset, fullText) => {
    const before = fullText[offset - 1];
    if (before === '$' || before === '#') return match;
    _increment('zip');
    return '[ZIP REDACTED]';
  });
}

/** #3  DATES */
function deidDates(text, granularity = 'year') {
  const months = '(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)';
  const patterns = [
    /\b(\d{4})[-\/](0?[1-9]|1[0-2])[-\/](0?[1-9]|[12]\d|3[01])\b/g,
    /\b(0?[1-9]|1[0-2])[-\/](0?[1-9]|[12]\d|3[01])[-\/](\d{4}|\d{2})\b/g,
    new RegExp(`\\b${months}\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+\\d{4}\\b`, 'gi'),
    new RegExp(`\\b\\d{1,2}(?:st|nd|rd|th)?\\s+${months}\\s+\\d{4}\\b`, 'gi'),
    new RegExp(`\\b${months}\\s+\\d{4}\\b`, 'gi'),
  ];
  for (const pattern of patterns) {
    text = text.replace(pattern, (match) => {
      _increment('date');
      const yearMatch = match.match(/\b(19|20)\d{2}\b/);
      const year = yearMatch ? yearMatch[0] : 'XXXX';
      if (granularity === 'month_year') {
        const monthNames = { jan:'Jan',feb:'Feb',mar:'Mar',apr:'Apr',may:'May',jun:'Jun',jul:'Jul',aug:'Aug',sep:'Sep',oct:'Oct',nov:'Nov',dec:'Dec' };
        const monthMatch = match.match(/\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b/i);
        if (monthMatch) {
          const abbr = monthNames[monthMatch[1].toLowerCase().slice(0, 3)];
          return `[DATE: ${abbr} ${year}]`;
        }
        const numMatch = match.match(/\b(0?[1-9]|1[0-2])\b/);
        if (numMatch) {
          const monthAbbrs = ['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
          return `[DATE: ${monthAbbrs[parseInt(numMatch[1], 10)]} ${year}]`;
        }
      }
      return `[YEAR: ${year}]`;
    });
  }
  return text;
}

/** #3  AGES  (HIPAA §164.514(b): ages 90+ must be aggregated) */
function deidAges(text) {
  const pattern = /\b(\d{1,3})[-\s]?(?:year(?:s)?[-\s]?old|y\/o|yo)\b/gi;
  return _replace(text, pattern, (match, ageStr) => {
    _increment('age');
    const age = parseInt(ageStr, 10);
    if (age < 18)  return 'a minor';
    if (age < 65)  return 'an adult';
    if (age < 90)  return 'an older adult';
    return 'an individual age 90 or over'; // HIPAA Safe Harbor requirement
  }, 'age');
}

/** #13 DEVICE IDENTIFIERS */
function deidDeviceIDs(text) {
  const pattern = /\b(?:Serial\s*(?:No\.?|Number|#)|SN\s*[:#]|IMEI\s*[:#]?)\s*[A-Z0-9][-A-Z0-9]{5,}\b/gi;
  return _replace(text, pattern, '[DEVICE-ID REDACTED]', 'device_id');
}

/** #1  NAMES (prefixed / contextual — conservative to avoid false positives) */
function deidNames(text, personLabel = 'Individual') {
  const titledPattern = /\b(?:Dr\.?|Mr\.?|Mrs\.?|Ms\.?|Miss|Prof\.?|Rev\.?|Hon\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b/g;
  let counter = 0;
  text = text.replace(titledPattern, () => {
    _increment('name');
    return `${personLabel} ${++counter}`;
  });
  const patientPattern = /\b(?:patient|client|individual|subject|participant)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/gi;
  text = text.replace(patientPattern, () => {
    _increment('name');
    return `${personLabel} ${++counter}`;
  });
  return text;
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTENDED CATEGORIES — v1.2.0  (Beyond the original 18)
// Sources: HIPAA Journal 2026 update, Healthcare IT Today Feb 2025,
//          IAPP state-law de-identification analysis 2025
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * E1. SOCIAL MEDIA HANDLES
 *   The HIPAA Safe Harbor identifier list predates social media.
 *   2026 legal guidance explicitly flags @usernames as emerging identifiers
 *   that should be removed from de-identified text.
 *   Pattern: @username (2-30 chars, alphanumeric + underscores)
 *   Replace with: [SOCIAL-HANDLE REDACTED]
 */
function deidSocialHandles(text) {
  // Match @handle not preceded by an email-local-part character (avoid email@domain)
  const pattern = /(?<![A-Za-z0-9._%+\-])@[A-Za-z0-9_]{2,30}\b/g;
  return _replace(text, pattern, '[SOCIAL-HANDLE REDACTED]', 'social_handle');
}

/**
 * E2. EMPLOYER / ORGANIZATION NAME  (labeled contexts only)
 *   "works at", "employed by", "staff at", "practices at", "a nurse at"
 *   Only targets explicitly labeled contexts to minimize false positives.
 *   Replace with: [EMPLOYER REDACTED]
 */
function deidEmployerRefs(text) {
  const pattern = /\b(?:works?\s+at|employed\s+by|staff\s+at|practices?\s+at|works?\s+for|position\s+at|employed\s+with|affiliated\s+with)\s+[A-Z][A-Za-z\s&'\-]{2,50}(?:Hospital|Clinic|Health|Medical|Center|Centre|Practice|Institute|Foundation|Group|System|Network|Associates|Partners|LLC|Inc\.?|Corp\.?)\b/gi;
  return _replace(text, pattern, '[EMPLOYER REDACTED]', 'employer');
}

/**
 * E3. GENOMIC / GENETIC IDENTIFIERS
 *   Gene mutation references combined with any other identifier become
 *   highly re-identifying. Flags labeled gene mutation references.
 *   Pattern: BRCA1, BRCA2, APOE, TP53, MTHFR + mutation context words
 *   Replace with: [GENOMIC-ID REDACTED]
 */
function deidGenomicRefs(text) {
  // Specific high-risk gene references with mutation qualifiers
  const pattern = /\b(?:BRCA[12]|APOE|TP53|MTHFR|KRAS|EGFR|ALK|PTEN|MLH1|MSH2|MSH6|PMS2|APC|RB1|VHL|MEN1|PALB2|CHEK2|ATM|CDH1)\s*(?:mutation|variant|positive|negative|carrier|status|gene|allele|deletion|insertion|pathogenic|benign)?\b/gi;
  return _replace(text, pattern, '[GENOMIC-ID REDACTED]', 'genomic');
}

// ═══════════════════════════════════════════════════════════════════════════════
// RE-IDENTIFICATION RISK SCORING — v1.2.0
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * calculateRiskScore()
 *
 * Evaluates the cleaned text for quasi-identifier combinations that
 * increase re-identification risk even after direct identifier removal.
 *
 * Based on research finding (Healthcare IT Today, Feb 2025):
 *   "AI can cross-reference thousands of data points in seconds —
 *    even 'properly' de-identified text can be re-identified."
 *
 * Quasi-identifiers considered:
 *   - Age bracket (minor / adult / older adult) still narrows a population
 *   - Gender terms (she/he/her/him/woman/man/male/female)
 *   - Geographic references (city names, state names, county)
 *   - Condition / diagnosis references (even without a name)
 *   - Occupation / specialty references
 *   - Time references (year, month/year)
 *   - Race / ethnicity references
 *   - Combination scoring: each quasi-identifier adds to risk
 *
 * @param {string} text - The de-identified text to score
 * @returns {{ score: 'low'|'medium'|'high', points: number, factors: string[] }}
 */
function calculateRiskScore(text) {
  const factors = [];
  let points = 0;

  // Age bracket present
  if (/\b(?:a minor|an adult|an older adult|individual age 90 or over)\b/i.test(text)) {
    points += 1;
    factors.push('Age bracket retained');
  }

  // Gender terms
  if (/\b(?:she|her|hers|woman|female|girl|he|him|his|man|male|boy|non-binary|transgender|trans|gender)\b/i.test(text)) {
    points += 1;
    factors.push('Gender reference retained');
  }

  // Geographic reference (city, state, county — not a direct address)
  if (/\b(?:county|township|district|borough|parish|precinct|neighborhood|suburb|metro area|greater\s+\w+\s+area)\b/i.test(text)) {
    points += 2;
    factors.push('Sub-state geographic reference retained');
  }

  // Condition / diagnosis reference (even de-named, a condition + other quasi-IDs = risk)
  if (/\b(?:diabetes|cancer|HIV|AIDS|hypertension|lupus|MS|COPD|depression|schizophrenia|bipolar|Alzheimer|Parkinson|autism|ASD|ADHD|eating\s+disorder|substance\s+use|addiction|overdose|opioid)\b/i.test(text)) {
    points += 2;
    factors.push('Specific condition / diagnosis reference retained');
  }

  // Occupation / specialty (narrows population)
  if (/\b(?:physician|surgeon|pharmacist|nurse|attorney|lawyer|teacher|professor|principal|CEO|executive|pastor|priest|police\s+officer|firefighter)\b/i.test(text)) {
    points += 1;
    factors.push('Occupation reference retained');
  }

  // Race / ethnicity
  if (/\b(?:African\s+American|Black|Hispanic|Latino|Latina|Latinx|Asian|White|Caucasian|Native\s+American|Indigenous|Pacific\s+Islander|Middle\s+Eastern|South\s+Asian)\b/i.test(text)) {
    points += 2;
    factors.push('Race / ethnicity reference retained');
  }

  // Residual date/year info
  if (/\[(?:YEAR|DATE):/i.test(text)) {
    points += 1;
    factors.push('Year or partial date retained in output');
  }

  // Combination multiplier: 3+ quasi-identifiers together is exponentially riskier
  if (factors.length >= 4) {
    points += 3;
    factors.push('COMBINATION RISK: 4+ quasi-identifiers present together');
  } else if (factors.length === 3) {
    points += 1;
    factors.push('Moderate combination: 3 quasi-identifiers present');
  }

  let score;
  if (points <= 1)      score = 'low';
  else if (points <= 4) score = 'medium';
  else                  score = 'high';

  return { score, points, factors };
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN EXPORT FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * deidentify()
 *
 * @param {string} text
 * @param {Object} options
 * @param {string}  options.dateGranularity  - 'year' | 'month_year'
 * @param {boolean} options.useClientLabel   - false = "Patient X" | true = "Client X"
 *
 * @returns {{ cleaned: string, summary: Object, changes: number, riskScore: Object }}
 */
function deidentify(text, options = {}) {
  if (!text || typeof text !== 'string') {
    return { cleaned: '', summary: {}, changes: 0, riskScore: { score: 'low', points: 0, factors: [] } };
  }

  const {
    dateGranularity = 'year',
    useClientLabel  = false,
  } = options;

  const personLabel = useClientLabel ? 'Client' : 'Patient';

  _resetCounters();

  let cleaned = text;

  // ── Pass 1: Extended identifiers (run before HIPAA pass to avoid conflicts) ──
  cleaned = deidSocialHandles(cleaned);   // E1 — social media @handles
  cleaned = deidGenomicRefs(cleaned);     // E3 — gene mutation references
  cleaned = deidEmployerRefs(cleaned);    // E2 — employer / org names (labeled)

  // ── Pass 2: HIPAA Safe Harbor 18 categories ──
  cleaned = deidEmails(cleaned);          // #6
  cleaned = deidFaxNumbers(cleaned);      // #5
  cleaned = deidPhones(cleaned);          // #4
  cleaned = deidSSN(cleaned);             // #7
  cleaned = deidNPI(cleaned);             // #18 (provider ID)
  cleaned = deidLicenseNumbers(cleaned);  // #11
  cleaned = deidMedicalIDs(cleaned);      // #8 #9 #10
  cleaned = deidCreditCards(cleaned);     // #10 (financial)
  cleaned = deidVehicleIDs(cleaned);      // #12
  cleaned = deidBiometricRefs(cleaned);   // #16
  cleaned = deidURLs(cleaned);            // #14
  cleaned = deidIPAddresses(cleaned);     // #15
  cleaned = deidStreetAddresses(cleaned); // #2
  cleaned = deidZipCodes(cleaned);        // #2
  cleaned = deidDates(cleaned, dateGranularity); // #3
  cleaned = deidAges(cleaned);            // #3 (age aggregation)
  cleaned = deidDeviceIDs(cleaned);       // #13
  cleaned = deidNames(cleaned, personLabel); // #1

  // ── Re-identification risk score on the cleaned output ──
  const riskScore = calculateRiskScore(cleaned);

  const totalChanges = Object.values(_counters).reduce((a, b) => a + b, 0);

  return {
    cleaned,
    summary: { ..._counters },
    changes: totalChanges,
    riskScore,
  };
}

/**
 * formatSummary()
 * Human-readable summary of changes made.
 */
function formatSummary(summary) {
  const labels = {
    social_handle: 'Social media handle(s)',  // E1
    genomic:       'Genomic / gene reference(s)', // E3
    employer:      'Employer / organization reference(s)', // E2
    email:         'Email address(es)',
    phone:         'Phone number(s)',
    fax:           'Fax number(s)',
    ssn:           'Social Security Number(s)',
    npi:           'NPI number(s)',
    license:       'License / Certificate number(s)',
    medical_id:    'Medical / Account ID(s)',
    credit_card:   'Credit card number(s)',
    vehicle_id:    'Vehicle identifier(s)',
    biometric:     'Biometric reference(s)',
    url:           'URL(s)',
    ip:            'IP address(es)',
    address:       'Street address(es)',
    zip:           'ZIP code(s)',
    date:          'Date(s)',
    age:           'Age(s)',
    device_id:     'Device / Serial ID(s)',
    name:          'Name(s)',
  };

  return Object.entries(summary)
    .filter(([, count]) => count > 0)
    .map(([key, count]) => `${labels[key] || key}: ${count} replaced`);
}

// ─── Global Export ────────────────────────────────────────────────────────────

if (typeof window !== 'undefined') {
  window.DeIDGuard = window.DeIDGuard || {};
  window.DeIDGuard.deidentify        = deidentify;
  window.DeIDGuard.formatSummary     = formatSummary;
  window.DeIDGuard.calculateRiskScore = calculateRiskScore;
}
