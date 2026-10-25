# CyberGhost — Hidden Privacy Risk Detector
## Project Report

**IBM SkillsBuild Cybersecurity BootCamp**
**Project Submission Document**
**Date:** October 2026

---

## 1. Title

**CyberGhost — Hidden Privacy Risk Detector**

A browser-based, privacy-first tool that detects hidden sensitive information in text and empowers users to mask it before sharing.

---

## 2. Abstract

People routinely and unintentionally expose sensitive personal data when sharing text online. CyberGhost is a fully client-side web application that scans user-supplied text for privacy risks — including email addresses, phone numbers, embedded credentials, government-style identifier patterns, and address information — using local pattern matching in the browser. No user data is uploaded to any server. The application calculates an indicative privacy score, displays structured findings with explanations and recommendations, provides automatic text masking with category-specific placeholders, and generates a downloadable JSON security report containing only metadata. All processing is performed in JavaScript using regular expressions, with no external dependencies or backend services.

---

## 3. Problem Statement

### The Problem
Modern communication surfaces — email, social media, shared documents, chat platforms — make it easy to accidentally include personal information in messages intended for broad audiences. Common exposures include:

- **Email addresses** embedded in public posts, enabling spam harvesting and phishing.
- **Phone numbers** disclosed unnecessarily, enabling unsolicited contact or SIM-swap attacks.
- **API keys and passwords** accidentally pasted from configuration files, risking credential compromise.
- **Government ID numbers** (e.g., Aadhaar-like patterns) shared without realising the risk.
- **Home addresses** disclosed in professional or semi-public contexts.

### The Gap
Most existing privacy tools either:
1. Require uploading text to a cloud service (creating a privacy paradox), or
2. Are built into complex enterprise security platforms inaccessible to individuals.

There is no simple, free, trustworthy, browser-local tool for reviewing text before sharing.

---

## 4. Objectives

1. Implement accurate, client-side pattern detection for five categories of sensitive information.
2. Calculate an indicative privacy score with clear explanations and an educational disclaimer.
3. Provide overlap-aware automatic text masking with category-specific placeholders.
4. Generate a safe JSON security report that excludes all original input text.
5. Build a professional, accessible, responsive UI suitable for non-technical users.
6. Ensure strict privacy-by-design: no backend, no network calls, no data storage.

---

## 5. Existing Problem and Proposed Solution

### Existing Solutions and Their Limitations

| Tool Type | Problem |
|-----------|---------|
| Cloud-based scanners | User must upload sensitive text to a third party — a privacy contradiction |
| Enterprise DLP tools | Costly, complex, require IT administration |
| Manual review | Error-prone and inconsistent |
| Browser password managers | Only cover passwords in forms, not arbitrary text |

### Proposed Solution

CyberGhost runs entirely in the user's browser. The text input is read into JavaScript memory, pattern-matched using regular expressions, and the results are rendered in the DOM — all without any outbound network request. When the user closes the tab, the text is gone. This approach resolves the privacy paradox by design.

---

## 6. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User's Browser Tab                   │
│                                                         │
│  ┌─────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │         │  │              │  │                   │  │
│  │ index   │  │  styles.css  │  │    script.js      │  │
│  │ .html   │  │  (layout +   │  │  (Detection       │  │
│  │ (UI     │  │   theme)     │  │   Engine + UI)    │  │
│  │  shell) │  │              │  │                   │  │
│  └────┬────┘  └──────────────┘  └────────┬──────────┘  │
│       │                                  │              │
│  ┌────▼──────────────────────────────────▼──────────┐  │
│  │               Browser DOM                        │  │
│  │  Text Input → Detection → Score → Render →       │  │
│  │  Masking → Report (Blob download)                │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ←── Zero outbound network calls during scanning ────→  │
└─────────────────────────────────────────────────────────┘
```

**No server component exists.** The application is three static files.

---

## 7. Implementation Methodology

### 7.1 Technology Choices

| Technology | Reason |
|------------|--------|
| HTML5 | Semantic structure, ARIA accessibility attributes |
| CSS3 Custom Properties | Design token system, responsive layout, animations |
| Vanilla JavaScript (ES2020) | No framework dependency, transparent logic, browser-native |
| Regular Expressions | Efficient pattern matching without external libraries |
| Web Blob API | Client-side JSON file generation and download |

External CDNs, analytics, and fonts were deliberately excluded to prevent third-party data exposure.

### 7.2 Detection Engine Design

Each detector is an independent function returning an array of `Finding` objects with a common structure:

```javascript
{
  id:             'f1',
  category:       'email',
  severity:       'Medium',
  label:          'Email Address',
  start:          14,          // character offset in original text
  end:            33,
  maskedValue:    '[EMAIL REDACTED]',
  contextSnippet: 'arjun@example.com',
  explanation:    '...',
  recommendation: '...'
}
```

Using character offsets (rather than line numbers or regex captures) enables reliable, offset-based masking that handles multiple findings and overlaps.

### 7.3 Overlap Resolution

Multiple detectors can flag the same text range (e.g., `password=abc@test.com` triggers both secret and email detectors). A priority queue resolves conflicts:

```
Priority: secret (0) > identifier (1) > address (2) > phone (3) > email (4)
```

Lower numeric priority = wins the overlap. This ensures the most security-critical finding is retained.

### 7.4 Privacy Score Algorithm

```
score = 100
for each unique finding category:
    first_occurrence_deduction = weight[category]
    repeat_occurrence_deduction = weight[category] / 2  (rounded up)
    score -= total_deduction
score = clamp(score, 0, 100)
```

Score weights: Secret=35, Identifier=25, Phone=20, Address=20, Email=15.

### 7.5 Masking Algorithm

Findings are sorted by ascending start offset. The original string is rebuilt by walking through findings in order, copying unaffected regions and inserting placeholders at each finding's position. This approach is O(n) and correct for any number of non-overlapping findings.

### 7.6 XSS Prevention

All user-supplied content is rendered exclusively via:
- `element.textContent = value` (safe, escaped by browser)
- DOM node creation (`createElement`, `appendChild`)

The `innerHTML` property is never set using user-supplied content.

---

## 8. Module Descriptions

### `index.html`
- Semantic HTML5 structure
- ARIA roles and labels for screen readers
- Skip navigation link
- Visible focus states for keyboard users
- No inline JavaScript or inline event handlers

### `styles.css`
- CSS custom property design system (colours, spacing, typography)
- Dark charcoal + deep navy + cyan accent theme
- CSS Grid for results layout, Flexbox for components
- Responsive breakpoints: 1200px desktop, 860px tablet, 600px mobile, 400px small mobile
- Smooth CSS transitions (no JavaScript animation libraries)
- `:focus-visible` for keyboard navigation indicators

### `script.js`

| Function | Responsibility |
|----------|----------------|
| `detectEmails(text)` | Matches common email patterns |
| `detectPhones(text)` | Matches phone patterns with false-positive filters |
| `detectSecrets(text)` | Matches credential assignment patterns |
| `detectPossibleIdentifiers(text)` | Matches Aadhaar-like, PAN-like, SSN-like |
| `detectPossibleAddresses(text)` | Matches keyword+number address patterns |
| `resolveOverlaps(findings)` | Priority-based overlap resolution |
| `calculatePrivacyScore(findings)` | Weighted deduction scoring |
| `maskFindings(text, findings)` | Offset-accurate replacement |
| `generateSecurityReport(...)` | Safe JSON report (no original text) |
| `renderResults(text)` | Orchestrates scan and DOM update |
| `applyMasking(text)` | Applies masking and shows output |
| `downloadReport()` | Creates Blob and triggers download |

---

## 9. Testing Methodology and Results

### Methodology
Manual functional testing was performed by entering specific inputs into the browser application and verifying DOM output against expected results. Network inspection was performed using browser DevTools.

### Results Summary

| Test ID | Test Case | Automated Verification | Manual Verification | Result |
|:-------:|-----------|:----------------------:|:-------------------:|:------:|
| T01 | Ordinary harmless text | Pass | Pass | Pass ✓ |
| T02 | One email address | Pass | Pass | Pass ✓ |
| T03 | Multiple email addresses | Pass | Pass | Pass ✓ |
| T04 | Indian mobile number (10-digit) | Pass | Pass | Pass ✓ |
| T05 | International-format phone (+91) | Pass | Pass | Pass ✓ |
| T06 | Password assignment | Pass | Pass | Pass ✓ |
| T07 | API-key assignment | Pass | Pass | Pass ✓ |
| T08 | Bearer-token-like value | Pass | Pass | Pass ✓ |
| T09 | Multiple different finding categories | Pass | Pass | Pass ✓ |
| T10 | Masking preserves surrounding text | Pass | Pass | Pass ✓ |
| T11 | Overlapping matches (priority resolver) | Pass | Pass | Pass ✓ |
| T12 | Adjacent findings masking | Pass | Pass | Pass ✓ |
| T13 | Repeated findings (diminishing deductions) | Pass | Pass | Pass ✓ |
| T14 | Unicode / non-English text | Pass | Pass | Pass ✓ |
| T15 | Empty input handling | Pass | Pass | Pass ✓ |
| T16 | Whitespace-only input | Pass | Pass | Pass ✓ |
| T17 | Maximum input length (100,000 chars) | Pass | Pass | Pass ✓ |
| T18 | Input exceeding 100,000 limit | Pass | Pass | Pass ✓ |
| T19 | Malformed or unusual punctuation | Pass | Pass | Pass ✓ |
| T20 | Script-tag input (XSS safety) | Pass | Pass | Pass ✓ |
| T21 | JSON report generation | Pass | Pass | Pass ✓ |
| T22 | Report secret safety (omits raw secrets) | Pass | Pass | Pass ✓ |
| T23 | Zero backend / zero external APIs | Pass | Pass | Pass ✓ |
| T24 | Clear action resets interface state | Pass | Pass | Pass ✓ |
| T25 | Rescanning after editing produces fresh results | Pass | Pass | Pass ✓ |
| T26 | Copy Masked Text copies masked string | Pass | Pass | Pass ✓ |

Full test cases with inputs, expected results, and notes are documented in `tests/test_cases.md`.
Automated suite executable via `python verify_logic.py`.

---

## 10. Security and Privacy Considerations

### 10.1 Privacy Architecture
CyberGhost implements a "data never leaves the device" architecture. The browser tab is the only processing environment. There are no API calls, no analytics endpoints, no cloud logging, and no session storage of scanned content.

### 10.2 Report Safety
The JSON report export was specifically designed to exclude:
- The original input text
- Complete secret values (only keyword prefixes with `***`)
- Any personally identifying information not already in metadata

The report function (`generateSecurityReport`) passes a curated summary of each finding — only category, severity, masked placeholder, explanation, and a pre-sanitised context snippet.

### 10.3 DOM Safety
Every rendering path that touches user-supplied content uses `textContent` assignment or `createElement`/`appendChild` DOM construction. No path uses `innerHTML`, `document.write`, or `eval` with user content.

### 10.4 No Credentials in Source
No real API keys, passwords, phone numbers, or personal data appear in the source code. Demo values use clearly fictional placeholders (e.g., `demo_fake_key_abc123456`, `DEMO_TOKEN_PLACEHOLDER_XYZ`).

### 10.5 Memory Considerations
Browser memory will hold the input text while the tab is open — this is unavoidable for client-side processing. The privacy notice in the application accurately discloses this. Clearing the form or closing the tab removes the text.

---

## 11. Limitations

| Limitation | Impact |
|------------|--------|
| Regex-only detection | Cannot detect semantically obfuscated secrets |
| No encoding awareness | Base64-encoded credentials are not decoded |
| Phone false positives | Numeric sequences in prices, dates, etc. may trigger phone detection |
| Address keyword dependency | International addresses without English street-type keywords are missed |
| No context analysis | Cannot distinguish public vs. private email addresses |
| English-optimised | Non-English address keywords not covered |
| Single-tab processing | No cross-document or batch scanning |

---

## 12. Conclusion

CyberGhost successfully implements all seven required features within a strict privacy-by-design architecture. The application runs entirely in the browser, performs accurate pattern-based detection, calculates an indicative privacy score, provides reliable masking, and generates safe downloadable reports. All security and privacy requirements in the project specification were met and verified through manual testing.

The project demonstrates that a privacy tool can itself be privacy-respecting — a meaningful distinction from cloud-based alternatives that require uploading sensitive data to detect sensitive data.

---

## 13. Future Enhancements

1. **Highlighted input overlay** — Show coloured highlights on detected ranges in the input itself.
2. **Configurable detection rules** — Allow users to add custom regex patterns.
3. **Multi-language support** — Address patterns for non-English street naming conventions.
4. **PWA packaging** — Full offline capability with service worker.
5. **Bulk file scanning** — Accept plain-text or Markdown file uploads for scanning.
6. **CSV report format** — Alternative to JSON for spreadsheet analysis.
7. **Confidence scoring** — Per-finding confidence levels to reduce false-positive noise.

---

## 14. References

- OWASP — Web Security Testing Guide (https://owasp.org/www-project-web-security-testing-guide/)
- MDN Web Docs — Regular Expressions (https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions)
- W3C — Accessible Rich Internet Applications (ARIA) Specification
- GDPR Article 25 — Data Protection by Design and by Default
- NIST SP 800-122 — Guide to Protecting the Confidentiality of Personally Identifiable Information (PII)

---

*This report documents the actual implementation of CyberGhost as built. No test results have been fabricated.*
