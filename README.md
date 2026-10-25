# CyberGhost — Hidden Privacy Risk Detector

**IBM SkillsBuild Cybersecurity BootCamp Project**

---

## Abstract

CyberGhost is a browser-based privacy risk detection tool that scans text for potentially sensitive information — email addresses, phone numbers, API secrets, government-style identifier patterns, and postal address patterns — entirely on the user's device without uploading any data to a server.

---

## Problem Statement

People routinely expose personal and sensitive information when composing social-media posts, emails, shared documents, and public messages. Common accidental disclosures include personal email addresses, mobile phone numbers, embedded API keys or passwords, government-issued identifier numbers, and home addresses. Most users lack a simple, trustworthy tool that can review text locally before sharing.

---

## Objectives

1. Detect seven categories of potentially sensitive text patterns using client-side JavaScript.
2. Calculate an indicative privacy score (0–100) to communicate risk level.
3. Allow users to mask detected information with safe placeholders before sharing.
4. Generate a JSON security report containing only metadata — never the original input.
5. Maintain a strict privacy-by-design architecture: no backend, no uploads, no tracking.

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Text Scanner** | Accepts up to 100,000 characters; validates input; Ctrl+Enter shortcut |
| 2 | **Email Detection** | RFC-ish regex detection of common email formats |
| 3 | **Phone Detection** | Indian mobile (10-digit, +91 prefix), international, US formats |
| 4 | **Secret Detection** | password=, api_key=, token=, Bearer headers, PEM markers |
| 5 | **Identifier Detection** | Aadhaar-like 12-digit, PAN-like, SSN-like patterns |
| 6 | **Address Detection** | Keyword + number heuristics for street/postal addresses |
| 7 | **Privacy Score** | 0–100 score with risk category and deduction explanation |
| 8 | **Automatic Masking** | Replaces findings with [EMAIL REDACTED], [SECRET REDACTED] etc. |
| 9 | **Security Report** | Downloadable JSON with metadata only — no original text |

---

## Architecture

```
User's Browser
│
├── index.html      — UI structure, ARIA accessibility, semantic HTML5
├── styles.css      — Dark-theme responsive cybersecurity dashboard (no external CSS)
└── script.js       — Detection engine + UI logic
    ├── detectEmails()
    ├── detectPhones()
    ├── detectSecrets()
    ├── detectPossibleIdentifiers()
    ├── detectPossibleAddresses()
    ├── resolveOverlaps()        ← priority-based overlap resolution
    ├── calculatePrivacyScore()
    ├── maskFindings()           ← offset-accurate replacement
    └── generateSecurityReport() ← never includes original text
```

**No server. No API. No framework. No build step.**

---

## Technologies

- HTML5 — Semantic structure, ARIA attributes
- CSS3 — Custom properties, Grid, Flexbox, animations
- Vanilla JavaScript (ES2020) — Detection engine, DOM manipulation
- Regular Expressions — Pattern detection
- Web Blob API — Client-side JSON report download

---

## Project Structure

```
CyberGhost/
├── index.html              Main application page
├── styles.css              Dashboard stylesheet
├── script.js               Detection engine and UI logic
├── README.md               This file
├── requirements.txt        Dependency declaration
├── .gitignore              Git ignore rules
├── LICENSE                 MIT License
├── tests/
│   └── test_cases.md       Manual test cases and results
└── docs/
    └── PROJECT_REPORT.md   Full project report
```

---

## Setup and Run Instructions

### Prerequisites
- A modern web browser (Chrome 90+, Firefox 88+, Edge 90+, Safari 14+)
- No Python, Node.js, or other runtime required
- Optional: VS Code with the Live Server extension

### Running Locally

**Option A — Direct file open (simplest)**
```
1. Download or clone this repository.
2. Open CyberGhost/index.html in your web browser.
   (Right-click → Open with → Browser)
```

**Option B — VS Code Live Server**
```
1. Open the CyberGhost/ folder in VS Code.
2. Install the "Live Server" extension (ritwickdey.liveserver).
3. Right-click index.html → Open with Live Server.
4. Browser opens at http://127.0.0.1:5500
```

**Option C — Python local server (optional convenience)**
```bash
# From the CyberGhost/ directory:
python -m http.server 8080
# Then open http://localhost:8080 in your browser
```

---

## Usage Instructions

1. **Paste text** into the large input area.
2. Click **Scan Text** (or press Ctrl+Enter).
3. Review the **Privacy Score** and **Findings**.
4. Click **Mask Sensitive Information** to generate masked output.
5. Use **Copy Masked Text** to copy to clipboard.
6. Click **Download Report (JSON)** for a metadata-only report.
7. Click **Clear All** to reset.

---

## Detection Limitations

| Limitation | Detail |
|------------|--------|
| Pattern-only matching | Cannot confirm whether a matched value is real or active |
| False positives | Numbers may match phone patterns; addresses rely on keywords |
| Novel formats | Secrets with unusual naming conventions may be missed |
| Encoding | Obfuscated or encoded secrets are not decoded |
| Language | Optimised for English-language text |
| Context-free | Cannot infer whether sharing is safe from context |

Always review findings manually. Do not rely solely on CyberGhost for security decisions.

---

## Privacy-by-Design

- ✅ **No server** — no backend exists
- ✅ **No uploads** — text never leaves the browser tab
- ✅ **No storage** — no localStorage, sessionStorage, or cookies used for scanned content
- ✅ **No analytics** — no tracking scripts or third-party requests
- ✅ **No external resources** — no CDN fonts, external CSS, or remote scripts
- ✅ **XSS safe** — user input is rendered with `textContent`, never `innerHTML`
- ✅ **Report safety** — downloaded JSON never contains the original input text

---

## Testing Instructions

See `tests/test_cases.md` for the full manual test plan.

Quick smoke test:
1. Open `index.html`.
2. Click **Load Demo** to load sample text.
3. Click **Scan Text**.
4. Verify findings appear across all categories.
5. Click **Mask Sensitive Information** and verify replacement.
6. Click **Download Report** and open the JSON — confirm no original text is present.

---

## Known Limitations

- The phone regex may flag long numeric sequences that are not phone numbers.
- Address detection is keyword-dependent and may miss unusual formats.
- Very long inputs (close to 100,000 chars) are supported but may take slightly longer to scan.
- The Aadhaar regex matches any 12-digit sequence and is not a validator.

---

## Future Enhancements

- [ ] Highlight matched text directly in the input area
- [ ] Category-level toggle to enable/disable detection types
- [ ] Multi-language support
- [ ] Custom regex rules via user configuration
- [ ] Export masked text as a plain-text file
- [ ] Offline Progressive Web App (PWA) wrapper

---

## GitHub Repository

`https://github.com/Keerthika-Cyber/CyberGhost-Hidden-Privacy-Risk-Detector.git

---

## License

MIT License. See `LICENSE` for details.
