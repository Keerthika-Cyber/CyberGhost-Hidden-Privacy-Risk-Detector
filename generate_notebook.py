"""
generate_notebook.py
Creates cyberghost_submission.ipynb for the IBM SkillsBuild submission form.
Run: python generate_notebook.py
"""
import json
import pathlib

BASE = pathlib.Path(__file__).parent

def read(filename):
    return (BASE / filename).read_text(encoding="utf-8")

html_src = read("index.html")
css_src  = read("styles.css")
js_src   = read("script.js")
readme   = read("README.md")


def md_cell(lines):
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": lines if isinstance(lines, list) else [lines]
    }


def code_cell(lines):
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": lines if isinstance(lines, list) else [lines]
    }


PYTHON_PSEUDOCODE = """\
\"\"\"
CyberGhost — Detection Logic (Python pseudocode / conceptual equivalent)

This code documents the logic implemented in script.js.
The browser application runs the equivalent logic in JavaScript — not Python.
No real credentials or personal data appear in this file.
\"\"\"

import re

SCORE_WEIGHTS = {
    "email":      15,
    "phone":      20,
    "secret":     35,
    "identifier": 25,
    "address":    20,
}

MASK_LABELS = {
    "email":      "[EMAIL REDACTED]",
    "phone":      "[PHONE REDACTED]",
    "secret":     "[SECRET REDACTED]",
    "identifier": "[IDENTIFIER REDACTED]",
    "address":    "[ADDRESS REDACTED]",
}

PRIORITY = {"secret": 0, "identifier": 1, "address": 2, "phone": 3, "email": 4}


def detect_emails(text):
    pattern = r"[a-zA-Z0-9._%+\\-]{1,64}@[a-zA-Z0-9.\\-]{1,253}\\.[a-zA-Z]{2,10}"
    return [(m.start(), m.end(), "email") for m in re.finditer(pattern, text)]


def detect_phones(text):
    pattern = r"(?<!\\d)(\\+?\\d{1,3}[\\s\\-])?(\\(?\\d{2,4}\\)?[\\s\\-])?\\d{3,5}[\\s\\-]?\\d{4,6}(?!\\d)"
    results = []
    for m in re.finditer(pattern, text):
        digits = re.sub(r"\\D", "", m.group())
        if len(digits) < 7 or len(digits) > 15:
            continue
        if re.match(r"^(.)\\1+$", digits):
            continue  # all same digit
        if len(digits) == 4 and 1900 <= int(digits) <= 2099:
            continue  # year-like
        results.append((m.start(), m.end(), "phone"))
    return results


def detect_secrets(text):
    pattern = (r"(?:password|passwd|pwd|secret|token|api[_\\-]?key|"
               r"access[_\\-]?key|client[_\\-]?secret|auth[_\\-]?token|"
               r"bearer|private[_\\-]?key)[\\s]*[=:][\\s]*\\S+")
    return [(m.start(), m.end(), "secret") for m in re.finditer(pattern, text, re.IGNORECASE)]


def detect_possible_identifiers(text):
    results = []
    for pat in [
        r"\\b\\d{4}\\s?\\d{4}\\s?\\d{4}\\b",   # Aadhaar-like
        r"\\b[A-Z]{5}[0-9]{4}[A-Z]\\b",          # PAN-like
        r"\\b\\d{3}[\\-\\s]?\\d{2}[\\-\\s]?\\d{4}\\b", # SSN-like
    ]:
        results += [(m.start(), m.end(), "identifier") for m in re.finditer(pat, text)]
    return results


def detect_possible_addresses(text):
    pattern = (r"(?:(?:\\d{1,5}\\s+)?(?:[A-Za-z]+\\s+){1,4}"
               r"(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|"
               r"Boulevard|Blvd|Nagar|Colony|Sector|Block|Apartment|Apt|"
               r"Flat|Floor|Building|Plot|House|Cross|Main)[\\s,]?\\d{0,5})")
    return [(m.start(), m.end(), "address") for m in re.finditer(pattern, text, re.IGNORECASE)]


def resolve_overlaps(findings):
    sorted_f = sorted(findings, key=lambda x: (PRIORITY.get(x[2], 99), x[0]))
    accepted = []
    for f in sorted_f:
        overlaps = any(f[0] < a[1] and f[1] > a[0] for a in accepted)
        if not overlaps:
            accepted.append(f)
    return sorted(accepted, key=lambda x: x[0])


def calculate_privacy_score(findings):
    counts = {}
    for (_, _, cat) in findings:
        counts[cat] = counts.get(cat, 0) + 1
    total_deduction = 0
    for cat, count in counts.items():
        w = SCORE_WEIGHTS.get(cat, 10)
        total_deduction += w + (count - 1) * ((w + 1) // 2)
    return max(0, min(100, 100 - total_deduction))


def mask_findings(text, findings):
    result, cursor = "", 0
    for (start, end, cat) in sorted(findings, key=lambda x: x[0]):
        result += text[cursor:start]
        result += MASK_LABELS.get(cat, "[REDACTED]")
        cursor = end
    return result + text[cursor:]


def generate_safe_report(findings, score):
    \"\"\"Returns a dict that NEVER includes original text or full secret values.\"\"\"
    return {
        "privacyScore": score,
        "totalFindings": len(findings),
        "findings": [
            {"category": cat, "placeholder": MASK_LABELS.get(cat, "[REDACTED]")}
            for (_, _, cat) in findings
        ],
        "disclaimer": (
            "Educational indicator only. Not a security certification. "
            "Pattern matching may produce false positives."
        ),
    }


# ---- Demo run (fictional data only) ----
if __name__ == "__main__":
    sample = (
        "Contact arjun@example.com or call +91 9876543210. "
        "api_key=demo_fake_key_abc123"
    )
    all_findings = (
        detect_emails(sample)
        + detect_phones(sample)
        + detect_secrets(sample)
        + detect_possible_identifiers(sample)
        + detect_possible_addresses(sample)
    )
    resolved = resolve_overlaps(all_findings)
    score    = calculate_privacy_score(resolved)
    masked   = mask_findings(sample, resolved)
    report   = generate_safe_report(resolved, score)

    print(f"Findings : {len(resolved)}")
    print(f"Score    : {score}/100")
    print(f"Masked   : {masked}")
    print("Report   :", json.dumps(report, indent=2))
"""

cells = [
    md_cell([
        "# CyberGhost — Hidden Privacy Risk Detector\n",
        "## IBM SkillsBuild Cybersecurity BootCamp — Source Listing Notebook\n\n",
        "---\n\n",
        "> **Important:** CyberGhost is a **browser-based application**. "
        "This notebook is a *source-code listing and documentation artifact* submitted to satisfy "
        "the IBM SkillsBuild form requirement for a `.ipynb` file. "
        "**The actual executable application is `index.html`** — open it in any modern browser. "
        "No Python, server, or installation is required to run the app.\n\n",
        "---\n\n",
        "## How to Run the Real Application\n\n",
        "```\n",
        "1. Open CyberGhost/index.html in Chrome, Firefox, or Edge.\n",
        "2. Paste text into the scanner.\n",
        "3. Click Scan Text.\n",
        "```\n\n",
        "No Python, Node.js, or internet connection required.\n\n",
        "---\n\n",
        "## Contents of This Notebook\n\n",
        "| Section | Contents |\n",
        "|---------|----------|\n",
        "| 1 | README / Project overview |\n",
        "| 2 | `index.html` — full HTML source |\n",
        "| 3 | `styles.css` — full CSS source |\n",
        "| 4 | `script.js` — full JavaScript detection engine |\n",
        "| 5 | Detection logic in Python pseudocode (runnable demo) |\n",
        "| 6 | Privacy and security notes |\n",
    ]),

    md_cell(["## Section 1 — Project README\n\n", readme]),

    md_cell(["## Section 2 — index.html (Full Source)\n\n",
             "```html\n", html_src, "\n```"]),

    md_cell(["## Section 3 — styles.css (Full Source)\n\n",
             "```css\n", css_src, "\n```"]),

    md_cell(["## Section 4 — script.js (Full Source)\n\n",
             "```javascript\n", js_src, "\n```"]),

    md_cell([
        "## Section 5 — Detection Logic in Python Pseudocode\n\n",
        "The cell below contains a runnable Python equivalent of the core detection logic "
        "from `script.js`. It uses only the Python standard library — no packages required. "
        "Run it to see a demonstration with fictional sample data.\n",
    ]),

    code_cell(PYTHON_PSEUDOCODE),

    md_cell([
        "## Section 6 — Privacy and Security Notes\n\n",
        "### Privacy Architecture\n",
        "- All detection runs in the browser (JavaScript). No text is uploaded anywhere.\n",
        "- The downloaded JSON report contains only metadata — never the original input.\n",
        "- No localStorage, sessionStorage, or cookies store scanned content.\n",
        "- No external scripts, CDN fonts, or analytics are loaded.\n\n",
        "### XSS Prevention\n",
        "- User input is rendered using `element.textContent` (not `innerHTML`).\n",
        "- DOM nodes are built with `createElement` / `appendChild`.\n\n",
        "### Limitations\n",
        "- Pattern matching cannot detect every format of sensitive data.\n",
        "- False positives may occur (e.g., numeric sequences flagged as phone numbers).\n",
        "- The privacy score is an educational indicator, not a security certification.\n\n",
        "---\n",
        "*This notebook is a source-code listing for the IBM SkillsBuild submission form.*\n",
        "*The executable application is `CyberGhost/index.html`.*\n",
    ]),
]

nb = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.10.0"
        }
    },
    "cells": cells,
}

nb_json = json.dumps(nb, ensure_ascii=False, indent=1)

out1 = BASE / "CyberGhost_Privacy_Risk_Detector.ipynb"
out1.write_text(nb_json, encoding="utf-8")
print("Written:", out1)
print("Size   :", out1.stat().st_size, "bytes")

out2 = BASE / "cyberghost_submission.ipynb"
out2.write_text(nb_json, encoding="utf-8")
print("Written:", out2)
print("Size   :", out2.stat().st_size, "bytes")

