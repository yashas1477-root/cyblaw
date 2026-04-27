THEME-16: Supply Chain Integrity and Software Piracy
A Fuzzing-Driven Study of X.509 Certificate Vulnerabilities

Department of Computer Science & Engineering (Cyber Security)
JAIN Deemed-to-be University



Overview

This repository contains the research report and source code for **THEME-16**, a Systematic Literature Review (SLR) on X.509 digital certificate vulnerabilities and how fuzzing-based defensive techniques can detect them before attackers exploit them.

---

Repository Structure

```
cyblaw/
├── README.md
├── reports/
│   ├── THEME-16_final_report.docx
│   └── THEME-16_final_report.pdf
└── code/
    ├── main.py                    ← Run this first
    ├── differential_fuzzer.py
    ├── cert_generator.py
    ├── greybox_fuzzer.py
    └── tcev_classifier.py
```

---

TCEV Taxonomy (6 Categories)

| Code | Category | Description |
|------|----------|-------------|
| TCEV-1 | CA Trust Abuse | Exploiting Certificate Authority trust relationships |
| TCEV-2 | Parsing Logic Exploitation | ASN.1/DER parsing bugs — most studied (21 papers) |
| TCEV-3 | Chain Validation Bypass | Certificate chain path validation bugs |
| TCEV-4 | Cryptographic Downgrade | Algorithm negotiation manipulation |
| TCEV-5 | Revocation Bypass | Certificate revocation checking evasion |
| TCEV-6 | Supply Chain Injection | Injection into software update pipelines |

---

How to Run

```bash
cd code
python main.py
```
No external libraries required — runs on standard Python 3.9+.
