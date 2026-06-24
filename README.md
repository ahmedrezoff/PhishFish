# 🐟 PhishFish

**Offline Enterprise-Style Phishing Detection Platform**

PhishFish is a local, offline phishing detection platform designed to identify malicious URLs using a multi-layered security analysis engine. It combines a database of **450,000+ verified phishing and legitimate URLs** with advanced heuristic analysis to detect both known threats and previously unseen phishing attacks.

Unlike cloud-based scanners, **all analysis is performed locally**—no APIs, no rate limits, and no user data leaves your machine.

---
## Key Features

### Intelligent URL Analysis

* Detects phishing using **16 independent heuristic checks**
* Shannon Entropy Analysis for DGA and randomly generated domains
* Typosquatting detection using Levenshtein Distance
* Brand hijacking detection
* Punycode and Unicode homograph detection
* IP obfuscation detection (Decimal, Hexadecimal, Octal, DWORD)
* Digit substitution detection (paypa1.com, g00gle.com)
* URL payload analysis for XSS, redirects, executables, Base64 payloads, and command injection
* Suspicious keyword analysis
* Sketchy TLD detection
* URL shortener detection
* Deep subdomain analysis
* Hyphen abuse detection
* Non-standard port detection
* WHOIS domain age analysis

### Threat Intelligence

* 450,000+ verified phishing and legitimate URLs
* Instant O(1) hash-table lookups
* Parent domain matching
* Manual blocklist support
* Duplicate-safe blocklist management

### Desktop SOC Dashboard

* Dark-mode Security Operations Center (SOC) interface
* Multi-threaded scanning
* Blocklist Manager
* Threat Education Center
* Export reports as JSON or TXT
* Keyboard shortcuts
* Real-time dataset loading progress

---

## Detection Pipeline

```
Input URL
     │
     ▼
450k Dataset Lookup
     │
     ▼
16 Heuristic Checks
     │
     ▼
WHOIS Intelligence
     │
     ▼
Risk Scoring Engine
     │
     ▼
Threat Classification
     │
     ▼
SOC Dashboard Report
```

---

## Risk Scoring

Every detected signal contributes to an overall risk score.

| Score    | Verdict       |
| -------- | ------------- |
| 75 – 100 | 🔴 Malicious  |
| 45 – 74  | 🟡 Suspicious |
| 0 – 44   | 🟢 Safe       |

> **Note:** A "Safe" verdict simply means no significant indicators were detected. It does not guarantee that a URL is completely harmless.

---

## Tech Stack

* Python 3.10+
* Tkinter
* Python-WHOIS
* CSV
* Threading
* Concurrent Futures
* Hash Tables
* JSON

---

## Project Structure

```
phishfish/
│
├── analyzer.py
├── gui.py
├── main.py
├── risk_calculator.py
├── blocklist_manager.py
├── whois_checker.py
├── display.py
├── education.py
├── blocklist.txt
├── URL dataset.csv
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/femme20/PhishFish.git
cd PhishFish
```

Install the only required dependency:

```bash
pip install python-whois
```

---

## Dataset

Download the phishing dataset from Kaggle:

https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls

Place the downloaded **URL dataset.csv** file inside the project folder.

Expected format:

```csv
https://www.google.com/,legitimate
http://paypal.security-alert.evil.com/,phishing
https://amazon.com/,legitimate
http://0xC0.0xA8.0x01.0x01/login.php,phishing
```

Supported labels:

* phishing
* legitimate
* benign
* safe
* clean

If no dataset is provided, PhishFish automatically switches to **heuristics-only mode**.

---

## Running the Application

### GUI

```bash
python gui.py
```

Wait until the dataset finishes loading, enter a URL, and press **Enter** or click **Scan**.

### Command Line

```bash
python main.py
```

The CLI provides:

* Deep URL Scan
* Blocklist Manager
* Threat Education
* Report Export
* Manual Threat Management

---

## Example Scan

```
URL:
https://paypa1-login.xyz

Detected Signals:
✔ Typosquatting
✔ Brand Hijacking
✔ Sketchy TLD
✔ Recently Registered Domain

Risk Score:
91

Verdict:
🔴 MALICIOUS
```

---

## Design Decisions

PhishFish was designed to remain lightweight, responsive, and privacy-focused.

Instead of relying on cloud APIs, every scan runs locally. The application combines historical threat intelligence with heuristic analysis to improve detection of newly created phishing infrastructure while protecting user privacy.

Heavy operations such as dataset loading and WHOIS requests run in background threads, ensuring that the graphical interface remains responsive at all times.

---

## Future Improvements

* Machine Learning-based phishing classification
* Browser extension
* Redirect chain analysis
* DNS intelligence
* VirusTotal integration
* REST API
* Email phishing analysis

---

## Team

* Ahmed
* Wania Rehman
* Roman Fatima
* Muhammad Ali

---

## License

This project is licensed under the MIT License.( Do whatever you want with it — just don't use it to build better phishing infrastructure, that would be deeply ironic lmao)
