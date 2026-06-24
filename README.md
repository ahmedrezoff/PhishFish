 PhishFish — Advanced URL Phishing Detection Engine
A local, offline-capable phishing detection tool with an enterprise-grade heuristics engine, 450k+ URL dataset lookups, and a dark-mode SOC dashboard GUI.

Overview
PhishFish analyzes URLs for phishing indicators using a multi-layered detection pipeline — no cloud API, no rate limits, no data sent anywhere. Everything runs on your machine.

It combines a pre-loaded dataset of 450,000+ confirmed phishing/legitimate URLs with a live heuristics engine that can catch zero-day threats the dataset has never seen.

Available as both a polished CLI tool and a dark-mode Tkinter GUI.

Features
Detection Engine (16 Heuristic Checks)
Check	Description
Shannon Entropy Analysis	Detects DGA/botnet domains by measuring character randomness. Domains like xkqjfvmzpwhb.xyz have high entropy (> 3.5 bits).
Levenshtein Distance	Catches typosquatting via edit distance ≤ 2 against 40+ protected brands. Catches paypa1.com, g00gle.com, etc.
IP Obfuscation Detection	Detects all four IP encoding schemes: plain decimal, hex octets (0xC0.0xA8...), octal (0300.0250...), DWORD integer.
Punycode / Homograph Attacks	Flags xn-- prefixed domains used to mimic ASCII with lookalike Unicode characters.
Brand Hijacking	Detects brand names (PayPal, Google, Apple, etc.) used deceptively in subdomains: paypal.evil.com.
@ Symbol Injection	Detects user:pass@evil.com URL structure that visually mimics a trusted brand before the @.
Digit Substitution	Catches leetspeak spoof domains: paypa1.com (1→l), g00gle.com (0→o), appl3.com (3→e).
URL Path Payload Analysis	Scans path/query for executables, Base64 payloads, open redirects, path traversal, command injection, XSS.
Keyword Semantics	Multi-category keyword engine: Financial × Urgency × Auth combinations reveal phishing intent.
TLD Reputation	Flags 40+ TLDs statistically over-represented in malware: .xyz, .top, .tk, .ml, .cf, etc.
URL Shortener Detection	Flags 30+ known URL shortening services that mask real destinations.
WHOIS Age Intelligence	Domains under 180 days old are flagged as suspicious (campaign infrastructure is almost always fresh).
Subdomain Depth Analysis	Deep nesting like login.secure.update.verify.evil.com is flagged.
Hyphen Abuse	Detects keyword-stuffed domains: secure-paypal-account-verify-login.com.
Non-Standard Port	Flags unusual ports in URLs (anything not 80/443/8080).
450k URL Dataset Lookup	Instant O(1) hash table lookup against 450,000+ confirmed phishing and legitimate URLs, loaded on startup.
Dataset Integration
Zero GUI freeze — The 450k CSV streams into memory in a background daemon thread. The GUI is fully interactive from the moment it opens.
Live progress counter — Both CLI and GUI show a live entry count during loading.
O(1) lookup — Domains are stored in Python set objects. Every check is a single hash table operation.
Subdomain parent matching — If evil-site.com is in the phishing set, login.evil-site.com is also caught.
Duplicate-safe write — Adding to the manual blocklist checks for existing entries before writing.
GUI Features
4-Tab SOC Dashboard: Scanner | Blocklist Manager | Education | About
Async scan pipeline — All network calls (WHOIS) and heavy computation run in worker threads, never on the main thread
Rich console output — Color-coded by severity with per-signal explanations
Blocklist Manager tab — View, add, and remove manual blocklist entries with a Treeview table
Education tab — Collapsible attack technique reference cards with example URLs and defense tips
Export Reports — Save scan results as JSON (machine-readable) or plain TXT (email/ticket-friendly) via file dialog
Keyboard shortcuts — Enter to scan, Ctrl+L to focus URL input, Ctrl+E to export
Auto-blocklist prompt — If a high-risk unknown domain is detected, GUI prompts to add it to the manual blocklist
Installation
Prerequisites
Python 3.10+ (uses str | None union type hints)
pip
Install Dependencies
pip install python-whois
That's the only external dependency. Everything else uses Python's standard library.

Clone / Download
git clone https://github.com/yourusername/phishfish.git
cd phishfish
Dataset Setup
Place your URL dataset.csv file in the project root directory. https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls e.g Dataset from this site

Expected format — no header row, one URL per line:

https://www.google.com/,legitimate
http://paypal.security-alert.evil.com/,phishing
https://amazon.com/,legitimate
http://0xC0.0xA8.0x01.0x01/login.php,phishing
Supported label values: phishing, legitimate (also accepts benign, safe, clean)

The tool runs fully functional without the dataset — it falls back to heuristics-only mode.

Usage
GUI Mode
python gui.py
Wait for the status indicator to turn green (dataset loaded)
Paste a URL into the input field
Press Enter or click SCAN
Read the color-coded threat report in the console
Use the Blocklist, Education, and About tabs as needed
CLI Mode
python main.py
Interactive menu:

  [1]  Deep Scan URL         — Full heuristics + WHOIS pipeline
  [2]  View Manual Blocklist — Inspect your local block registry
  [3]  Add Threat Signature  — Manually blacklist a domain
  [4]  Remove from Blocklist — Remove a domain entry
  [5]  Threat Education      — Common attack vectors & detection
  [6]  Export Last Report    — Save scan results as JSON/TXT
  [0]  Terminate             — Exit PhishFish
Project Structure
phishfish/
├── main.py               # CLI orchestrator and menu loop
├── gui.py                # Tkinter SOC dashboard (4 tabs)
├── analyzer.py           # Core heuristics engine (all 16 checks)
├── blocklist_manager.py  # Dataset loading, O(1) lookup, blocklist I/O
├── whois_checker.py      # WHOIS lookup with threaded timeout
├── risk_calculator.py    # Tiered scoring engine (0–100)
├── display.py            # CLI renderer + JSON/TXT export
├── education.py          # Attack vector content (CLI + GUI)
├── blocklist.txt         # Manual blocklist (auto-created)
├── URL dataset.csv       # Your 450k URL dataset (you provide this)
└── README.md
Risk Scoring
Scores are additive across 6 weighted tiers:

Tier	Signals	Weight
T1 — Structural Deception	IP obfuscation, brand hijacking, typosquatting, punycode, @ injection, digit substitution	+60 to +90
T2 — Behavioral Indicators	High entropy (DGA), path payloads, sketchy TLD, URL shortener, hyphen abuse	+20 to +50
T3 — Keyword Combinatorics	Financial × Urgency × Auth combos	+10 to +55
T4 — Structural Heuristics	Subdomain depth, URL length	+8 to +25
T5 — WHOIS Trust Signals	Domain age < 180 days, unknown registrar	+12 to +35
T6 — Soft Signals	HTTP (not HTTPS)	+10
Verdict thresholds:

Score	Verdict	Meaning
75–100	🔴 MALICIOUS	High-confidence threat. Do not visit.
45–74	🟡 SUSPICIOUS	Meaningful signals. Proceed with extreme caution.
0–44	🟢 SAFE	No significant heuristic flags fired.
⚠️ Note: SAFE does not mean "guaranteed clean." It means the heuristics found nothing. Zero-day phishing URLs pass everything until they're caught and added to a dataset.

Architecture Notes
Why No Async/Await?
Tkinter is not thread-safe and doesn't integrate with Python's asyncio event loop without significant complexity. Instead, PhishFish uses the standard threading pattern for Tkinter:

Heavy work happens in threading.Thread(daemon=True) workers
Workers communicate results back using window.after(0, callback, data)
window.after() safely queues the callback on the Tkinter main thread
The main thread never blocks
This is simpler, more debuggable, and just as performant for this use case.

Why Not Pandas for the CSV?
Pandas adds ~60MB of overhead and ~1 second of import time for a task that Python's built-in csv.reader handles perfectly. The CSV is read once, streamed line-by-line, and the domains land in a set. That's all we need.

WHOIS Timeout Strategy
The original code used socket.setdefaulttimeout(5.0) — a global that poisons every socket operation in the process. The replacement uses concurrent.futures.ThreadPoolExecutor with a future.result(timeout=6.0) call, which imposes a per-call timeout without touching global state.

Adding Custom Threat Intelligence
Manual Blocklist (blocklist.txt)
Add one domain per line. Lines starting with # are ignored.

# My custom blocks
evil-phishing-site.com
fake-bank-login.net
Extending Brand Protection
In analyzer.py, add to HIJACKABLE_BRANDS:

HIJACKABLE_BRANDS = [
    # ... existing brands ...
    'yourcompany',
    'newbrand',
]
Extending Sketchy TLDs
In analyzer.py, add to SKETCHY_TLDS:

SKETCHY_TLDS = {
    # ... existing TLDs ...
    '.newtld',
}
Known Limitations
WHOIS coverage: Some registrars block WHOIS lookups or rate-limit heavily. If WHOIS fails, the tool falls back to heuristics-only for that check.
Dataset recall: The CSV dataset only catches domains it's seen before. Novel phishing infrastructure is handled by heuristics, not the dataset.
False positives on high-entropy legitimate domains: Some CDN subdomains and hash-based URLs can trigger the entropy check. The score weighting keeps single-flag detections in the SUSPICIOUS range rather than MALICIOUS.
Shortener chains: PhishFish flags URL shorteners but doesn't follow redirect chains. It cannot inspect the final destination of a shortened URL.
License
MIT License. Do whatever you want with it — just don't use it to build better phishing infrastructure, that would be deeply ironic lmao

TEAM
Ahmed | Wania Rehman | Roman Fatima | Muhammad Ali |
