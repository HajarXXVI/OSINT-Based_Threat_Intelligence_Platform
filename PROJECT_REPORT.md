# ThreatLens — Project Report

**Project type:** Final-year academic project (PFA)
**Author:** [Your name]
**Supervisor:** [Supervisor's name]
**Date:** 11 August 2026
**Status:** In progress — core intelligence engine and web platform functional; reporting and hardening modules planned.

---

## 1. Executive Summary

ThreatLens is a **passive Open Source INTelligence (OSINT) platform** that assesses the risk of any public **IP address or domain name** and produces a structured, actionable threat report.

The user enters a target (e.g. `8.8.8.8` or `github.com`). The platform automatically gathers public data about that target from **five independent sources**, correlates the facts into **security findings**, calculates a **risk score (0–100)**, and additionally distinguishes **two risk profiles**:

- **Exposure** — how easily *this target* could be compromised by others (open ports, known vulnerabilities).
- **Threat** — how dangerous *this target* is to others (malicious reputation).

All intelligence is **passive**: the platform never sends packets to the target. It relies exclusively on data already collected by public scanning and reputation services, which makes every analysis fully legal and demoable.

---

## 2. Motivation & Problem Statement

Organizations and security analysts routinely need a quick answer to two questions about an internet-facing asset:

1. *"Is this IP/domain dangerous?"* (e.g. a suspicious IP that attacked the network).
2. *"Is our own infrastructure exposed?"* (e.g. a public server that might be compromised).

These answers exist scattered across many independent services: network scanners, vulnerability databases, antivirus reputation engines, geolocation and domain-registration services. Each source answers **one** narrow question, and none alone is conclusive.

**Problem addressed:** no single public tool aggregates, cross-references, and scores all of these signals into a single human-readable verdict. ThreatLens fills that gap with a **correlation engine** that combines facts from different sources and derives conclusions no single source provides.

---

## 3. Objectives

1. Build a web platform where a user can scan any IP or domain with one click.
2. Aggregate public intelligence from **five independent data sources**.
3. Implement a **custom correlation engine** that turns raw facts into findings with severity, explanation and recommendations.
4. Implement a **scoring model** (0–100, with LOW/MEDIUM/HIGH/CRITICAL levels) that is transparent and cannot be inflated by minor signals.
5. Distinguish **Exposure vs Threat** profiles so the report answers "is this a victim or a danger?".
6. Persist all scans in a database for **history and reporting**.
7. Provide user accounts, per-user API keys, themes and settings.

---

## 4. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Language | Python 3.13 | Entire backend and intelligence engine |
| Web framework | Flask 3.1.3 | Web application and routes |
| Database | SQLite + SQLAlchemy (ORM) | Persistent storage of users and scans |
| Authentication | Flask-Login + Flask-Bcrypt | Sessions and password hashing |
| HTTP client | requests | All external API calls |
| Certificate parsing | cryptography 50.0.0 | Decode raw DER TLS certificates |
| Frontend | Jinja2 templates + Tailwind CSS (CDN) + Font Awesome | UI styling and icons |
| Testing | unittest (Python standard library) | Unit tests for the correlation engine |
| Config | python-dotenv + `.env` | Secret management (API keys) |
| Reporting (planned) | ReportLab 4.1.0 | PDF report generation (installed, not yet wired) |

All dependencies are listed in `requirements.txt`.

---

## 5. Architecture

The project follows the **5-layer architecture** defined in the project specification.

| Layer | Responsibility | Implementation |
|---|---|---|
| **1. Presentation** | User interface and pages | `templates/*.html`, `static/style.css` |
| **2. API layer** | Communication with external services | `apis/shodan_api.py`, `apis/nvd_api.py`, `apis/virustotal_api.py`, `apis/ipapi.py`, `apis/metadata_api.py` |
| **3. Correlation** | Custom analysis logic (the core) | `engine/correlator.py`, `engine/scorer.py` |
| **4. Data** | Persistence of users and scan history | `models.py` + SQLite database (`instance/threatlens.db`) |
| **5. Reporting** | Generation of reports (PDF) | **Planned** — ReportLab installed, not yet wired |

### File structure

```
ThreatLens/
├── main.py                    # Flask application, routes, migrations
├── config.py                  # Reads .env (secret key, API keys)
├── models.py                  # User and ScanResult database models
├── requirements.txt           # Python dependencies
├── .env / .env.example        # API keys & secrets (never committed)
├── apis/                      # Layer 2 — external data sources
│   ├── shodan_api.py          # Shodan official API + free InternetDB fallback
│   ├── nvd_api.py             # NVD/NIST CVE lookups (exact ID)
│   ├── virustotal_api.py      # VirusTotal reputation (IP or domain)
│   ├── ipapi.py               # ip-api geolocation (free, no key)
│   └── metadata_api.py        # RDAP domain registration + TLS certificate
├── engine/                    # Layer 3 — the core
│   ├── correlator.py          # ThreatCorrelator rules + analyze_target() pipeline
│   └── scorer.py              # Risk scoring + Exposure/Threat profiles
├── templates/                 # Layer 1 — pages
│   ├── base.html              # Layout, navigation, flash messages
│   ├── index.html             # Dashboard: scan form + recent scans
│   ├── login.html / register.html
│   ├── settings.html          # Visual, security, intelligence, alert settings
│   ├── history.html           # All scans for the account
│   ├── control_panel.html     # Admin: user management
│   └── target_details.html    # Full intelligence report for one scan
├── static/style.css           # Custom styles
├── test/test_correclator.py   # Unit tests
└── instance/threatlens.db     # SQLite database (auto-created)
```

---

## 6. The Five Data Sources

Every source answers **one specific question**. They complement each other; no single source is sufficient.

| # | Source | Question answered | Example data | Key required |
|---|---|---|---|---|
| 1 | **ip-api** (geolocation) | "Where is this machine and who hosts it?" | country, city, ISP, organization, GPS | No |
| 2 | **Shodan** (infrastructure) | "What is exposed on its network?" | open ports, hostnames, OS, organization, detected CVEs | Optional (falls back to free InternetDB) |
| 3 | **NVD / NIST** (vulnerabilities) | "How dangerous are the known flaws?" | CVE ID, CVSS score (0–10), severity, description | No |
| 4 | **VirusTotal** (reputation) | "What do ~70 antivirus engines think?" | counts of malicious / suspicious / harmless / undetected | Yes (optional) |
| 5 | **RDAP** (domain registration) | "Who owns the domain and how old is it?" | registrar, creation date, expiration date | No |
| — | **SSL/TLS** (local) | "What TLS certificate does it present?" | issuer, subject, expiry (days left) | No (done locally via Python socket + cryptography) |

### Source details

**1. Geolocation — ip-api.com** (`apis/ipapi.py`)
Free, no API key. Returns the physical location and hosting organization of the IP. Used to understand the hosting context (e.g. cloud provider vs residential ISP).

**2. Infrastructure & ports — Shodan** (`apis/shodan_api.py`)
Shodan is the "search engine for internet-connected devices"; it has already scanned the entire internet, so its data is used **without touching the target** (passive analysis).

Two modes, in order of priority:
- **Official REST API** (`api.shodan.io`) — used when an API key is configured. Returns open ports, hostnames, OS, organization and a `vulns` map of **CVE IDs with real CVSS scores**. The real CVSS score is parsed and mapped to a severity.
- **Free InternetDB fallback** (`internetdb.shodan.io`) — no key needed. Returns open ports and CVE IDs **without scores**; the engine then resolves each exact ID against NVD to obtain real scores.

**3. Vulnerability scores — NVD/NIST** (`apis/nvd_api.py`)
The official US National Vulnerability Database. `get_cve_by_id()` fetches a single CVE by its **exact identifier** (`cveId` parameter). Returns the CVSS base score and severity. Exact-ID lookup guarantees no unrelated results.
- A keyword-search function exists (`get_nvd_vulnerabilities`) but is **not used in the default scan flow**: a generic keyword like "linux" returns unrelated CVEs and inflates the risk score. This was a deliberate engineering decision.

**4. Reputation — VirusTotal** (`apis/virustotal_api.py` and inline in `engine/correlator.py`)
VirusTotal aggregates the verdicts of ~70 antivirus engines. The engine reads `last_analysis_stats` and counts `malicious` / `suspicious` / `harmless` / `undetected`. Works for both IPs and domains. Without a key, it returns zeros rather than fabricating detections.

**5. Domain registration — RDAP** (`apis/metadata_api.py`)
RDAP (Registration Data Access Protocol) is the modern, free successor to WHOIS. The engine queries `rdap.org`, which automatically routes to the correct registry server for the TLD, and extracts the **registrar**, **creation date** and **expiration date**. IP addresses have no domain registration and correctly return N/A. (A WHOIS module previously existed as a placeholder returning hardcoded strings; it has been replaced with real RDAP lookups.)

**6. TLS certificate — local** (`apis/metadata_api.py`)
Connects to the target on port 443, performs a TLS handshake with SNI, and reads the certificate. Uses `ssl` for the handshake and the `cryptography` library to decode the raw DER certificate (see Section 12, bug fix #11).

---

## 7. The Scan Flow (end-to-end)

A scan is triggered by `POST /scan` and executed by `analyze_target()` in `engine/correlator.py`:

1. **Resolve** — `socket.gethostbyname()` converts a domain to an IP (a raw IP is used as-is).
2. **Geolocation** — ip-api returns the physical location and host.
3. **Shodan** — official API (if key) or free InternetDB returns open ports, hostnames, OS and detected CVE IDs.
4. **NVD enrichment** — every CVE ID lacking a score is resolved by exact ID to obtain its real CVSS score and severity.
5. **VirusTotal** — reputation counts (zeros if no key).
6. **Correlation** — `ThreatCorrelator` applies the rules and produces findings.
7. **Scoring** — `calculate_score()` computes the 0–100 risk score.
8. **Profiles** — `calculate_profiles()` computes the Exposure and Threat indices plus the verdict.
9. **Metadata** — RDAP (domain registration) and TLS certificate.
10. **Persistence** — the whole result is stored in the SQLite database.
11. **Display** — redirect to the report page.

Every external call is wrapped in `try/except` with short timeouts; a failed source returns safe default values (N/A or 0) so a scan **never crashes** because one service is down or rate-limited.

---

## 8. The Correlation Engine (`engine/correlator.py`)

This is the **"pièce maîtresse"** of the project — the original logic that transforms raw facts into conclusions. Each finding carries: **title, severity, description, recommendation, and category** (`exposure` or `threat`).

### 8.1 Port rules (from Shodan)

| Condition | Finding | Severity | Category |
|---|---|---|---|
| Port 3389 open | RDP Exposé Publiquement | HIGH | exposure |
| Port 22 open | SSH Exposé Publiquement | MEDIUM | exposure |
| Ports 1433 / 3306 / 5432 open | Base de Données Exposée Publiquement | CRITICAL | exposure |
| Port 23 open | Telnet Non Chiffré | HIGH | exposure |
| Port 21 open | FTP Non Chiffré | MEDIUM | exposure |
| More than 20 ports open | Surface d'Attaque Critiquement Étendue | CRITICAL | exposure |

### 8.2 CVE rules (from NVD/Shodan)

- Any CVE with CVSS ≥ 9.0 → **Vulnérabilité(s) Critique(s) Décelée(s)** (CRITICAL, exposure), listing the CVEs.
- Otherwise high-severity CVEs → **Vulnérabilités Élevées Non Corrigées** (HIGH, exposure).
- More than 5 CVEs → **Surface d'Attaque Vulnérable Étendue** (HIGH, exposure).

### 8.3 Reputation rules (from VirusTotal)

Severity **bands**, not one finding per antivirus engine (this was a scoring bug fix):
- ≥ 6 malicious engines → **Réputation Malveillante Confirmée** (CRITICAL, threat).
- 1–5 malicious engines → **Réputation Suspecte** (MEDIUM, threat).

### 8.4 Cross-correlation rules (the differentiator)

These rules combine facts from **different sources** — the true "correlation" that makes the project original:

| Condition | Finding | Severity | Category | Reasoning |
|---|---|---|---|---|
| RDP open (Shodan) **+** critical CVE (NVD) | Intrusion Distante Potentielle | CRITICAL | exposure | "The remote-desktop door is open **and** it has a critical known flaw" |
| Malicious reputation (VT) **+** database port open (Shodan) | Exfiltration de Données Probable | CRITICAL | exposure | "A bad-actor machine has an exposed database" |
| Malicious reputation (VT) **+** SSH open (Shodan) | Credential Stuffing Possible | HIGH | threat | "Bad reputation plus exposed SSH" |

**Why this matters:** each source alone is inconclusive. An open RDP port is common; a critical CVE existing in NVD does not prove *this* machine runs the vulnerable service. Only by *crossing* both does a credible risk emerge. This cross-referencing is the intellectual core of the project.

---

## 9. The Scoring Model (`engine/scorer.py`)

### 9.1 Global risk score (0–100)

- **Weights:** CRITICAL = 30, HIGH = 18, MEDIUM = 8, LOW = 3.
- **Bonuses:** 2+ CRITICAL findings → +15; 1 CRITICAL + 2+ HIGH → +10.
- **Floors:** the score can never fall below the band of its worst finding (CRITICAL ≥ 75, HIGH ≥ 50, MEDIUM ≥ 25, LOW ≥ 5). This prevents a serious finding from being displayed as LOW risk.
- **Cap:** 100.
- **Bands:** 0–24 LOW (green), 25–49 MEDIUM (yellow), 50–74 HIGH (orange), 75–100 CRITICAL (red).
- No findings → score 2.0 LOW.

Examples:
- Clean target → **2.0 LOW**.
- RDP + SSH exposed → **50 HIGH**.
- RDP + critical CVE → **93 CRITICAL**.
- Flagged by 30 antivirus engines → **75 CRITICAL**.

### 9.2 Exposure / Threat profiles (`calculate_profiles`)

Each finding belongs to a category, so the engine computes **two independent indices**:

- **Exposure index** — sum of the weights of `exposure` findings (ports, CVEs, intrusion/exfiltration), floored by its worst finding, capped at 100.
- **Threat index** — sum of the weights of `threat` findings (reputation, credential stuffing), with the same floor logic.

**Verdict** derived from the two indices:

| Exposure band | Threat band | Verdict |
|---|---|---|
| HIGH/CRITICAL | HIGH/CRITICAL | Cible Exposée ET Acteur de Menace Potentiel |
| HIGH/CRITICAL | LOW/MEDIUM | Cible Potentielle : Asset Exposé / Compromettable |
| LOW/MEDIUM | HIGH/CRITICAL | Acteur de Menace Potentiel |
| MEDIUM | MEDIUM | Préoccupation Modérée |
| LOW | LOW | Faible Préoccupation — Ressource A Priori Saine |

This directly answers the question: **"is this IP a victim (exposure) or a danger to others (threat), or both?"**

---

## 10. The Web Application

### 10.1 Routes

| Route | Method | Page / action | Access |
|---|---|---|---|
| `/` | GET | Dashboard: scan form + 5 recent scans | logged-in |
| `/login`, `/register`, `/logout` | — | Authentication | public (logout: logged-in) |
| `/scan` | POST | Runs the analysis, saves result | logged-in |
| `/scan/<id>` | GET | Full intelligence report | logged-in |
| `/history` | GET | All scans of the account | logged-in |
| `/delete-scan/<id>` | POST | Delete a scan | owner |
| `/settings` | GET/POST | Visual preferences (theme, toggles) | logged-in |
| `/settings/security` | POST | Change password | logged-in |
| `/settings/intel` | POST | Save per-user access keys | logged-in |
| `/settings/alerts` | POST | Alert threshold + webhook URL | logged-in |
| `/control-panel` | GET | User management | admin only |
| `/delete-user/<id>` | POST | Delete a user | admin only |

### 10.2 Authentication & roles

- **Flask-Login** manages sessions; `@login_required` protects all routes.
- **Flask-Bcrypt** hashes passwords (never stored in plaintext).
- Two roles: `user` and `admin`. The Control Panel and user deletion are **admin-only** — a privilege-escalation bug where any user could delete others was fixed.
- Default administrator: `admin` / `adminpassword123` (created automatically at startup).

### 10.3 Report page (`target_details.html`)

The report is organized into:
1. **Header** — target, IP/Domain badge, global risk score with color.
2. **Target Profile (Exposure vs Threat)** — verdict, both indices with colored bars.
3. **Origin & Network** — geolocation.
4. **Infrastructure & Ports** — organization, hostnames, OS, open ports, known vulnerabilities (CVEs with CVSS scores).
5. **Threat Telemetry** — VirusTotal engine counts.
6. **Correlation Engine Findings** — each finding with severity badge, EXPOSURE/THREAT category badge, description and recommendation.
7. **Domain & Registrar / TLS** — RDAP registration and certificate details. These sections are **hidden for IP targets**, replaced by a short explanation, because domain-registration and TLS records belong to domain names only.

### 10.4 UX decisions

- Vendor/service names (Shodan, VirusTotal, NVD, SQLite, etc.) are **not exposed in the UI**; the interface presents the product's own information model (Organization, Known Vulnerabilities, Threat Telemetry, etc.).
- Reports adapt to target type: IP vs Domain badge, and domain-only widgets hidden for IPs with an explanation.

---

## 11. Data Model (`models.py`)

**User**
`id`, `username` (unique), `password` (bcrypt hash), `role`, `virustotal_key`, `abuseipdb_key`, `shodan_key`, `theme`, `alert_threshold`, `webhook_url`, `enable_particles`, `enable_crt`.

**ScanResult**
`id`, `user_id` (FK), `target`, `scan_date`, `geolocation_data`, `shodan_data`, `vt_data`, `whois_data`, `ssl_data`, `findings_data` (all stored as **JSON text**), `risk_score`, `risk_level`, `risk_color`, `exposure_index`, `threat_index`, `exposure_band`, `threat_band`, `profile`.

**Design note:** API responses have irregular shapes; storing them as JSON text keeps the schema flexible, and the parsed score/findings are rendered at display time. A lightweight migration routine at startup (`ALTER TABLE ... ADD COLUMN`) upgrades existing databases when new fields are added.

---

## 12. Engineering Fixes & Decisions (important)

These are the corrections made during development, each with a technical justification:

1. **Real CVSS parsing from Shodan** — previously every Shodan CVE was assigned a hardcoded 7.5/HIGH. Now the real CVSS score returned by Shodan is parsed and mapped to severity.
2. **InternetDB score resolution** — free InternetDB returns CVE IDs without scores; the engine resolves each exact ID against NVD so every vulnerability has a real score. No fabricated severities.
3. **VirusTotal severity bands** — previously each malicious engine created one CRITICAL finding, so 4 engines maxed the score at 100 instantly. Now bands are used (≥6 engines = CRITICAL, 1–5 = MEDIUM).
4. **Removed NVD keyword noise** — generic keyword search returned unrelated CVEs and inflated scores. Default flow uses only exact-ID lookups.
5. **Scoring floors** — a single HIGH finding could previously score LOW. Floors now guarantee the score reflects its worst finding.
6. **bcrypt password hashing** — passwords were stored in plaintext; now hashed with Flask-Bcrypt (with a safe fallback for legacy rows).
7. **Secrets in `.env`** — API keys were hardcoded in `config.py`; now loaded from `.env` (gitignored), with `.env.example` as a template.
8. **Admin gating** — control panel and user deletion were accessible to any user; now restricted to `role == 'admin'`.
9. **Missing settings routes** — settings forms returned 405; the missing POST routes were implemented.
10. **Real RDAP WHOIS** — the WHOIS module was a placeholder returning hardcoded strings ("Verified Registrar / Enrolled Domain"); replaced with real RDAP lookups returning actual registrar and dates.
11. **TLS certificate parsing** — SSL detection was silently broken for *every* target: with `CERT_NONE` verification, Python's `getpeercert()` returns an empty dict, so `has_ssl` was always false. Fixed by reading the raw DER bytes and decoding them with the `cryptography` library (valid, expired or self-signed certificates all parse correctly).
12. **Graceful degradation** — every external call is exception-safe with short timeouts; missing keys produce zeros/N/A, never crashes or fabricated data.
13. **Persisted profile columns** — exposure/threat indices and verdict are stored per scan and displayed in history.

---

## 13. Testing

Unit tests in `test/test_correclator.py` (Python `unittest`):

1. Open RDP port generates a HIGH exposure finding.
2. More than 20 ports triggers a CRITICAL finding and score boost.
3. A clean target receives a LOW risk rating.
4. Open ports push the **Exposure** axis, not the Threat axis.
5. A malicious reputation pushes the **Threat** axis, not the Exposure axis.
6. Every finding carries a valid exposure/threat category.

Run with:
```
python -m unittest test.test_correclator -v
```

All tests pass. Full end-to-end verification (login → live scan → report page → database row) was also performed through the Flask test client.

---

## 14. Running the Project

```
python main.py
```
Then open `http://localhost:5000`. Login: `admin` / `adminpassword123`.

Dependencies are installed with:
```
python -m pip install -r requirements.txt
```

Important environment notes:
- Requirement: **Python 3.13** with the `requirements.txt` dependencies installed.
- Internet access is required for live scans; the app itself runs offline.

---

## 15. API Keys & Usage Limits

| Service | Free tier | Notes |
|---|---|---|
| ip-api | Free, no key | — |
| Shodan official API | 100 credits **total** (one-time) | InternetDB fallback is free and unlimited |
| NVD | Free, no key | Exact-ID lookups |
| VirusTotal | ~500 requests/day, 4/minute | Optional |
| RDAP | Free, no key | Registry servers rate-limit; avoid mass scanning |

Per-user keys can be configured in Settings → Intelligence; they take priority over the global `.env` keys.

---

## 16. Known Limitations

1. **PDF report not yet implemented** — ReportLab is installed; the data model already stores everything needed, but no `reports/` output or download button exists yet.
2. **Email breach checks not implemented** — the specification mentions breached-email (HIBP) checks; the paid HIBP API is the blocker. A free alternative (e.g. XposedOrNot) is planned.
3. **Shodan CVE detection is fingerprinting-based** — it reports *potential* vulnerabilities, not proof of exploitation (findings are intentionally labeled "potentielle").
4. **No CSRF protection** on forms and **no login rate-limiting** — hardening items.
5. **No charts** (the spec mentions Chart.js) — data is stored; visualization is a polish step.
6. **Webhook alerts are saved but not yet sent**.
7. **No scan deduplication** — re-scanning the same target creates a new row (a caching layer is planned to protect API quotas).

---

## 17. Roadmap (Planned Work)

These are the improvements I am looking forward to adding next — a simple overview of where the project is heading:

1. **PDF report extraction** — a one-click download of a professional report for any scan (ReportLab is already installed; the data needed is already stored).
2. **Interactive geolocation mini-map** — a small map on the dashboard showing the physical location of the scanned target.
3. **Email breach intelligence (HIBP)** — check whether email addresses appear in known data breaches (a free API is planned as the paid HIBP API is the current blocker).
4. **Chart.js dashboards** — visual risk trends across the scan history.
5. **Security hardening** — CSRF protection on all forms and login rate-limiting.
6. **Alert delivery** — actually send webhook/email alerts when a scan exceeds the configured threshold.
7. **Caching layer** — avoid re-querying APIs for recently scanned targets to protect API quotas.

---

## 18. Honest Status Summary for the Supervisor

**Complete and working today:**
- Full scan pipeline across 5 sources with graceful fallbacks.
- Custom correlation engine (ports, CVEs, reputation, 3 cross-correlation rules).
- Transparent scoring model with floors.
- Exposure vs Threat profiling with per-target verdict.
- Web application: auth, roles, settings, history, report page, admin panel.
- Real RDAP registration data and real TLS certificate parsing.
- Database persistence and automatic migrations.
- 6 passing unit tests + end-to-end verification.

**Not yet done (planned next):**
- PDF report extraction.
- Interactive geolocation mini-map on the dashboard.
- Email breach checks (HIBP).
- Chart.js dashboards.
- CSRF protection and login rate-limiting.
- Alert delivery and a caching layer.

---

*End of report.*
