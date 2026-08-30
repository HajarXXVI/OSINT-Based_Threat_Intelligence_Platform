# engine/correlator.py
import socket
import requests
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from apis.shodan_api import get_shodan_host_info
from apis.nvd_api import get_cve_by_id
from apis.metadata_api import get_whois_info, get_ssl_certificate_info
from apis.dns_api import get_dns_records
from engine.scorer import calculate_score, calculate_profiles

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

DATABASE_PORTS = {1433, 3306, 5432}

# Capping the per-scan NVD resolutions keeps scans fast even when
# InternetDB reports a very large number of CVE IDs for one host.
# With an NVD API key (full rate limit) the cap is lifted and every
# CVE is resolved so the score reflects the complete vulnerability set.
MAX_NVD_RESOLUTIONS = 12


class ThreatCorrelator:
    """
    Turns raw OSINT facts into actionable findings.
    Each rule is a self-contained method; findings carry a title, a
    severity, a description and a recommendation (the "pièce maîtresse"
    of the project).
    """

    def __init__(self, scan_results):
        shodan = scan_results.get("shodan", {}) or {}
        vt = scan_results.get("virustotal", {}) or {}
        self.ports = list(shodan.get("ports", []) or [])
        self.cves = list(scan_results.get("cves", []) or [])
        # VirusTotal payloads can be flat {"malicious": n} or {"stats": {...}}
        vt_stats = vt.get("stats", vt) if isinstance(vt, dict) else {}
        self.vt_malicious = int(vt_stats.get("malicious", 0) or 0)
        self.vt_suspicious = int(vt_stats.get("suspicious", 0) or 0)
        self.whois_data = scan_results.get("whois", {}) or {}
        self.ssl_data = scan_results.get("ssl", {}) or {}
        self.dns_data = scan_results.get("dns", {}) or {}
        self.findings = []

    def correlate(self):
        self._check_ports()
        self._check_cves()
        self._check_reputation()
        self._check_cross_correlations()
        self._check_dns_posture()
        self._check_domain_age()
        self._check_tls_posture()
        return self.findings

    def _add_finding(self, title, severity, description, recommendation, category="exposure"):
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            # "exposure" = the TARGET can be compromised by others.
            # "threat"   = the TARGET is dangerous to others.
            "category": category
        })

    # --- Port rules (Shodan data) ---
    def _check_ports(self):
        if 3389 in self.ports:
            self._add_finding(
                "RDP Publicly Exposed", "HIGH",
                "Port 3389 (RDP) is open to the public internet, exposing the target to brute-force and exploits.",
                "Restrict RDP access via a VPN or an IP allowlist.")
        if 22 in self.ports:
            self._add_finding(
                "SSH Publicly Exposed", "MEDIUM",
                "Port 22 (SSH) is open; it may face brute-force or credential-stuffing attempts.",
                "Limit SSH access and prefer key-based authentication.")
        db_ports = sorted(set(self.ports) & DATABASE_PORTS)
        if db_ports:
            self._add_finding(
                "Database Publicly Exposed", "CRITICAL",
                f"Database port(s) {db_ports} exposed directly to the internet.",
                "Close these ports publicly and reach databases only over the internal network or a VPN.")
        if 23 in self.ports:
            self._add_finding(
                "Unencrypted Telnet", "HIGH",
                "Port 23 (Telnet) transmits credentials in plaintext and should never be exposed.",
                "Disable Telnet and use SSH.")
        if 21 in self.ports:
            self._add_finding(
                "Unencrypted FTP", "MEDIUM",
                "Port 21 (FTP) exposes unencrypted file transfers.",
                "Replace FTP with SFTP/FTPS.")
        if len(self.ports) > 20:
            self._add_finding(
                "Critically Extended Attack Surface", "CRITICAL",
                f"{len(self.ports)} open ports detected, substantially widening the attack surface.",
                "Reduce exposure to the bare minimum required.")

    # --- CVE rules (NVD / Shodan data) ---
    def _check_cves(self):
        critical_cves = [c for c in self.cves if str(c.get("severity", "")).upper() == "CRITICAL"]
        high_cves = [c for c in self.cves if str(c.get("severity", "")).upper() == "HIGH"]

        if critical_cves:
            self._add_finding(
                "Critical Vulnerabilities Detected", "CRITICAL",
                f"{len(critical_cves)} CVE(s) with a CVSS score >= 9.0: "
                + ", ".join(c["cve_id"] for c in critical_cves),
                "Apply security patches immediately and verify there is no active exploitation.")
        elif high_cves:
            self._add_finding(
                "Unpatched High Vulnerabilities", "HIGH",
                f"{len(high_cves)} high-severity CVE(s) affect the detected services.",
                "Prioritize updating the vulnerable software.")

        if len(self.cves) > 5:
            self._add_finding(
                "Extended Vulnerable Attack Surface", "HIGH",
                f"{len(self.cves)} known vulnerabilities associated with this target.",
                "Implement a structured patch-management program.")

    # --- Reputation rules (VirusTotal data) ---
    # Severity BANDS, not one finding per engine: this was the score bug.
    # Reputation findings describe how DANGEROUS the target is to others.
    def _check_reputation(self):
        if self.vt_malicious >= 6:
            self._add_finding(
                "Confirmed Malicious Reputation", "CRITICAL",
                f"More than 5 antivirus engines ({self.vt_malicious}) classify the target as malicious.",
                "Isolate the target, analyze its traffic and check for possible compromise.",
                category="threat")
        elif self.vt_malicious >= 1:
            self._add_finding(
                "Suspicious Reputation", "MEDIUM",
                f"{self.vt_malicious} antivirus engine(s) flag the target as malicious.",
                "Investigate further before trusting this resource.",
                category="threat")

    # --- Cross-correlation rules (the differentiator) ---
    def _check_cross_correlations(self):
        has_rdp = 3389 in self.ports
        has_critical_cve = any(str(c.get("severity", "")).upper() == "CRITICAL" for c in self.cves)
        has_db_port = bool(set(self.ports) & DATABASE_PORTS)
        has_ssh = 22 in self.ports

        if has_rdp and has_critical_cve:
            self._add_finding(
                "Potential Remote Intrusion", "CRITICAL",
                "Exposed RDP combined with a known critical vulnerability makes the target potentially compromisable remotely.",
                "Close RDP or place it behind a VPN, then remediate the critical vulnerabilities.")
        if self.vt_malicious >= 1 and has_db_port:
            self._add_finding(
                "Likely Data Exfiltration", "CRITICAL",
                "Malicious reputation associated with an exposed database port.",
                "Monitor outbound connections and lock down database access.")
        if self.vt_malicious >= 1 and has_ssh:
            self._add_finding(
                "Possible Credential Stuffing", "HIGH",
                "Target with a bad reputation and exposed SSH: risk of credential stuffing or brute-force.",
                "Enforce strong authentication and log connection attempts.",
                category="threat")

    def _check_dns_posture(self):
        if self.dns_data.get("mx_records") and not self.dns_data.get("spoofing_protected"):
            self._add_finding(
                "Email Spoofing Not Protected", "MEDIUM",
                "The domain receives mail (MX records exist) but publishes no valid anti-spoofing "
                "policy (SPF combined with DMARC or DKIM), so senders can forge emails in its name.",
                "Publish an SPF record and a DMARC policy, and sign outgoing mail with DKIM.")

    def _check_domain_age(self):
        creation = self.whois_data.get("creation_date")
        if not creation or creation == "N/A":
            return
        try:
            created = datetime.strptime(creation, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return
        if (datetime.now(timezone.utc) - created).days < 30:
            self._add_finding(
                "Newly Registered Domain", "HIGH",
                f"The domain was registered less than 30 days ago ({creation}), a common pattern "
                "for phishing and typosquatting infrastructure.",
                "Treat the domain as suspicious and verify its owner before trusting it.")

    def _check_tls_posture(self):
        if not self.ssl_data.get("has_ssl"):
            return
        try:
            days_left = int(self.ssl_data.get("expires_in_days"))
        except (TypeError, ValueError):
            return
        if days_left < 0:
            self._add_finding(
                "Expired TLS Certificate", "MEDIUM",
                "The TLS certificate presented on port 443 has expired, exposing users to browser "
                "warnings and man-in-the-middle risk.",
                "Renew the certificate immediately and re-check any services still using the old one.")


def _resolve_ip(target):
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def _get_geolocation(ip_address):
    geo_data = {
        "query": ip_address, "country": "N/A", "city": "N/A",
        "lat": "N/A", "lon": "N/A", "isp": "N/A", "org": "N/A"
    }
    try:
        res = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=4).json()
        if res.get('status') == 'success':
            geo_data = res
    except Exception:
        pass
    return geo_data


def _get_virustotal(ip_address, vt_api_key):
    vt_data = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    if not vt_api_key:
        return vt_data
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                           headers={"x-apikey": vt_api_key}, timeout=5)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_data = {
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0))
            }
    except Exception as e:
        logging.warning(f"VirusTotal API fetch failed: {e}")
    return vt_data


def _resolve_unknown_cves(shodan_data, nvd_api_key=None):
    """
    InternetDB returns CVE IDs without scores. Resolve each exact ID
    against NVD so every vulnerability has a real CVSS score/severity.
    No generic keyword search -> no fabricated CVEs -> no score inflation.

    Resolutions run in parallel. Without an NVD API key they are also
    capped (free tier allows ~5 requests per 30s; resolving hundreds of
    IDs sequentially would block a scan for minutes). With a key the cap
    is lifted and the complete CVE set is scored. Unresolved IDs keep
    severity UNKNOWN and still count toward the "many vulnerabilities"
    rule without inflating the score.
    """
    unresolved = [v for v in shodan_data.get("enriched_vulns", []) if v.get("severity") == "UNKNOWN"]

    def resolve(vuln):
        resolved = get_cve_by_id(vuln["cve_id"], api_key=nvd_api_key)
        if resolved:
            vuln["score"] = resolved["score"]
            vuln["severity"] = resolved["severity"]
            vuln["description"] = resolved["description"]

    cap = None if nvd_api_key else MAX_NVD_RESOLUTIONS
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(resolve, unresolved[:cap]))
    return shodan_data


def analyze_target(target, shodan_api_key=None, vt_api_key=None, nvd_api_key=None, progress_callback=None):
    def report(message):
        if progress_callback:
            progress_callback(message)

    ip_address = _resolve_ip(target.strip())
    report(f"DNS resolution: {ip_address}")

    # 1. Geolocation (ip-api, free, no key)
    report("Geolocation (ip-api)...")
    geo_data = _get_geolocation(ip_address)
    report("Geolocation OK")

    # 2. Shodan: official API if a key is configured, else free InternetDB
    report("Network footprint (Shodan)...")
    shodan_data = get_shodan_host_info(ip_address, api_key=shodan_api_key)
    if shodan_data["organization"] == "Unknown":
        shodan_data["organization"] = geo_data.get("org", "N/A")
    report(f"{len(shodan_data.get('ports', []))} open port(s), {len(shodan_data.get('enriched_vulns', []))} CVE(s) found")

    # 3. NVD: resolve score-less CVE IDs by exact ID (no noise)
    report("Vulnerability scores (NVD)...")
    shodan_data = _resolve_unknown_cves(shodan_data, nvd_api_key=nvd_api_key)
    report("Vulnerabilities scored")

    # 4. VirusTotal reputation (0s if no key -> never fabricates detections)
    report("Reputation (VirusTotal)...")
    vt_data = _get_virustotal(ip_address, vt_api_key)
    report(f"Reputation: {vt_data.get('malicious', 0)} malicious engine(s)")

    # 5. Metadata posture (WHOIS, TLS & DNS), collected before correlation
    report("Domain metadata (RDAP) and TLS certificate...")
    whois_summary = get_whois_info(target)
    ssl_summary = get_ssl_certificate_info(target)

    report("DNS records & email-spoofing protection...")
    dns_summary = get_dns_records(target)

    # 6. Correlation + scoring
    report("Correlating findings...")
    findings = ThreatCorrelator({
        "shodan": shodan_data,
        "virustotal": vt_data,
        "cves": shodan_data.get("enriched_vulns", []),
        "whois": whois_summary,
        "ssl": ssl_summary,
        "dns": dns_summary
    }).correlate()
    report(f"{len(findings)} finding(s) generated")

    report("Calculating risk score and profiles...")
    risk_assessment = calculate_score(findings)
    profiles = calculate_profiles(findings)
    report(f"Score: {risk_assessment['score']}/100 ({risk_assessment['level']})")

    report("Analysis complete")
    return {
        "geolocation": geo_data,
        "shodan": shodan_data,
        "virustotal": vt_data,
        "whois_data": whois_summary,
        "ssl_data": ssl_summary,
        "dns_data": dns_summary,
        "findings": findings,
        "risk_score": risk_assessment["score"],
        "risk_level": risk_assessment["level"],
        "risk_color": risk_assessment["color"],
        "exposure_index": profiles["exposure_index"],
        "threat_index": profiles["threat_index"],
        "exposure_band": profiles["exposure_band"],
        "threat_band": profiles["threat_band"],
        "profile": profiles["profile"]
    }
