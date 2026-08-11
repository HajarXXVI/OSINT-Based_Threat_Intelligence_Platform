# engine/correlator.py
import socket
import requests
import logging
from apis.shodan_api import get_shodan_host_info
from apis.nvd_api import get_cve_by_id
from apis.metadata_api import get_whois_info, get_ssl_certificate_info
from engine.scorer import calculate_score, calculate_profiles

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

DATABASE_PORTS = {1433, 3306, 5432}


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
        self.findings = []

    def correlate(self):
        self._check_ports()
        self._check_cves()
        self._check_reputation()
        self._check_cross_correlations()
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
                "RDP Exposé Publiquement", "HIGH",
                "Le port 3389 (RDP) est ouvert sur l'internet public, exposant la cible au brute-force et aux exploits.",
                "Restreindre l'accès RDP via un VPN ou une liste blanche IP.")
        if 22 in self.ports:
            self._add_finding(
                "SSH Exposé Publiquement", "MEDIUM",
                "Le port 22 (SSH) est ouvert; il peut subir des tentatives de brute-force ou de credential stuffing.",
                "Limiter l'accès SSH et privilégier l'authentification par clé.")
        db_ports = sorted(set(self.ports) & DATABASE_PORTS)
        if db_ports:
            self._add_finding(
                "Base de Données Exposée Publiquement", "CRITICAL",
                f"Port(s) de base de données {db_ports} exposé(s) directement sur Internet.",
                "Fermer ces ports publiquement et accéder aux bases uniquement via le réseau interne ou un VPN.")
        if 23 in self.ports:
            self._add_finding(
                "Telnet Non Chiffré", "HIGH",
                "Le port 23 (Telnet) transmet les identifiants en clair et ne doit jamais être exposé.",
                "Désactiver Telnet et utiliser SSH.")
        if 21 in self.ports:
            self._add_finding(
                "FTP Non Chiffré", "MEDIUM",
                "Le port 21 (FTP) expose des transferts de fichiers non chiffrés.",
                "Remplacer FTP par SFTP/FTPS.")
        if len(self.ports) > 20:
            self._add_finding(
                "Surface d'Attaque Critiquement Étendue", "CRITICAL",
                f"{len(self.ports)} ports ouverts détectés, élargissant considérablement la surface d'attaque.",
                "Réduire l'exposition au strict minimum nécessaire.")

    # --- CVE rules (NVD / Shodan data) ---
    def _check_cves(self):
        critical_cves = [c for c in self.cves if str(c.get("severity", "")).upper() == "CRITICAL"]
        high_cves = [c for c in self.cves if str(c.get("severity", "")).upper() == "HIGH"]

        if critical_cves:
            self._add_finding(
                "Vulnérabilité(s) Critique(s) Décelée(s)", "CRITICAL",
                f"{len(critical_cves)} CVE(s) avec score CVSS >= 9.0 : "
                + ", ".join(c["cve_id"] for c in critical_cves),
                "Appliquer les correctifs de sécurité immédiatement et vérifier l'absence d'exploitation.")
        elif high_cves:
            self._add_finding(
                "Vulnérabilités Élevées Non Corrigées", "HIGH",
                f"{len(high_cves)} CVE(s) de sévérité élevée affectent les services détectés.",
                "Prioriser la mise à jour des logiciels vulnérables.")

        if len(self.cves) > 5:
            self._add_finding(
                "Surface d'Attaque Vulnérable Étendue", "HIGH",
                f"{len(self.cves)} vulnérabilités connues associées à cette cible.",
                "Mettre en place un programme structuré de gestion des correctifs.")

    # --- Reputation rules (VirusTotal data) ---
    # Severity BANDS, not one finding per engine: this was the score bug.
    # Reputation findings describe how DANGEROUS the target is to others.
    def _check_reputation(self):
        if self.vt_malicious >= 6:
            self._add_finding(
                "Réputation Malveillante Confirmée", "CRITICAL",
                f"Plus de 5 moteurs antivirus ({self.vt_malicious}) classent la cible comme malveillante.",
                "Isoler la cible, analyser son trafic et vérifier une éventuelle compromission.",
                category="threat")
        elif self.vt_malicious >= 1:
            self._add_finding(
                "Réputation Suspecte", "MEDIUM",
                f"{self.vt_malicious} moteur(s) antivirus signalent la cible comme malveillante.",
                "Approfondir l'analyse avant de faire confiance à cette ressource.",
                category="threat")

    # --- Cross-correlation rules (the differentiator) ---
    def _check_cross_correlations(self):
        has_rdp = 3389 in self.ports
        has_critical_cve = any(str(c.get("severity", "")).upper() == "CRITICAL" for c in self.cves)
        has_db_port = bool(set(self.ports) & DATABASE_PORTS)
        has_ssh = 22 in self.ports

        if has_rdp and has_critical_cve:
            self._add_finding(
                "Intrusion Distante Potentielle", "CRITICAL",
                "RDP exposé combiné à une vulnérabilité critique connue rend la cible potentiellement compromettable à distance.",
                "Fermer RDP ou le placer derrière un VPN, puis corriger les vulnérabilités critiques.")
        if self.vt_malicious >= 1 and has_db_port:
            self._add_finding(
                "Exfiltration de Données Probable", "CRITICAL",
                "Réputation malveillante associée à un port de base de données exposé.",
                "Surveiller les connexions sortantes et verrouiller l'accès aux bases de données.")
        if self.vt_malicious >= 1 and has_ssh:
            self._add_finding(
                "Credential Stuffing Possible", "HIGH",
                "Cible à mauvaise réputation avec SSH exposé : risque de credential stuffing ou de brute-force.",
                "Imposer une authentification forte et journaliser les tentatives de connexion.",
                category="threat")


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


def _resolve_unknown_cves(shodan_data):
    """
    InternetDB returns CVE IDs without scores. Resolve each exact ID
    against NVD so every vulnerability has a real CVSS score/severity.
    No generic keyword search -> no fabricated CVEs -> no score inflation.
    """
    unresolved = [v for v in shodan_data.get("enriched_vulns", []) if v.get("severity") == "UNKNOWN"]
    for vuln in unresolved:
        resolved = get_cve_by_id(vuln["cve_id"])
        if resolved:
            vuln["score"] = resolved["score"]
            vuln["severity"] = resolved["severity"]
            vuln["description"] = resolved["description"]
    return shodan_data


def analyze_target(target, shodan_api_key=None, vt_api_key=None):
    ip_address = _resolve_ip(target.strip())

    # 1. Geolocation (ip-api, free, no key)
    geo_data = _get_geolocation(ip_address)

    # 2. Shodan: official API if a key is configured, else free InternetDB
    shodan_data = get_shodan_host_info(ip_address, api_key=shodan_api_key)
    if shodan_data["organization"] == "Unknown":
        shodan_data["organization"] = geo_data.get("org", "N/A")

    # 3. NVD: resolve score-less CVE IDs by exact ID (no noise)
    shodan_data = _resolve_unknown_cves(shodan_data)

    # 4. VirusTotal reputation (0s if no key -> never fabricates detections)
    vt_data = _get_virustotal(ip_address, vt_api_key)

    # 5. Correlation + scoring
    findings = ThreatCorrelator({
        "shodan": shodan_data,
        "virustotal": vt_data,
        "cves": shodan_data.get("enriched_vulns", [])
    }).correlate()

    risk_assessment = calculate_score(findings)
    profiles = calculate_profiles(findings)

    # 6. Metadata summaries (WHOIS & SSL)
    whois_summary = get_whois_info(target)
    ssl_summary = get_ssl_certificate_info(target)

    return {
        "geolocation": geo_data,
        "shodan": shodan_data,
        "virustotal": vt_data,
        "whois_data": whois_summary,
        "ssl_data": ssl_summary,
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
