# apis/nvd_api.py
import requests
import logging

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HEADERS = {"User-Agent": "CyberSecurity-PFA-Tool/1.0"}


def _severity_from_cvss(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_cve(item):
    cve_data = item.get('cve', {})
    cve_id = cve_data.get('id')

    descriptions = cve_data.get('descriptions', [])
    desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description available.')

    metrics = cve_data.get('metrics', {})
    score = None
    severity = "UNKNOWN"

    if 'cvssMetricV31' in metrics:
        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
        score = float(cvss_data.get('baseScore', 0))
        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
    elif 'cvssMetricV2' in metrics:
        metric = metrics['cvssMetricV2'][0]
        cvss_data = metric.get('cvssData', {})
        score = float(cvss_data.get('baseScore', 0))
        severity = metric.get('baseSeverity') or _severity_from_cvss(score)

    return {
        "cve_id": cve_id,
        "score": round(score, 1) if score is not None else "N/A",
        "severity": severity,
        "description": desc[:180] + "..."
    }


def get_cve_by_id(cve_id, api_key=None):
    """
    Fetches a single CVE by its exact identifier (no fuzzy keyword search,
    so results are guaranteed to match the detected vulnerability).
    An optional NVD API key raises the rate limit from 5 to 50 requests
    per 30 seconds, enabling full CVE resolution for large findings.
    """
    try:
        params = {"cveId": cve_id}
        headers = dict(NVD_HEADERS)
        if api_key:
            headers["apiKey"] = api_key
        response = requests.get(NVD_BASE, params=params, headers=headers, timeout=8)
        if response.status_code == 200:
            data = response.json()
            for item in data.get('vulnerabilities', []):
                return _parse_cve(item)
    except Exception as e:
        logging.warning(f"NVD CVE lookup failed for {cve_id}: {e}")
    return None


def get_nvd_vulnerabilities(search_query):
    """
    Keyword search kept for extended/manual use.
    NOTE: not used by the default scan flow, because a generic keyword
    (e.g. "linux") returns unrelated CVEs and inflates the risk score.
    """
    vulns = []
    if not search_query:
        return vulns

    try:
        response = requests.get(
            NVD_BASE,
            params={"keywordSearch": search_query, "resultsPerPage": 5},
            headers=NVD_HEADERS,
            timeout=8
        )
        if response.status_code == 200:
            for item in response.json().get('vulnerabilities', []):
                parsed = _parse_cve(item)
                if parsed:
                    vulns.append(parsed)
    except Exception as e:
        logging.warning(f"NVD API fetch failed: {e}")

    return vulns
