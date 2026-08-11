# apis/shodan_api.py
import requests
import logging


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


def _to_vuln(cve_id, cvss, verified=None, summary=None):
    return {
        "cve_id": cve_id,
        "score": round(float(cvss), 1) if cvss is not None else "N/A",
        "severity": _severity_from_cvss(cvss),
        "description": summary or "Vulnerability identified via Shodan host scan."
    }


def _merge_vulns(vuln_list):
    merged = {}
    for v in vuln_list:
        merged[v["cve_id"]] = v
    return list(merged.values())


def get_shodan_host_info(ip_address, api_key=None):
    shodan_data = {
        "organization": "Unknown",
        "hostnames": [],
        "os": "Unknown OS",
        "ports": [],
        "enriched_vulns": []
    }

    # 1. Official Shodan REST API.
    #    The 'vulns' field is a dict: {CVE-ID: {"cvss": float, "verified": bool, "summary": str}}.
    #    The real CVSS score is parsed and mapped to a severity - no more hardcoded values.
    if api_key:
        try:
            url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                data = res.json()
                shodan_data["ports"] = data.get('ports', [])
                shodan_data["hostnames"] = data.get('hostnames', [])
                shodan_data["os"] = data.get('os', 'Unknown OS')
                shodan_data["organization"] = data.get('org', 'Unknown')

                vulns = data.get('vulns', {}) or {}
                items = vulns.items() if isinstance(vulns, dict) else [(v, {}) for v in vulns]
                for cve_id, info in items:
                    shodan_data["enriched_vulns"].append(
                        _to_vuln(cve_id, info.get("cvss"), info.get("verified"), info.get("summary")))
                shodan_data["enriched_vulns"] = _merge_vulns(shodan_data["enriched_vulns"])
                return shodan_data
        except Exception as e:
            logging.warning(f"Shodan API call failed, falling back to InternetDB: {e}")

    # 2. Free Shodan InternetDB (No API key needed).
    #    Here 'vulns' is a plain list of CVE IDs with no score -> severity UNKNOWN.
    #    The correlator resolves those exact IDs against NVD so scores stay real.
    try:
        url = f"https://internetdb.shodan.io/{ip_address}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            shodan_data["ports"] = data.get('ports', [])
            shodan_data["hostnames"] = data.get('hostnames', [])

            for cve_id in data.get('vulns', []) or []:
                shodan_data["enriched_vulns"].append(_to_vuln(cve_id, None))
            shodan_data["enriched_vulns"] = _merge_vulns(shodan_data["enriched_vulns"])
    except Exception as e:
        logging.warning(f"Shodan InternetDB lookup failed: {e}")

    return shodan_data
