import requests
from config import Config


def get_virustotal_info(target):
    """
    Queries VirusTotal v3 API for IP or domain threat reputation.
    """
    if not Config.VIRUSTOTAL_API_KEY:
        return {"status": "fail", "message": "VirusTotal API key is missing in config.py"}

    # Check if target is an IP or a domain
    is_ip = target.replace(".", "").isdigit()
    endpoint_type = "ip_addresses" if is_ip else "domains"

    url = f"https://www.virustotal.com/api/v3/{endpoint_type}/{target}"

    headers = {
        "x-apikey": Config.VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "target": target,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "status": "success"
            }
        elif response.status_code == 404:
            return {"status": "fail", "message": "Target not found in VirusTotal database."}
        else:
            return {"status": "fail", "message": f"API returned status code {response.status_code}"}

    except Exception as e:
        return {"status": "fail", "message": str(e)}