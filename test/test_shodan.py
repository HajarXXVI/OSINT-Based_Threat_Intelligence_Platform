# test_shodan.py
import sys
import os

# Add project root to path if needed
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from apis.shodan_api import get_shodan_host_info
from config import Config


def run_diagnostic():
    # Test a well-known public IP with active open ports and telemetry
    test_ip = "8.8.8.8"

    api_key = getattr(Config, 'SHODAN_API_KEY', None)
    print(f"[*] Testing Shodan lookup for IP: {test_ip}")
    print(f"[*] Using API Key configured: {bool(api_key and api_key != 'YOUR_SHODAN_API_KEY_HERE')}")

    data = get_shodan_host_info(test_ip, api_key=api_key)

    print("\n--- RESULTS ---")
    print(f"Organization: {data.get('organization')}")
    print(f"Hostnames: {data.get('hostnames')}")
    print(f"Operating System: {data.get('os')}")
    print(f"Open Ports Found: {data.get('ports')}")
    print(f"Enriched CVEs Found: {len(data.get('enriched_vulns', []))}")
    for vuln in data.get('enriched_vulns', []):
        print(f"  - {vuln.get('cve_id')}: {vuln.get('description')}")
    print("----------------\n")


if __name__ == '__main__':
    run_diagnostic()