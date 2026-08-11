# test_nvd.py
import requests
import json


def test_nvd_connection():
    # Official NIST NVD API 2.0 endpoint for checking a specific CVE
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"

    print("[*] Connecting to NIST NVD API 2.0...")
    try:
        response = requests.get(url, timeout=10)
        print(f"[*] Response Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                cve_item = vulnerabilities[0].get('cve', {})
                cve_id = cve_item.get('id')
                descriptions = cve_item.get('descriptions', [])
                desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description')

                print("\n--- NVD API SUCCESS ---")
                print(f"CVE ID: {cve_id}")
                print(f"Description: {desc[:150]}...")
                print("-----------------------\n")
            else:
                print("[-] Connected, but received an empty vulnerability array.")
        else:
            print(f"[-] NVD API returned non-200 status: {response.status_code}")
            print(response.text[:200])

    except Exception as e:
        print(f"[-] Connection to NVD API failed: {e}")


if __name__ == '__main__':
    test_nvd_connection()