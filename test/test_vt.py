from apis.virustotal_api import get_virustotal_info

if __name__ == "__main__":
    print("[*] Testing live VirusTotal API...")
    # Let's test with a safe and well-known IP (Google DNS)
    result = get_virustotal_info("8.8.8.8")
    print(result)