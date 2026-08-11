from apis.ipapi import get_ip_info

if __name__ == "__main__":
    print("[*] Testing live IP Geolocation API...")
    result = get_ip_info("8.8.8.8")
    print(result)