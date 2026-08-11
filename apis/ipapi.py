import requests


def get_ip_info(target_ip):
    """
    Queries ip-api.com for geolocation and network details.
    Free, no API key required.
    """
    url = f"http://ip-api.com/json/{target_ip}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get('status') == 'success':
            return {
                "query": data.get("query"),
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "status": "success"
            }
        else:
            return {"status": "fail", "message": data.get("message", "Unknown error")}

    except Exception as e:
        return {"status": "fail", "message": str(e)}