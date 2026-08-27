# apis/crt_api.py
import logging
import socket
import requests
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")

CRT_URL = "https://crt.sh/"
TIMEOUT = 12


CRT_DEFAULTS = {
    "enabled": True,
    "subdomains": [],
    "total": 0,
    "checked": 0,
    "alive": 0,
    "error": None,
}


def _query_crt(domain):
    """
    Queries the public Certificate Transparency log (crt.sh) for every
    subdomain of `domain` that has ever had an SSL certificate issued.

    Returns a deduplicated, sorted list of subdomain names. The crt.sh
    endpoint is occasionally flaky (returning 5xx/429), so we retry a
    few times before giving up gracefully.

    Purely passive: we only READ the public CT log. We never contact the
    target's servers here.
    """
    names = set()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for attempt in range(3):
            try:
                resp = requests.get(
                    CRT_URL,
                    params={"q": f"%25.{domain}", "output": "json"},
                    timeout=TIMEOUT,
                )
                if resp.status_code != 200:
                    logging.warning(f"crt.sh returned {resp.status_code} (attempt {attempt + 1})")
                    continue
                data = resp.json()
                for entry in data or []:
                    for line in (entry.get("name_value") or "").split("\n"):
                        name = line.strip().lstrip("*.").lower()
                        # Keep only names that belong to this domain exactly once,
                        # dedupe case-insensitively, and drop the bare apex domain.
                        if name.endswith("." + domain) or name == domain:
                            if name != domain:
                                names.add(name)
                return sorted(names)
            except Exception as e:
                logging.warning(f"crt.sh lookup attempt {attempt + 1} failed: {e}")
    return sorted(names)


def _subdomain_is_alive(sub):
    """Cheap passive liveness check: does the subdomain resolve to an IP?"""
    try:
        socket.gethostbyname(sub)
        return True
    except Exception:
        return False


def get_subdomains(target):
    """
    Discovers subdomains of `target` (a domain) via Certificate
    Transparency logs. For each discovered subdomain we also do ONE cheap,
    free liveness check so the listing is actionable without burning real
    scan quota.

    Returns a dict that the report widget renders as a compact list, each row
    with a 'Scan' button to run a full scan (Shodan/NVD) on that
    specific subdomain.
    """
    clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    if "." not in clean or clean.replace(".", "").isdigit():
        return dict(CRT_DEFAULTS)

    result = dict(CRT_DEFAULTS)
    subdomains = _query_crt(clean)

    # Sort: alive (interesting) first, then alpha
    living = []
    dead = []
    for sub in subdomains:
        alive = _subdomain_is_alive(sub)
        (living if alive else dead).append(sub)
        result["alive"] += 1 if alive else 0

    result["subdomains"] = sorted(living) + sorted(dead)
    result["total"] = len(result["subdomains"])
    result["checked"] = len(result["subdomains"])
    return result
