# apis/dns_api.py
import logging
import requests

DNS_GOOGLE = "https://dns.google/resolve"
TIMEOUT = 6


def _lookup(name, rtype, include_authority=False):
    """
    Single DNS lookup against the free, key-less Google DNS-over-JSON API.
    Returns a flat list of records. When include_authority is True and no
    answer exists, the authoritative SOA record is returned instead (used for
    NS lookups so that zones exposing only a delegation are still covered).
    """
    try:
        response = requests.get(DNS_GOOGLE, params={"name": name, "type": rtype},
                                timeout=TIMEOUT)
        if response.status_code != 200:
            return None
        data = response.json()
        records = list(data.get("Answer", []) or [])
        if include_authority and not records:
            records = [r for r in (data.get("Authority", []) or []) if r.get("type") == 6]
        return records or None
    except Exception as e:
        logging.warning(f"DNS lookup failed for {name} (type {rtype}): {e}")
        return None


DNS_DEFAULTS = {
    "ns_servers": [],
    "mx_records": [],
    "spf": "NOT SET",
    "dkim": "NOT DETECTED",
    "dmarc": "NOT SET",
    "spoofing_protected": False,
}


def get_dns_records(target):
    """
    Fetches public DNS records relevant to email spoofing protection.
    Domain names have a permanent phone-book of records anyone can read;
    validating them is entirely passive (a DNS lookup never contacts the
    target's servers).

    Returns a dict with:
      - ns_servers / mx_records   : hosting + mail-routing infrastructure
      - spf                       : "v=spf1 ..." (which servers may send mail as me)
      - dkim                      : looks for a signed mail record
      - dmarc                     : policy telling receivers what to do with spoofed mail
      - spoofing_protected        : True when SPF AND (DMARC or DKIM) are present
    """
    clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    if "." not in clean or clean.replace(".", "").isdigit():
        return dict(DNS_DEFAULTS)

    result = dict(DNS_DEFAULTS)

    # 1. Authoritative name servers (hosting / DNS infrastructure).
    #    Most zones return NS records directly; zones that only show a
    #    delegation return the SOA record, whose first field is the primary
    #    name server.
    ns_records = _lookup(clean, "NS", include_authority=True) or []
    ns_servers = []
    for r in ns_records:
        data = r["data"].split()[0].rstrip(".")
        if data and data not in ns_servers:
            ns_servers.append(data)
    result["ns_servers"] = ns_servers

    # 2. Mail exchange servers (where incoming email is routed)
    mx_records = _lookup(clean, "MX") or []
    mx_records.sort(key=lambda r: r.get("preference", 0))
    result["mx_records"] = [r["data"].rstrip(".") for r in mx_records]

    # 3. SPF record — published in the main TXT record, starts with "v=spf1"
    txt_records = _lookup(clean, "TXT") or []
    spf = next((r["data"] for r in txt_records if "v=spf1" in r.get("data", "")), None)
    if spf:
        result["spf"] = spf

    # 4. DMARC policy — always lives at the dedicated "_dmarc." subdomain
    dmarc_records = _lookup(f"_dmarc.{clean}", "TXT") or []
    dmarc = next((r["data"] for r in dmarc_records if "v=DMARC1" in r.get("data", "")), None)
    if dmarc:
        result["dmarc"] = dmarc

    # 5. DKIM — selectors vary per provider; probe a handful of common ones.
    #    Any signed record returned proves DKIM is configured for the domain.
    dkim = None
    for selector in ("google", "default", "selector1", "selector2", "k1", "s1",
                     "smtp", "mail", "dkim", "key1", "mandrill", "x"):
        dkim_records = _lookup(f"{selector}._domainkey.{clean}", "TXT")
        if dkim_records:
            dkim = next((r["data"] for r in dkim_records if "v=DKIM1" in r.get("data", "")), None)
            if dkim:
                break
    if dkim:
        result["dkim"] = "DETECTED"

    # Protection verdict: mail cannot be credibly spoofed only when an
    # authorized-sender policy (SPF) is combined with a policy (DMARC) or a
    # signing mechanism (DKIM).
    result["spoofing_protected"] = bool(
        result["spf"] != "NOT SET" and (result["dmarc"] != "NOT SET" or result["dkim"] == "DETECTED")
    )

    return result
