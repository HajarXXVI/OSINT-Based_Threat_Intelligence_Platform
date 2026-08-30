# apis/crt_api.py
import base64
import json
import logging
import socket
import time
import requests
import warnings
from datetime import datetime, timedelta

with warnings.catch_warnings():
    warnings.simplefilter("ignore")

CRT_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
TIMEOUT = 8              # per-request timeout for crt.sh (seconds)
CERTSPOTTER_TIMEOUT = 25  # fallback answers very large domains slowly, so give it a longer budget
BACKOFFS = [0, 3, 5]  # delay before each attempt (rate-limit politeness)
DEADLINE = 20         # hard budget for the whole crt.sh lookup
CACHE_TTL_HOURS = 24  # how long a cached subdomain listing stays fresh
MAX_RESULTS = 100     # cap so a huge domain cannot make us loop forever


CRT_DEFAULTS = {
    "enabled": True,
    "subdomains": [],
    "total": 0,
    "checked": 0,
    "alive": 0,
    "source": None,
    "error": None,
}

# Legacy wording used by an older version when both CT sources answered but
# found no certificates. Kept so cached rows from before this fix render the
# normal "no subdomains found" state instead of a misleading warning.
NO_CERTS_FOUND_TEXT = "No certificates found in public certificate transparency logs"


def _looks_like_ip(clean):
    return "." in clean and clean.replace(".", "").isdigit()


def _certspotter_key():
    """Reads the Cert Spotter Monitoring API key from the environment (via
    Config / .env). Empty string means 'use the anonymous low-rate tier'."""
    try:
        from config import Config
        return (getattr(Config, 'CERTSPOTTER_API_KEY', '') or '').strip()
    except Exception:
        return ""


def _query_crt(domain, max_results):
    """
    Queries the public Certificate Transparency log (crt.sh) for every
    subdomain of `domain` that has ever had an SSL certificate issued.

    Rate-limit / flakiness strategy:
      * the whole lookup is bounded by a hard deadline (~20s);
      * each request has its own timeout (8s, capped to the remaining budget);
      * we back off for a few seconds between attempts (crt.sh is flaky);
      * the result list is capped so we never loop without end.

    Purely passive: we only READ the public CT log, never the target's servers.
    Returns (names, error).
    """
    names = set()
    start = time.time()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for attempt in range(3):
            if time.time() >= start + DEADLINE:
                break
            delay = BACKOFFS[attempt] if attempt < len(BACKOFFS) else 0
            if delay:
                time.sleep(delay)
            remaining = DEADLINE - (time.time() - start)
            if remaining <= 0:
                break
            request_timeout = min(TIMEOUT, remaining)
            try:
                resp = requests.get(
                    CRT_URL,
                    params={"q": f"%25.{domain}", "output": "json"},
                    timeout=request_timeout,
                )
                if resp.status_code != 200:
                    logging.warning(f"crt.sh returned {resp.status_code} (attempt {attempt + 1})")
                    continue
                data = resp.json()
                for entry in data or []:
                    for line in (entry.get("name_value") or "").split("\n"):
                        name = line.strip().lstrip("*.").lower()
                        # Keep names that belong to this domain exactly once,
                        # dedupe case-insensitively, and drop the apex domain.
                        if (name.endswith("." + domain) or name == domain) and name != domain:
                            names.add(name)
                            if max_results and len(names) >= max_results:
                                return sorted(names), None
                return sorted(names), None
            except Exception as e:
                logging.warning(f"crt.sh lookup attempt {attempt + 1} failed: {e}")
    if not names:
        return sorted(names), "primary CT-log source unreachable after retries"
    return sorted(names), None


def _query_certspotter(domain, api_key, max_results):
    """
    Fallback passive CT-log source (SSLMate Cert Spotter). Same query, clean
    JSON API. Accepts the token as HTTP Basic ('username:password') or as a
    plain Bearer token. Returns (names, error).
    """
    params = {
        "domain": domain,
        "include_subdomains": "true",
        "match_wildcards": "true",
        "expand": "dns_names",
    }
    headers = {}
    if api_key:
        if ":" in api_key:
            encoded = base64.b64encode(api_key.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        else:
            headers["Authorization"] = f"Bearer {api_key}"
    try:
        resp = requests.get(CERTSPOTTER_URL, params=params, headers=headers, timeout=CERTSPOTTER_TIMEOUT)
        if resp.status_code != 200:
            return None, f"fallback CT-log source returned {resp.status_code}"
        names = set()
        for issuance in resp.json() or []:
            for dn in (issuance.get("dns_names") or []):
                name = dn.strip().lstrip("*.").lower()
                if (name.endswith("." + domain) or name == domain) and name != domain:
                    names.add(name)
                    if max_results and len(names) >= max_results:
                        return sorted(names), None
        return sorted(names), None
    except Exception as e:
        return None, f"fallback CT-log source lookup failed: {e}"


def _subdomain_is_alive(sub):
    """Cheap passive liveness check: does the subdomain resolve to an IP?"""
    try:
        socket.gethostbyname(sub)
        return True
    except Exception:
        return False


def get_subdomains(target, certspotter_key=None, max_results=MAX_RESULTS):
    """
    Discovers subdomains of `target` (a domain) via Certificate
    Transparency logs. Tries crt.sh first; if it is down or returns nothing,
    falls back to Cert Spotter (keyed when available) so a single flaky free
    service cannot silently empty the feature. Each discovered subdomain also
    gets ONE cheap, free liveness check so the listing is actionable without
    burning real scan quota.

    Returns a dict the report widget renders as a compact list, each row with
    a 'Scan' button to run a full scan (Shodan/NVD) on that specific
    subdomain. The "source" field records which CT service was used.
    """
    clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    if not clean or "." not in clean or _looks_like_ip(clean):
        return dict(CRT_DEFAULTS)

    result = dict(CRT_DEFAULTS)

    names, crt_error = _query_crt(clean, max_results)
    source = "crt.sh"
    if crt_error is None and names:
        pass  # primary source delivered
    else:
        # Primary source failed or was empty -> try the fallback provider
        api_key = _certspotter_key() if certspotter_key is None else certspotter_key
        alt_names, cs_error = _query_certspotter(clean, api_key, max_results)
        if cs_error is None and alt_names:
            names = alt_names
            source = "certspotter"
        elif cs_error is None:
            # Both CT sources answered successfully but found no certificates
            # for this domain. Benign, NOT an error: leave the error field
            # unset so the report shows its normal "no subdomains found" state
            # instead of a contradictory "lookup unavailable" warning.
            pass
        else:
            result["error"] = f"{crt_error or 'no certificates found in public CT logs'} | {cs_error}"

    result["source"] = source

    # Each row carries its own liveness flag so the report can render per-row
    # indicators; sort alive (interesting) first, then alphabetically.
    rows = []
    for sub in names:
        alive = _subdomain_is_alive(sub)
        rows.append({"name": sub, "alive": alive})

    rows.sort(key=lambda r: (not r["alive"], r["name"]))
    result["subdomains"] = rows
    result["alive"] = sum(1 for r in rows if r["alive"])
    result["total"] = len(rows)
    result["checked"] = len(rows)
    return result


def discover_subdomains_cached(target, max_age_hours=CACHE_TTL_HOURS, max_results=MAX_RESULTS):
    """
    Cache-aware subdomain discovery for the scan pipeline.

    Returns the fresh cached listing when one exists (< max_age_hours old),
    otherwise queries the CT sources live and stores the result so the same
    domain never pays the slow lookup more than once per cache window. The
    returned dict carries a "cached" flag so the UI can tell the operator
    whether the listing is live or cached. Never raises: on failure it returns
    the default payload with an "error" message for the report section.
    """
    clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    if not clean or "." not in clean or _looks_like_ip(clean):
        return dict(CRT_DEFAULTS)

    from models import SubdomainCache, db

    result = dict(CRT_DEFAULTS)
    try:
        row = db.session.get(SubdomainCache, clean)
        if row and row.data and row.fetched_at:
            age = datetime.utcnow() - row.fetched_at
            if age < timedelta(hours=max_age_hours):
                result = json.loads(row.data)
                if result.get("error") == NO_CERTS_FOUND_TEXT:
                    result["error"] = None
                # Never serve a cached FAILURE: it represents a transient outage
                # and would block a genuine retry for the whole cache window.
                if not result.get("error"):
                    result["cached"] = True
                    return result

        result = get_subdomains(clean, max_results=max_results)
        result["cached"] = False

        # Only successful listings are cached, so the next scan genuinely
        # retries after a transient CT-source outage.
        if not result.get("error"):
            row = db.session.get(SubdomainCache, clean) or SubdomainCache(domain=clean)
            row.data = json.dumps(result)
            row.fetched_at = datetime.utcnow()
            db.session.add(row)
            db.session.commit()
    except Exception as e:
        logging.warning(f"subdomain discovery failed for {clean}: {e}")
        result = dict(CRT_DEFAULTS)
        result["error"] = str(e)
    return result