# apis/metadata_api.py
import socket
import ssl
import datetime
import logging
import requests

WHOIS_DEFAULTS = {
    "registrar": "N/A",
    "creation_date": "N/A",
    "expiration_date": "N/A"
}


def _looks_like_domain(target):
    clean = target.replace("https://", "").replace("http://", "").split("/")[0]
    return "." in clean and not clean.replace(".", "").isdigit()


def _rdap_field(vcard_props, name):
    """
    RDAP encodes contact info as vCards. Each property is a list like
    ["fn", {}, "text", "MarkMonitor Inc."]. Return the value (index 3).
    """
    for prop in vcard_props or []:
        if len(prop) >= 4 and prop[0] == name:
            return prop[3]
    return None


def _parse_rdap(data):
    """
    Extracts the registrar and registration/expiration dates from an
    RDAP domain JSON document. Unknown fields stay "N/A".
    """
    events = {}
    for event in data.get("events", []) or []:
        events[event.get("eventAction")] = event.get("eventDate", "N/A")

    registrar = "N/A"
    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        props = vcard[1] if len(vcard) > 1 else []
        name = _rdap_field(props, "fn") or _rdap_field(props, "org")
        if "registrar" in roles and name:
            registrar = name
            break

    def date_part(value):
        return value[:10] if isinstance(value, str) and value else "N/A"

    return {
        "registrar": registrar,
        "creation_date": date_part(events.get("registration")),
        "expiration_date": date_part(events.get("expiration"))
    }


def get_whois_info(target):
    """
    Fetches real WHOIS registration data via the modern RDAP protocol
    (HTTPS + JSON, free, no API key). rdap.org redirects to the correct
    registry server for the domain's TLD. Falls back to N/A on any
    failure so the scan pipeline never crashes.
    """
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    if not _looks_like_domain(clean_target):
        return dict(WHOIS_DEFAULTS)

    try:
        response = requests.get(f"https://rdap.org/domain/{clean_target}", timeout=5)
        if response.status_code == 200:
            return _parse_rdap(response.json())
    except Exception as e:
        logging.warning(f"RDAP lookup failed for {clean_target}: {e}")

    return dict(WHOIS_DEFAULTS)


def get_ssl_certificate_info(target):
    """
    Connects to port 443 via Python's built-in ssl/socket modules
    to extract real certificate issuer and expiration details safely.
    """
    ssl_data = {
        "has_ssl": False,
        "issuer": "N/A",
        "expires_in_days": "N/A",
        "subject": "N/A"
    }

    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((clean_target, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=clean_target) as ssock:
                # CERT_NONE mode makes getpeercert() return an empty dict, so we
                # fetch the raw DER bytes and decode them with the `cryptography`
                # library. This works for every certificate, valid or not.
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return ssl_data

                from cryptography import x509
                cert = x509.load_der_x509_certificate(cert_der)

                ssl_data["has_ssl"] = True

                # Extract Issuer (prefer Organization, fall back to Common Name)
                issuer = cert.issuer
                ssl_data["issuer"] = (
                    issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                    or issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                )[0].value

                # Extract Expiration & Subject
                not_after = cert.not_valid_after_utc
                days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
                ssl_data["expires_in_days"] = str(days_left)

                subject = cert.subject
                cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                ssl_data["subject"] = cn[0].value if cn else "N/A"
    except Exception:
        # Fails silently if port 443 is closed or times out, keeping the app 100% stable
        pass

    return ssl_data