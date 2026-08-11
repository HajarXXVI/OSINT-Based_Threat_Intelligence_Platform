# engine/scorer.py
SEVERITY_WEIGHTS = {
    "CRITICAL": 30,
    "HIGH": 18,
    "MEDIUM": 8,
    "LOW": 3
}

# A single finding of a given severity must reach at least that risk band.
# Otherwise one HIGH finding would be displayed as LOW risk.
MIN_SCORE_BY_SEVERITY = {
    "CRITICAL": 75.0,
    "HIGH": 50.0,
    "MEDIUM": 25.0,
    "LOW": 5.0
}

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

RISK_LEVELS = [
    (0, 24, "LOW", "#28a745"),
    (25, 49, "MEDIUM", "#ffc107"),
    (50, 74, "HIGH", "#fd7e14"),
    (75, 100, "CRITICAL", "#dc3545")
]

# Same floor idea as the global score, applied per profile axis so that a
# single CRITICAL finding still reads CRITICAL on its own axis.
PROFILE_FLOORS = {
    "CRITICAL": 75.0,
    "HIGH": 50.0,
    "MEDIUM": 25.0,
    "LOW": 5.0
}


def calculate_score(findings):
    if not findings:
        return {"score": 2.0, "level": "LOW", "color": "#28a745"}

    raw_score = 0.0
    critical_count = 0
    high_count = 0
    worst_severity = "UNKNOWN"

    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        raw_score += SEVERITY_WEIGHTS.get(sev, 3)
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(worst_severity, 0):
            worst_severity = sev
        if sev == "CRITICAL":
            critical_count += 1
        elif sev == "HIGH":
            high_count += 1

    if critical_count >= 2:
        raw_score += 15
    elif critical_count == 1 and high_count >= 2:
        raw_score += 10

    # Ensure the worst finding is never rated below its own severity band
    score = max(raw_score, MIN_SCORE_BY_SEVERITY.get(worst_severity, 5.0))
    score = min(score, 100.0)

    for low, high, label, color in RISK_LEVELS:
        if low <= score <= high:
            return {"score": round(score, 1), "level": label, "color": color}

    return {"score": 100.0, "level": "CRITICAL", "color": "#dc3545"}


def _band_for(index):
    for low, high, label, _ in RISK_LEVELS:
        if low <= index <= high:
            return label
    return "LOW"


def calculate_profiles(findings):
    """
    Splits findings into two independent axes:
      - exposure_index: how easily the TARGET could be compromised
        (open ports, known CVEs, intrusion/exfiltration findings).
      - threat_index:   how dangerous the TARGET is to others
        (malicious reputation findings, credential-stuffing).
    Each axis uses the same floor logic as the global score, so a single
    critical finding still reads as CRITICAL on its own axis. The verdict
    then answers the jury question directly: is this IP a victim (exposure)
    or a danger to others (threat), or both?
    """
    weights = {"exposure": 0.0, "threat": 0.0}
    worst = {"exposure": "UNKNOWN", "threat": "UNKNOWN"}

    for f in findings or []:
        category = "threat" if f.get("category") == "threat" else "exposure"
        sev = str(f.get("severity", "LOW")).upper()
        weights[category] += SEVERITY_WEIGHTS.get(sev, 3)
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(worst[category], 0):
            worst[category] = sev

    def _index(category):
        floored = max(weights[category], PROFILE_FLOORS.get(worst[category], 5.0))
        return round(min(floored, 100.0), 1)

    exposure_index = _index("exposure")
    threat_index = _index("threat")
    exposure_band = _band_for(exposure_index)
    threat_band = _band_for(threat_index)

    if exposure_band in ("HIGH", "CRITICAL") and threat_band in ("HIGH", "CRITICAL"):
        verdict = "Cible Exposée ET Acteur de Menace Potentiel"
    elif exposure_band in ("HIGH", "CRITICAL"):
        verdict = "Cible Potentielle : Asset Exposé / Compromettable"
    elif threat_band in ("HIGH", "CRITICAL"):
        verdict = "Acteur de Menace Potentiel"
    elif exposure_band == "MEDIUM" or threat_band == "MEDIUM":
        verdict = "Préoccupation Modérée"
    else:
        verdict = "Faible Préoccupation — Ressource A Priori Saine"

    return {
        "exposure_index": exposure_index,
        "threat_index": threat_index,
        "exposure_band": exposure_band,
        "threat_band": threat_band,
        "profile": verdict
    }
