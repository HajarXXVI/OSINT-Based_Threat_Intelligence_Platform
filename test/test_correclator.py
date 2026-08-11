import os
import sys

# Ensure Python can locate 'engine' and 'apis' directories
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
from engine.correlator import ThreatCorrelator
from engine.scorer import calculate_score, calculate_profiles

class TestThreatCorrelator(unittest.TestCase):

    def test_rdp_exposure_flag(self):
        """Verify that exposing port 3389 generates a HIGH severity finding."""
        payload = {
            "shodan": {"ports": [3389], "cpes": []},
            "virustotal": {"stats": {"malicious": 0}},
            "hibp": [],
            "cves": []
        }
        correlator = ThreatCorrelator(payload)
        findings = correlator.correlate()

        # Check that RDP finding was generated
        titles = [f["title"] for f in findings]
        self.assertIn("RDP Exposé Publiquement", titles)

    def test_high_port_volume_score(self):
        """Verify that an IP with > 20 ports triggers a CRITICAL finding and score boost."""
        many_ports = list(range(1000, 1025))  # 25 open ports
        payload = {
            "shodan": {"ports": many_ports},
            "virustotal": {"stats": {"malicious": 0}},
            "hibp": [],
            "cves": []
        }
        correlator = ThreatCorrelator(payload)
        findings = correlator.correlate()
        score_data = calculate_score(findings)

        self.assertGreaterEqual(score_data["score"], 30.0)
        self.assertIn("Surface d'Attaque Critiquement Étendue", [f["title"] for f in findings])

    def test_clean_target_score(self):
        """Verify that a clean target receives a LOW risk rating."""
        payload = {
            "shodan": {"ports": [80, 443]},
            "virustotal": {"stats": {"malicious": 0}},
            "hibp": [],
            "cves": []
        }
        correlator = ThreatCorrelator(payload)
        findings = correlator.correlate()
        score_data = calculate_score(findings)

        self.assertEqual(score_data["level"], "LOW")

    def test_open_ports_profile_is_exposure(self):
        """Open RDP/SSH ports should push the exposure axis, not the threat axis."""
        payload = {
            "shodan": {"ports": [22, 3389]},
            "virustotal": {"stats": {"malicious": 0}},
            "hibp": [],
            "cves": []
        }
        correlator = ThreatCorrelator(payload)
        findings = correlator.correlate()
        profile = calculate_profiles(findings)

        self.assertGreaterEqual(profile["exposure_index"], 50.0)
        self.assertEqual(profile["exposure_band"], "HIGH")
        self.assertLess(profile["threat_index"], 50.0)
        self.assertIn("Asset Exposé", profile["profile"])

    def test_malicious_reputation_profile_is_threat(self):
        """A malicious reputation should push the threat axis, not the exposure axis."""
        payload = {
            "shodan": {"ports": [80, 443]},
            "virustotal": {"stats": {"malicious": 30}},
            "hibp": [],
            "cves": []
        }
        correlator = ThreatCorrelator(payload)
        findings = correlator.correlate()
        profile = calculate_profiles(findings)

        self.assertGreaterEqual(profile["threat_index"], 50.0)
        self.assertEqual(profile["threat_band"], "CRITICAL")
        self.assertLess(profile["exposure_index"], 50.0)
        self.assertIn("Acteur de Menace", profile["profile"])

    def test_findings_are_categorized(self):
        """Every finding must carry an exposure or threat category."""
        payload = {
            "shodan": {"ports": [22, 3389, 3306]},
            "virustotal": {"stats": {"malicious": 7}},
            "hibp": [],
            "cves": [
                {"cve_id": "CVE-2024-0001", "severity": "CRITICAL", "score": 9.8, "description": "x"}
            ]
        }
        correlator = ThreatCorrelator(payload)
        findings = correlator.correlate()

        self.assertTrue(findings)
        for f in findings:
            self.assertIn(f.get("category"), ("exposure", "threat"))

if __name__ == "__main__":
    unittest.main()