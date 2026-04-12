"""Unit tests for formatter modules (to_mistral_jsonl.py and to_mistral_jsonl_v2.py)."""
import json
import os
import sys
import pytest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Formatter v1 — to_mistral_jsonl.py ────────────────────────────────────────

class TestFormatKbPairs:
    """Tests for formatter.to_mistral_jsonl.format_kb_pairs."""

    def test_format_basic_kb_data(self):
        from formatter.to_mistral_jsonl import format_kb_pairs
        kb_data = {
            "system_prompt": "You are Hancock.",
            "pairs": [
                {"user": "What is SQL injection?", "assistant": "SQL injection is a code injection technique."},
                {"user": "Explain XSS?", "assistant": "Cross-site scripting (XSS) is a type of security vulnerability."},
            ]
        }
        result = format_kb_pairs(kb_data)
        assert len(result) == 2
        assert result[0]["messages"][0]["role"] == "system"
        assert result[0]["messages"][0]["content"] == "You are Hancock."
        assert result[0]["messages"][1]["role"] == "user"
        assert result[0]["messages"][1]["content"] == "What is SQL injection?"
        assert result[0]["messages"][2]["role"] == "assistant"

    def test_format_kb_empty_pairs(self):
        from formatter.to_mistral_jsonl import format_kb_pairs
        kb_data = {"system_prompt": "system", "pairs": []}
        result = format_kb_pairs(kb_data)
        assert result == []

    def test_format_kb_uses_default_system_prompt(self):
        from formatter.to_mistral_jsonl import format_kb_pairs, HANCOCK_SYSTEM
        kb_data = {
            "pairs": [
                {"user": "What is nmap?", "assistant": "Nmap is a network scanner."}
            ]
        }
        result = format_kb_pairs(kb_data)
        assert result[0]["messages"][0]["content"] == HANCOCK_SYSTEM


class TestFormatMitreTechniques:
    """Tests for formatter.to_mistral_jsonl.format_mitre_techniques."""

    def test_format_valid_technique(self):
        from formatter.to_mistral_jsonl import format_mitre_techniques
        mitre_data = {
            "techniques": [{
                "name": "PowerShell",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution. " * 5,
                "mitre_id": "T1059.001",
                "kill_chain_phases": ["execution"],
                "platforms": ["Windows"],
                "detection": "Monitor for execution of PowerShell scripts.",
            }]
        }
        result = format_mitre_techniques(mitre_data)
        assert len(result) == 1
        assert "T1059.001" in result[0]["messages"][1]["content"]
        assert "PowerShell" in result[0]["messages"][1]["content"]
        assert "Detection" in result[0]["messages"][2]["content"]

    def test_format_technique_short_description_skipped(self):
        from formatter.to_mistral_jsonl import format_mitre_techniques
        mitre_data = {
            "techniques": [{
                "name": "Short",
                "description": "Too short",
                "mitre_id": "T0001",
                "kill_chain_phases": [],
                "platforms": [],
                "detection": "",
            }]
        }
        result = format_mitre_techniques(mitre_data)
        assert len(result) == 0

    def test_format_technique_no_detection_still_valid(self):
        from formatter.to_mistral_jsonl import format_mitre_techniques
        mitre_data = {
            "techniques": [{
                "name": "Some Technique",
                "description": "A description that is longer than 80 characters to pass the quality filter in the formatter. " * 2,
                "mitre_id": "T1234",
                "kill_chain_phases": ["initial-access"],
                "platforms": ["Linux", "macOS"],
                "detection": "",
            }]
        }
        result = format_mitre_techniques(mitre_data)
        assert len(result) == 1
        assert "Detection" not in result[0]["messages"][2]["content"]

    def test_format_empty_techniques(self):
        from formatter.to_mistral_jsonl import format_mitre_techniques
        result = format_mitre_techniques({"techniques": []})
        assert result == []


class TestFormatCves:
    """Tests for formatter.to_mistral_jsonl.format_cves."""

    def test_format_critical_cve(self):
        from formatter.to_mistral_jsonl import format_cves
        cve_list = [{
            "cve_id": "CVE-2024-0001",
            "description": "A critical remote code execution vulnerability in the admin panel of Example Server." * 2,
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "cwes": ["CWE-78"],
        }]
        result = format_cves(cve_list)
        assert len(result) == 1
        assert "CVE-2024-0001" in result[0]["messages"][1]["content"]
        assert "Critical" in result[0]["messages"][2]["content"]
        assert "Immediate patching" in result[0]["messages"][2]["content"]

    def test_format_high_cve(self):
        from formatter.to_mistral_jsonl import format_cves
        cve_list = [{
            "cve_id": "CVE-2024-0002",
            "description": "A high severity vulnerability in the authentication module allowing bypass via crafted tokens. " * 2,
            "cvss_score": 7.5,
            "severity": "HIGH",
            "attack_vector": "NETWORK",
            "cwes": [],
        }]
        result = format_cves(cve_list)
        assert len(result) == 1
        assert "High" in result[0]["messages"][2]["content"]

    def test_format_medium_cve(self):
        from formatter.to_mistral_jsonl import format_cves
        cve_list = [{
            "cve_id": "CVE-2024-0003",
            "description": "A medium severity information disclosure vulnerability in the logging module of Example Server." * 2,
            "cvss_score": 5.0,
            "severity": "MEDIUM",
            "attack_vector": "LOCAL",
            "cwes": ["CWE-200"],
        }]
        result = format_cves(cve_list)
        assert len(result) == 1
        assert "Medium" in result[0]["messages"][2]["content"]

    def test_format_cve_short_description_skipped(self):
        from formatter.to_mistral_jsonl import format_cves
        cve_list = [{
            "cve_id": "CVE-2024-0004",
            "description": "Too short",
            "cvss_score": 9.0,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "cwes": [],
        }]
        result = format_cves(cve_list)
        assert len(result) == 0

    def test_format_cve_missing_id_skipped(self):
        from formatter.to_mistral_jsonl import format_cves
        cve_list = [{
            "cve_id": "",
            "description": "A valid description that is long enough to pass the quality filter.",
            "cvss_score": 8.0,
            "severity": "HIGH",
            "attack_vector": "NETWORK",
            "cwes": [],
        }]
        result = format_cves(cve_list)
        assert len(result) == 0

    def test_format_empty_cve_list(self):
        from formatter.to_mistral_jsonl import format_cves
        result = format_cves([])
        assert result == []


class TestValidateSample:
    """Tests for formatter.to_mistral_jsonl.validate_sample."""

    def test_valid_sample_passes(self):
        from formatter.to_mistral_jsonl import validate_sample
        sample = {
            "messages": [
                {"role": "system", "content": "System prompt here"},
                {"role": "user", "content": "A question about security testing?"},
                {"role": "assistant", "content": "A detailed answer about security testing techniques and tools used in practice." * 2},
            ]
        }
        assert validate_sample(sample) is True

    def test_wrong_number_of_messages_fails(self):
        from formatter.to_mistral_jsonl import validate_sample
        assert validate_sample({"messages": [{"role": "user", "content": "test"}]}) is False

    def test_wrong_role_order_fails(self):
        from formatter.to_mistral_jsonl import validate_sample
        sample = {
            "messages": [
                {"role": "user", "content": "user content here"},
                {"role": "system", "content": "system content here"},
                {"role": "assistant", "content": "assistant content here that is long enough to pass validation"},
            ]
        }
        assert validate_sample(sample) is False

    def test_short_user_content_fails(self):
        from formatter.to_mistral_jsonl import validate_sample
        sample = {
            "messages": [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "short"},
                {"role": "assistant", "content": "A long enough assistant response that passes the fifty character minimum length requirement."},
            ]
        }
        assert validate_sample(sample) is False

    def test_short_assistant_content_fails(self):
        from formatter.to_mistral_jsonl import validate_sample
        sample = {
            "messages": [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "A question that is long enough to pass the ten character minimum."},
                {"role": "assistant", "content": "Too short"},
            ]
        }
        assert validate_sample(sample) is False

    def test_empty_messages_fails(self):
        from formatter.to_mistral_jsonl import validate_sample
        assert validate_sample({"messages": []}) is False
        assert validate_sample({}) is False


class TestFormatAll:
    """Tests for formatter.to_mistral_jsonl.format_all with mocked data files."""

    def test_format_all_with_kb_only(self, tmp_path):
        from formatter import to_mistral_jsonl

        kb_data = {
            "system_prompt": "You are Hancock.",
            "pairs": [
                {
                    "user": "What is SQL injection and how does it work?",
                    "assistant": "SQL injection is a code injection technique that exploits vulnerabilities in web applications. " * 3,
                },
            ]
        }
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        with open(data_dir / "raw_pentest_kb.json", "w") as f:
            json.dump(kb_data, f)

        output_file = data_dir / "hancock_pentest_v1.jsonl"
        with patch.object(to_mistral_jsonl, "DATA_DIR", data_dir), \
             patch.object(to_mistral_jsonl, "OUTPUT_FILE", output_file):
            result = to_mistral_jsonl.format_all()

        assert len(result) == 1
        assert output_file.exists()
        # Verify JSONL format
        with open(output_file) as f:
            lines = f.readlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert len(parsed["messages"]) == 3

    def test_format_all_no_data_files(self, tmp_path):
        from formatter import to_mistral_jsonl

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        output_file = data_dir / "hancock_pentest_v1.jsonl"

        with patch.object(to_mistral_jsonl, "DATA_DIR", data_dir), \
             patch.object(to_mistral_jsonl, "OUTPUT_FILE", output_file):
            result = to_mistral_jsonl.format_all()

        assert result == []


# ── Formatter v2 — to_mistral_jsonl_v2.py ────────────────────────────────────

class TestFormatterV2:
    """Tests for formatter.to_mistral_jsonl_v2 specific functionality."""

    def test_format_kb_pairs_v2_with_override(self):
        from formatter.to_mistral_jsonl_v2 import format_kb_pairs
        kb_data = {
            "pairs": [
                {"user": "How do I triage a SIEM alert?", "assistant": "First check the severity, then correlate with other alerts and map to MITRE ATT&CK." * 2},
            ]
        }
        result = format_kb_pairs(kb_data, override_system="Custom SOC system prompt.")
        assert len(result) == 1
        assert result[0]["messages"][0]["content"] == "Custom SOC system prompt."

    def test_format_kb_pairs_v2_default_system(self):
        from formatter.to_mistral_jsonl_v2 import format_kb_pairs
        kb_data = {
            "system_prompt": "Original system prompt.",
            "pairs": [
                {"user": "What is OSINT?", "assistant": "OSINT stands for Open Source Intelligence." * 5},
            ]
        }
        result = format_kb_pairs(kb_data)
        assert result[0]["messages"][0]["content"] == "Original system prompt."

    def test_format_kb_pairs_v2_soc_category(self):
        from formatter.to_mistral_jsonl_v2 import format_kb_pairs, SOC_SYSTEM
        kb_data = {
            "pairs": [
                {
                    "user": "How do I triage alerts?",
                    "assistant": "Triage alerts by checking severity, correlate with other events, and map to MITRE ATT&CK." * 2,
                    "category": "alert_triage",
                },
            ]
        }
        result = format_kb_pairs(kb_data)
        assert result[0]["messages"][0]["content"] == SOC_SYSTEM

    def test_format_mitre_v2(self):
        from formatter.to_mistral_jsonl_v2 import format_mitre_techniques
        mitre_data = {
            "techniques": [{
                "name": "Pass the Hash",
                "description": "Adversaries may use stolen password hashes to authenticate without needing the actual password. " * 3,
                "mitre_id": "T1550.002",
                "kill_chain_phases": ["lateral-movement"],
                "platforms": ["Windows"],
                "detection": "Monitor for unusual NTLM authentication events.",
            }]
        }
        result = format_mitre_techniques(mitre_data)
        assert len(result) == 1
        assert "T1550.002" in result[0]["messages"][1]["content"]

    def test_format_cves_v2_critical(self):
        from formatter.to_mistral_jsonl_v2 import format_cves
        cve_list = [{
            "cve_id": "CVE-2024-1111",
            "description": "A critical RCE in the parser component allowing remote execution via specially crafted input." * 2,
            "cvss_score": 9.5,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "cwes": ["CWE-502"],
        }]
        result = format_cves(cve_list)
        assert len(result) == 1
        assert "CVE-2024-1111" in result[0]["messages"][2]["content"]

    def test_format_soc_detections(self):
        from formatter.to_mistral_jsonl_v2 import format_soc_detections
        detections = [
            {
                "user": "How do I detect lateral movement via PsExec in Splunk?",
                "assistant": "Use the following SPL query to detect PsExec usage: index=windows EventCode=7045 ServiceName=PSEXESVC | table _time host ServiceName" * 2,
            },
            {
                "user": "short",
                "assistant": "too short",  # Should be filtered
            },
        ]
        result = format_soc_detections(detections)
        assert len(result) == 1

    def test_validate_sample_v2(self):
        from formatter.to_mistral_jsonl_v2 import validate_sample
        valid = {
            "messages": [
                {"role": "system", "content": "System prompt"},
                {"role": "user", "content": "Long enough user question about security"},
                {"role": "assistant", "content": "A sufficiently long assistant response that meets the fifty character minimum requirement for validation." * 2},
            ]
        }
        assert validate_sample(valid) is True
        assert validate_sample({"messages": []}) is False

    def test_system_for_helper(self):
        from formatter.to_mistral_jsonl_v2 import _system_for, SOC_SYSTEM, PENTEST_SYSTEM
        assert _system_for("alert_triage") == SOC_SYSTEM
        assert _system_for("siem_queries") == SOC_SYSTEM
        assert _system_for("unknown_category") == PENTEST_SYSTEM


# ── Formatter v3 — collectors/formatter_v3.py ────────────────────────────────

class TestFormatterV3:
    """Tests for collectors.formatter_v3 functions."""

    def test_load_json_existing(self, tmp_path):
        from collectors.formatter_v3 import load_json
        f = tmp_path / "test.json"
        f.write_text('[{"id": 1}]')
        result = load_json(f)
        assert result == [{"id": 1}]

    def test_load_json_missing(self, tmp_path):
        from collectors.formatter_v3 import load_json
        result = load_json(tmp_path / "nonexistent.json")
        assert result == []

    def test_load_jsonl_existing(self, tmp_path):
        from collectors.formatter_v3 import load_jsonl
        f = tmp_path / "test.jsonl"
        f.write_text('{"a": 1}\n{"b": 2}\n')
        result = load_jsonl(f)
        assert len(result) == 2

    def test_load_jsonl_missing(self, tmp_path):
        from collectors.formatter_v3 import load_jsonl
        result = load_jsonl(tmp_path / "nonexistent.jsonl")
        assert result == []

    def test_format_nvd_cves(self):
        from collectors.formatter_v3 import format_nvd_cves
        cves = [{
            "cve_id": "CVE-2024-9999",
            "description": "A critical buffer overflow vulnerability in the network protocol handler of ExampleServer allowing remote code execution." * 2,
            "cvss_score": 9.8,
            "attack_vector": "NETWORK",
            "cwes": ["CWE-120"],
        }]
        result = format_nvd_cves(cves)
        # Should produce 2 samples per CVE (explain + triage)
        assert len(result) == 2
        assert "CVE-2024-9999" in result[0]["messages"][1]["content"]
        assert "triage" in result[1]["messages"][1]["content"].lower()

    def test_format_nvd_cves_filters_short(self):
        from collectors.formatter_v3 import format_nvd_cves
        cves = [{"cve_id": "CVE-2024-0001", "description": "Short", "cvss_score": 5.0}]
        result = format_nvd_cves(cves)
        assert len(result) == 0

    def test_format_kev_entries(self):
        from collectors.formatter_v3 import format_kev_entries
        kevs = [{
            "cve_id": "CVE-2024-5555",
            "name": "Test KEV Vulnerability",
            "description": "Actively exploited vulnerability in test product.",
            "vendor": "TestVendor",
            "product": "TestProduct",
            "action_required": "Apply update per vendor",
            "known_ransomware": "Known",
            "cvss_score": 9.5,
        }]
        result = format_kev_entries(kevs)
        assert len(result) == 1
        assert "ransomware" in result[0]["messages"][2]["content"].lower()
        assert "KEV" in result[0]["messages"][2]["content"]

    def test_format_kev_entries_no_ransomware(self):
        from collectors.formatter_v3 import format_kev_entries
        kevs = [{
            "cve_id": "CVE-2024-6666",
            "name": "Another KEV",
            "description": "Description here.",
            "vendor": "V", "product": "P",
            "action_required": "Patch",
            "known_ransomware": "Unknown",
            "cvss_score": 7.0,
        }]
        result = format_kev_entries(kevs)
        assert len(result) == 1
        assert "⚠️" not in result[0]["messages"][2]["content"]

    def test_format_kev_filters_empty(self):
        from collectors.formatter_v3 import format_kev_entries
        assert format_kev_entries([{"cve_id": "", "description": ""}]) == []

    def test_format_ghsa_advisories(self):
        from collectors.formatter_v3 import format_ghsa_advisories
        advisories = [{
            "ghsa_id": "GHSA-test-1234-abcd",
            "cve_id": "CVE-2024-7777",
            "summary": "Critical RCE in example-lib",
            "description": "A remote code execution vulnerability exists in the deserialization of untrusted input." * 3,
            "ecosystem": "npm",
            "packages": ["example-lib (npm)"],
            "severity": "critical",
            "cvss_score": 9.8,
        }]
        result = format_ghsa_advisories(advisories)
        assert len(result) == 1
        assert "CVE-2024-7777" in result[0]["messages"][1]["content"]

    def test_format_ghsa_filters_short(self):
        from collectors.formatter_v3 import format_ghsa_advisories
        advisories = [{"summary": "Short", "description": "Also short", "ghsa_id": "GHSA-x"}]
        assert format_ghsa_advisories(advisories) == []

    def test_format_atomic_tests(self):
        from collectors.formatter_v3 import format_atomic_tests
        tests = [{
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "test_name": "Encoded Command",
            "description": "Runs a base64-encoded PowerShell command to evade detection.",
            "commands": "powershell -enc dGVzdA==",
            "platforms": "windows",
        }]
        result = format_atomic_tests(tests)
        # Should produce 2 per test (pentest + SOC detection)
        assert len(result) == 2
        assert "T1059.001" in result[0]["messages"][1]["content"]
        assert "detect" in result[1]["messages"][1]["content"].lower()

    def test_format_atomic_filters_empty(self):
        from collectors.formatter_v3 import format_atomic_tests
        assert format_atomic_tests([{"technique_id": "", "description": ""}]) == []

    def test_format_existing_v2(self):
        from collectors.formatter_v3 import format_existing_v2
        samples = [
            {"messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "q"}]},
            {"messages": []},  # should be filtered
            {"other": "no messages key"},  # should be filtered
        ]
        result = format_existing_v2(samples)
        assert len(result) == 1

    def test_format_all_v3(self, tmp_path):
        from collectors import formatter_v3

        data_dir = tmp_path / "data"
        data_dir.mkdir()

        # Write sample data files
        (data_dir / "raw_cve.json").write_text(json.dumps([{
            "cve_id": "CVE-2024-0001",
            "description": "A critical vulnerability in ExampleServer allowing remote code execution via crafted network packets." * 2,
            "cvss_score": 9.8,
            "attack_vector": "NETWORK",
            "cwes": ["CWE-78"],
        }]))
        (data_dir / "raw_kev.json").write_text(json.dumps([]))
        (data_dir / "raw_ghsa.json").write_text(json.dumps([]))
        (data_dir / "raw_atomic.json").write_text(json.dumps([]))
        (data_dir / "hancock_v2.jsonl").write_text("")

        output_file = data_dir / "hancock_v3.jsonl"
        with patch.object(formatter_v3, "DATA_DIR", data_dir), \
             patch.object(formatter_v3, "OUTPUT_FILE", output_file):
            result = formatter_v3.format_all()

        assert len(result) >= 2  # 2 samples per CVE
        assert output_file.exists()


class TestFormatterV2FormatAll:
    """Tests for formatter.to_mistral_jsonl_v2.format_all with mocked data files."""

    def test_format_all_v2_with_all_sources(self, tmp_path):
        from formatter import to_mistral_jsonl_v2

        data_dir = tmp_path / "data"
        data_dir.mkdir()

        # Pentest KB
        (data_dir / "raw_pentest_kb.json").write_text(json.dumps({
            "system_prompt": "You are Hancock.",
            "pairs": [{
                "user": "What is SQL injection and how is it exploited?",
                "assistant": "SQL injection is a code injection technique that exploits input validation vulnerabilities in web applications." * 3,
            }]
        }))
        # SOC KB
        (data_dir / "raw_soc_kb.json").write_text(json.dumps({
            "pairs": [{
                "user": "How do I analyze suspicious PowerShell activity?",
                "assistant": "Analyze PowerShell activity by checking Event ID 4104 for script block logging and correlating with process creation events." * 3,
                "category": "log_analysis",
            }]
        }))
        # MITRE
        (data_dir / "raw_mitre.json").write_text(json.dumps({
            "techniques": [{
                "name": "PowerShell Execution",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution on Windows systems." * 5,
                "mitre_id": "T1059.001",
                "kill_chain_phases": ["execution"],
                "platforms": ["Windows"],
                "detection": "Monitor for PowerShell activity",
            }]
        }))
        # SOC Detections
        (data_dir / "raw_soc_detections.json").write_text(json.dumps([{
            "user": "How do I detect lateral movement via PsExec in my environment?",
            "assistant": "Detect PsExec by monitoring for Event ID 7045 (new service installed) with service name PSEXESVC. Also check for SMB activity." * 3,
        }]))
        # CVEs
        (data_dir / "raw_cve.json").write_text(json.dumps([{
            "cve_id": "CVE-2024-1234",
            "description": "A remote code execution vulnerability in Example Server v1.2.3 via crafted HTTP requests affecting the admin panel." * 2,
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "cwes": ["CWE-78"],
        }]))

        output_file = data_dir / "hancock_v2.jsonl"
        with patch.object(to_mistral_jsonl_v2, "DATA_DIR", data_dir), \
             patch.object(to_mistral_jsonl_v2, "OUTPUT_FILE", output_file):
            result = to_mistral_jsonl_v2.format_all()

        assert len(result) >= 4  # At least one from each source
        assert output_file.exists()

    def test_format_all_v2_no_data(self, tmp_path):
        from formatter import to_mistral_jsonl_v2

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        output_file = data_dir / "hancock_v2.jsonl"

        with patch.object(to_mistral_jsonl_v2, "DATA_DIR", data_dir), \
             patch.object(to_mistral_jsonl_v2, "OUTPUT_FILE", output_file):
            result = to_mistral_jsonl_v2.format_all()

        assert result == []


class TestNvdCollectorCollect:
    """Tests for collectors.nvd_collector.collect with mocked HTTP."""

    @patch("collectors.nvd_collector.time.sleep")
    @patch("collectors.nvd_collector.fetch_page")
    def test_collect_saves_output(self, mock_fetch, mock_sleep, tmp_path):
        from collectors import nvd_collector

        mock_fetch.return_value = {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "A critical vulnerability in Example Server allowing remote code execution via specially crafted HTTP requests."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "attackVector": "NETWORK", "baseSeverity": "CRITICAL"}}]},
                    "weaknesses": [],
                    "references": [],
                }
            }]
        }

        output = tmp_path / "raw_cve.json"
        with patch.object(nvd_collector, "OUTPUT_FILE", output):
            result = nvd_collector.collect()

        assert len(result) >= 1
        assert output.exists()

    @patch("collectors.nvd_collector.time.sleep")
    @patch("collectors.nvd_collector.fetch_page")
    def test_collect_handles_empty_pages(self, mock_fetch, mock_sleep, tmp_path):
        from collectors import nvd_collector
        mock_fetch.return_value = {"totalResults": 0, "vulnerabilities": []}

        output = tmp_path / "raw_cve.json"
        with patch.object(nvd_collector, "OUTPUT_FILE", output):
            result = nvd_collector.collect()

        assert result == []


class TestGhsaCollectorCollect:
    """Tests for collectors.ghsa_collector.collect with mocked HTTP."""

    @patch("collectors.ghsa_collector.time.sleep")
    @patch("collectors.ghsa_collector.fetch_advisories")
    def test_collect_deduplicates(self, mock_fetch, mock_sleep, tmp_path):
        from collectors import ghsa_collector

        # Return same advisory twice for different severity levels
        advisory = {
            "ghsa_id": "GHSA-test-1234",
            "summary": "Test advisory",
            "description": "A critical security issue in example package allowing remote code execution." * 3,
            "severity": "critical",
            "cvss": {"score": 9.0},
            "cwes": [],
            "vulnerabilities": [{"package": {"name": "test", "ecosystem": "npm"}}],
            "identifiers": [],
            "published_at": "2024-01-01",
            "references": [],
        }
        mock_fetch.return_value = [advisory]

        output = tmp_path / "raw_ghsa.json"
        with patch.object(ghsa_collector, "OUTPUT_FILE", output):
            result = ghsa_collector.collect(max_per_eco=1)

        # Should deduplicate — only one unique GHSA ID
        ghsa_ids = [a["ghsa_id"] for a in result]
        assert len(set(ghsa_ids)) == len(ghsa_ids)
        assert output.exists()
