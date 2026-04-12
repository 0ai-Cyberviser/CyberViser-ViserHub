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
