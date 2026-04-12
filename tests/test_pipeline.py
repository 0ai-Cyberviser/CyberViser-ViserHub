"""Unit tests for hancock_pipeline.py."""
import os
import sys
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPipelineRunners:
    """Tests for individual pipeline runner functions."""

    def test_run_kb_success(self):
        import hancock_pipeline
        with patch("collectors.pentest_kb.build") as mock_build:
            result = hancock_pipeline.run_kb(Path("/tmp/data"))
        assert result is True
        mock_build.assert_called_once()

    def test_run_kb_failure(self):
        import hancock_pipeline
        with patch("collectors.pentest_kb.build", side_effect=Exception("build failed")):
            result = hancock_pipeline.run_kb(Path("/tmp/data"))
        assert result is False

    def test_run_mitre_success(self):
        import hancock_pipeline
        with patch("collectors.mitre_collector.collect") as mock_collect:
            result = hancock_pipeline.run_mitre(Path("/tmp/data"))
        assert result is True
        mock_collect.assert_called_once()

    def test_run_mitre_failure(self):
        import hancock_pipeline
        with patch("collectors.mitre_collector.collect", side_effect=Exception("network error")):
            result = hancock_pipeline.run_mitre(Path("/tmp/data"))
        assert result is False

    def test_run_nvd_success(self):
        import hancock_pipeline
        with patch("collectors.nvd_collector.collect") as mock_collect:
            result = hancock_pipeline.run_nvd(Path("/tmp/data"))
        assert result is True
        mock_collect.assert_called_once()

    def test_run_nvd_failure(self):
        import hancock_pipeline
        with patch("collectors.nvd_collector.collect", side_effect=Exception("rate limit")):
            result = hancock_pipeline.run_nvd(Path("/tmp/data"))
        assert result is False

    def test_run_soc_kb_success(self):
        import hancock_pipeline
        with patch("collectors.soc_kb.build") as mock_build:
            result = hancock_pipeline.run_soc_kb(Path("/tmp/data"))
        assert result is True
        mock_build.assert_called_once()

    def test_run_soc_kb_failure(self):
        import hancock_pipeline
        with patch("collectors.soc_kb.build", side_effect=Exception("error")):
            result = hancock_pipeline.run_soc_kb(Path("/tmp/data"))
        assert result is False

    def test_run_soc_collector_success(self):
        import hancock_pipeline
        with patch("collectors.soc_collector.collect") as mock_collect:
            result = hancock_pipeline.run_soc_collector(Path("/tmp/data"))
        assert result is True
        mock_collect.assert_called_once()

    def test_run_soc_collector_failure(self):
        import hancock_pipeline
        with patch("collectors.soc_collector.collect", side_effect=Exception("error")):
            result = hancock_pipeline.run_soc_collector(Path("/tmp/data"))
        assert result is False

    def test_run_kev_success(self):
        import hancock_pipeline
        with patch("collectors.cisa_kev_collector.collect") as mock_collect:
            result = hancock_pipeline.run_kev(Path("/tmp/data"))
        assert result is True
        mock_collect.assert_called_once()

    def test_run_kev_failure(self):
        import hancock_pipeline
        with patch("collectors.cisa_kev_collector.collect", side_effect=Exception("error")):
            result = hancock_pipeline.run_kev(Path("/tmp/data"))
        assert result is False

    def test_run_atomic_success(self):
        import hancock_pipeline
        with patch("collectors.atomic_collector.collect") as mock_collect:
            result = hancock_pipeline.run_atomic(Path("/tmp/data"))
        assert result is True
        mock_collect.assert_called_once()

    def test_run_atomic_failure(self):
        import hancock_pipeline
        with patch("collectors.atomic_collector.collect", side_effect=Exception("error")):
            result = hancock_pipeline.run_atomic(Path("/tmp/data"))
        assert result is False

    def test_run_ghsa_success(self):
        import hancock_pipeline
        with patch("collectors.ghsa_collector.collect") as mock_collect:
            result = hancock_pipeline.run_ghsa(Path("/tmp/data"))
        assert result is True
        mock_collect.assert_called_once()

    def test_run_ghsa_failure(self):
        import hancock_pipeline
        with patch("collectors.ghsa_collector.collect", side_effect=Exception("error")):
            result = hancock_pipeline.run_ghsa(Path("/tmp/data"))
        assert result is False


class TestPipelineFormatter:
    """Tests for the formatter runner functions."""

    def test_run_formatter_v1_success(self):
        import hancock_pipeline
        with patch("formatter.to_mistral_jsonl.format_all", return_value=[{"sample": 1}]):
            result = hancock_pipeline.run_formatter(v2=False)
        assert result is True

    def test_run_formatter_v2_success(self):
        import hancock_pipeline
        with patch("formatter.to_mistral_jsonl_v2.format_all", return_value=[{"sample": 1}]):
            result = hancock_pipeline.run_formatter(v2=True)
        assert result is True

    def test_run_formatter_no_samples(self):
        import hancock_pipeline
        with patch("formatter.to_mistral_jsonl.format_all", return_value=[]):
            result = hancock_pipeline.run_formatter(v2=False)
        assert result is False

    def test_run_formatter_exception(self):
        import hancock_pipeline
        with patch("formatter.to_mistral_jsonl.format_all", side_effect=Exception("format error")):
            result = hancock_pipeline.run_formatter(v2=False)
        assert result is False

    def test_run_formatter_v3_success(self):
        import hancock_pipeline
        with patch("collectors.formatter_v3.format_all", return_value=[{"sample": 1}]):
            result = hancock_pipeline.run_formatter_v3()
        assert result is True

    def test_run_formatter_v3_failure(self):
        import hancock_pipeline
        with patch("collectors.formatter_v3.format_all", side_effect=Exception("v3 error")):
            result = hancock_pipeline.run_formatter_v3()
        assert result is False

    def test_run_formatter_v3_empty(self):
        import hancock_pipeline
        with patch("collectors.formatter_v3.format_all", return_value=[]):
            result = hancock_pipeline.run_formatter_v3()
        assert result is False
