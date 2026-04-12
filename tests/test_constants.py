"""Unit tests for hancock_constants module."""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hancock_constants import OPENAI_IMPORT_ERROR_MSG, require_openai


class TestRequireOpenai:
    """Tests for the require_openai guard function."""

    def test_raises_import_error_when_none(self):
        """require_openai(None) should raise ImportError."""
        with pytest.raises(ImportError, match="OpenAI client not installed"):
            require_openai(None)

    def test_error_message_content(self):
        """The error message should include install instructions."""
        assert "pip install openai" in OPENAI_IMPORT_ERROR_MSG

    def test_no_error_when_class_provided(self):
        """require_openai should not raise when a non-None class is passed."""
        # Any truthy object should pass the check without error
        require_openai(object)

    def test_no_error_when_mock_class_provided(self):
        """require_openai works with a mock OpenAI class."""
        from unittest.mock import MagicMock
        require_openai(MagicMock)
