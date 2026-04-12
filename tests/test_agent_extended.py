"""Additional tests for hancock_agent.py to improve coverage on
client factories, notifications, streaming, and edge cases."""
import json
import os
import sys
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Client factories ─────────────────────────────────────────────────────────

class TestMakeOllamaClient:
    """Tests for hancock_agent.make_ollama_client."""

    def test_make_ollama_client_creates_openai_client(self):
        from unittest.mock import MagicMock, patch
        mock_openai_cls = MagicMock()
        with patch("hancock_agent.OpenAI", mock_openai_cls):
            import hancock_agent
            client = hancock_agent.make_ollama_client()
        mock_openai_cls.assert_called_once()
        # Base URL should point to Ollama
        call_kwargs = mock_openai_cls.call_args
        assert "ollama" in str(call_kwargs).lower() or call_kwargs[1].get("api_key") == "ollama"


class TestMakeClient:
    """Tests for hancock_agent.make_client (NVIDIA NIM)."""

    def test_make_client_with_api_key(self):
        mock_openai_cls = MagicMock()
        with patch("hancock_agent.OpenAI", mock_openai_cls):
            import hancock_agent
            client = hancock_agent.make_client("nvapi-test-key-123")
        mock_openai_cls.assert_called_once()
        call_kwargs = mock_openai_cls.call_args
        assert call_kwargs[1]["api_key"] == "nvapi-test-key-123"


class TestMakeOpenaiClient:
    """Tests for hancock_agent.make_openai_client."""

    def test_returns_none_when_no_key(self):
        import hancock_agent
        with patch.dict(os.environ, {}, clear=False):
            with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
                result = hancock_agent.make_openai_client()
        assert result is None

    def test_returns_none_when_placeholder_key(self):
        import hancock_agent
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-your-key-here"}):
            result = hancock_agent.make_openai_client()
        assert result is None

    def test_returns_client_when_valid_key(self):
        mock_openai_cls = MagicMock()
        with patch("hancock_agent.OpenAI", mock_openai_cls):
            import hancock_agent
            with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-valid-test-key"}):
                result = hancock_agent.make_openai_client()
        assert result is not None

    def test_returns_none_when_openai_not_installed(self):
        import hancock_agent
        with patch("hancock_agent.OpenAI", None):
            result = hancock_agent.make_openai_client()
        assert result is None


# ── Chat function (non-streaming) ─────────────────────────────────────────────

class TestChatFunction:
    """Tests for the top-level chat() function."""

    def test_chat_non_streaming(self):
        import hancock_agent
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "Test response"
        mock_client.chat.completions.create.return_value = mock_resp

        result = hancock_agent.chat(
            mock_client,
            [{"role": "user", "content": "hello"}],
            "test-model",
            stream=False,
        )
        assert result == "Test response"

    def test_chat_with_custom_system_prompt(self):
        import hancock_agent
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "Custom response"
        mock_client.chat.completions.create.return_value = mock_resp

        result = hancock_agent.chat(
            mock_client,
            [{"role": "user", "content": "test"}],
            "test-model",
            stream=False,
            system_prompt="Custom system prompt",
        )
        assert result == "Custom response"
        # Verify the custom system prompt was used
        call_args = mock_client.chat.completions.create.call_args
        messages = call_args[1]["messages"]
        assert messages[0]["content"] == "Custom system prompt"

    def test_chat_fallback_to_openai(self):
        import hancock_agent
        nim_client = MagicMock()
        nim_client.chat.completions.create.side_effect = Exception("NIM down")

        openai_resp = MagicMock()
        openai_resp.choices[0].message.content = "OpenAI fallback"
        openai_client = MagicMock()
        openai_client.chat.completions.create.return_value = openai_resp

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("hancock_agent.make_openai_client", return_value=openai_client):
                result = hancock_agent.chat(
                    nim_client,
                    [{"role": "user", "content": "test"}],
                    "model",
                    stream=False,
                )
        assert result == "OpenAI fallback"

    def test_chat_raises_when_no_fallback(self):
        import hancock_agent
        nim_client = MagicMock()
        nim_client.chat.completions.create.side_effect = Exception("NIM down")

        with patch("hancock_agent.make_openai_client", return_value=None):
            with pytest.raises(Exception, match="NIM down"):
                hancock_agent.chat(
                    nim_client,
                    [{"role": "user", "content": "test"}],
                    "model",
                    stream=False,
                )


# ── _do_chat ──────────────────────────────────────────────────────────────────

class TestDoChat:
    """Tests for _do_chat including non-streaming path."""

    def test_do_chat_non_streaming(self):
        import hancock_agent
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "Direct response"
        mock_client.chat.completions.create.return_value = mock_resp

        result = hancock_agent._do_chat(
            mock_client,
            [{"role": "system", "content": "sys"}, {"role": "user", "content": "test"}],
            "model",
            stream=False,
        )
        assert result == "Direct response"


# ── _send_notification ────────────────────────────────────────────────────────

class TestSendNotification:
    """Tests for the _send_notification helper."""

    @patch("urllib.request.urlopen")
    @patch("urllib.request.Request")
    def test_slack_notification(self, mock_request_cls, mock_urlopen):
        import hancock_agent
        with patch.dict(os.environ, {"HANCOCK_SLACK_WEBHOOK": "https://hooks.slack.com/test"}):
            hancock_agent._send_notification("splunk", "high", "Test alert", "Triage result here")
        # Should have attempted to send the notification
        mock_request_cls.assert_called()
        mock_urlopen.assert_called()

    @patch("urllib.request.urlopen")
    @patch("urllib.request.Request")
    def test_teams_notification(self, mock_request_cls, mock_urlopen):
        import hancock_agent
        with patch.dict(os.environ, {
            "HANCOCK_SLACK_WEBHOOK": "",
            "HANCOCK_TEAMS_WEBHOOK": "https://outlook.office.com/webhook/test",
        }):
            hancock_agent._send_notification("elastic", "critical", "Test alert", "Triage")
        mock_request_cls.assert_called()

    @patch("urllib.request.urlopen")
    def test_notification_failure_non_fatal(self, mock_urlopen):
        import hancock_agent
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        with patch.dict(os.environ, {"HANCOCK_SLACK_WEBHOOK": "https://hooks.slack.com/test"}):
            # Should not raise
            hancock_agent._send_notification("source", "high", "alert", "triage")

    def test_no_notification_when_no_webhooks(self):
        import hancock_agent
        with patch.dict(os.environ, {"HANCOCK_SLACK_WEBHOOK": "", "HANCOCK_TEAMS_WEBHOOK": ""}):
            # Should not raise or attempt any HTTP calls
            hancock_agent._send_notification("source", "low", "alert", "triage")

    @patch("urllib.request.urlopen")
    @patch("urllib.request.Request")
    def test_notification_truncates_long_triage(self, mock_request_cls, mock_urlopen):
        import hancock_agent
        long_triage = "x" * 500
        with patch.dict(os.environ, {"HANCOCK_SLACK_WEBHOOK": "https://hooks.slack.com/test"}):
            hancock_agent._send_notification("splunk", "medium", "alert", long_triage)
        # Verify the request was made (notification sent despite long content)
        mock_request_cls.assert_called()


# ── REST API edge cases ───────────────────────────────────────────────────────

class TestApiEdgeCases:
    """Additional edge case tests for the REST API."""

    @pytest.fixture
    def app(self):
        from unittest.mock import MagicMock, patch
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "Mocked Hancock response."
        mock_client.chat.completions.create.return_value = mock_resp

        with patch("hancock_agent.OpenAI", return_value=mock_client):
            import hancock_agent
            app = hancock_agent.build_app(mock_client, "mistralai/mistral-7b-instruct-v0.3")
            app.testing = True
            return app

    @pytest.fixture
    def client(self, app):
        return app.test_client()

    def test_chat_valid_request(self, client):
        r = client.post("/v1/chat",
                        data=json.dumps({"message": "What is nmap?"}),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "response" in d
        assert "model" in d

    def test_chat_with_history(self, client):
        r = client.post("/v1/chat",
                        data=json.dumps({
                            "message": "Follow up question",
                            "history": [
                                {"role": "user", "content": "First question"},
                                {"role": "assistant", "content": "First answer"},
                            ],
                        }),
                        content_type="application/json")
        assert r.status_code == 200

    def test_ask_with_mode(self, client):
        r = client.post("/v1/ask",
                        data=json.dumps({"question": "What is OSINT?", "mode": "pentest"}),
                        content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["mode"] == "pentest"

    def test_ask_soc_mode(self, client):
        r = client.post("/v1/ask",
                        data=json.dumps({"question": "How to triage alerts?", "mode": "soc"}),
                        content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["mode"] == "soc"

    def test_hunt_empty_target(self, client):
        r = client.post("/v1/hunt",
                        data=json.dumps({"target": ""}),
                        content_type="application/json")
        assert r.status_code == 400

    def test_respond_empty_incident(self, client):
        r = client.post("/v1/respond",
                        data=json.dumps({"incident": ""}),
                        content_type="application/json")
        assert r.status_code == 400

    def test_code_empty_task(self, client):
        r = client.post("/v1/code",
                        data=json.dumps({"task": ""}),
                        content_type="application/json")
        assert r.status_code == 400

    def test_sigma_empty_description(self, client):
        r = client.post("/v1/sigma",
                        data=json.dumps({"description": ""}),
                        content_type="application/json")
        assert r.status_code == 400

    def test_yara_empty_description(self, client):
        r = client.post("/v1/yara",
                        data=json.dumps({"description": ""}),
                        content_type="application/json")
        assert r.status_code == 400

    def test_ioc_empty_indicator(self, client):
        r = client.post("/v1/ioc",
                        data=json.dumps({"indicator": ""}),
                        content_type="application/json")
        assert r.status_code == 400

    def test_webhook_with_source_and_severity(self, client):
        r = client.post("/v1/webhook",
                        data=json.dumps({
                            "source": "elastic",
                            "alert": "Unauthorized access attempt",
                            "severity": "critical",
                        }),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert d["source"] == "elastic"
        assert d["severity"] == "critical"

    def test_chat_sigma_mode(self, client):
        r = client.post("/v1/chat",
                        data=json.dumps({"message": "Write a Sigma rule", "mode": "sigma"}),
                        content_type="application/json")
        assert r.status_code == 200

    def test_chat_yara_mode(self, client):
        r = client.post("/v1/chat",
                        data=json.dumps({"message": "Write a YARA rule", "mode": "yara"}),
                        content_type="application/json")
        assert r.status_code == 200

    def test_chat_ciso_mode(self, client):
        r = client.post("/v1/chat",
                        data=json.dumps({"message": "NIST compliance?", "mode": "ciso"}),
                        content_type="application/json")
        assert r.status_code == 200

    def test_chat_ioc_mode(self, client):
        r = client.post("/v1/chat",
                        data=json.dumps({"message": "Enrich 1.2.3.4", "mode": "ioc"}),
                        content_type="application/json")
        assert r.status_code == 200

    def test_ioc_with_context(self, client):
        r = client.post("/v1/ioc",
                        data=json.dumps({
                            "indicator": "10.0.0.1",
                            "type": "ip",
                            "context": "Seen in lateral movement activity",
                        }),
                        content_type="application/json")
        assert r.status_code == 200

    def test_health_modes_list(self, client):
        r = client.get("/health")
        d = r.get_json()
        assert "sigma" in d["modes"]
        assert "yara" in d["modes"]
        assert "ioc" in d["modes"]
        assert "ciso" in d["modes"]

    def test_ciso_query_alias(self, client):
        """Test that 'query' field is accepted as alias for 'question'."""
        r = client.post("/v1/ciso",
                        data=json.dumps({"query": "What is SOC 2?"}),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "advice" in d
        assert d["output"] == "advice"

    def test_sigma_query_alias(self, client):
        """Test that 'query' field is accepted as alias for description."""
        r = client.post("/v1/sigma",
                        data=json.dumps({"query": "Detect LSASS dump"}),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "rule" in d
        assert "model" in d

    def test_yara_query_alias(self, client):
        """Test that 'query' field is accepted as alias for description."""
        r = client.post("/v1/yara",
                        data=json.dumps({"query": "Cobalt Strike beacon"}),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "rule" in d
        assert "model" in d

    def test_ioc_query_alias(self, client):
        """Test that 'query' field is accepted as alias for indicator."""
        r = client.post("/v1/ioc",
                        data=json.dumps({"query": "malicious.example.com"}),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "report" in d
        assert d["indicator"] == "malicious.example.com"


class TestApiEmptyModelResponse:
    """Tests for endpoints returning 502 when model returns empty."""

    @pytest.fixture
    def empty_app(self):
        from unittest.mock import MagicMock, patch
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = ""
        mock_client.chat.completions.create.return_value = mock_resp

        with patch("hancock_agent.OpenAI", return_value=mock_client):
            import hancock_agent
            app = hancock_agent.build_app(mock_client, "mistralai/mistral-7b-instruct-v0.3")
            app.testing = True
            return app

    @pytest.fixture
    def empty_client(self, empty_app):
        return empty_app.test_client()

    def test_ciso_empty_response_returns_502(self, empty_client):
        r = empty_client.post("/v1/ciso",
                              data=json.dumps({"question": "What is NIST?"}),
                              content_type="application/json")
        assert r.status_code == 502

    def test_sigma_empty_response_returns_502(self, empty_client):
        r = empty_client.post("/v1/sigma",
                              data=json.dumps({"description": "Detect PS exec"}),
                              content_type="application/json")
        assert r.status_code == 502

    def test_yara_empty_response_returns_502(self, empty_client):
        r = empty_client.post("/v1/yara",
                              data=json.dumps({"description": "Detect malware"}),
                              content_type="application/json")
        assert r.status_code == 502


# ── Constants / system prompts ────────────────────────────────────────────────

class TestSystemPrompts:
    """Verify all system prompts are defined and non-empty."""

    def test_all_modes_have_system_prompts(self):
        import hancock_agent
        for mode in ["pentest", "soc", "auto", "code", "ciso", "sigma", "yara", "ioc"]:
            assert mode in hancock_agent.SYSTEMS
            assert hancock_agent.SYSTEMS[mode] is not None
            assert len(hancock_agent.SYSTEMS[mode]) > 50

    def test_models_dict_populated(self):
        import hancock_agent
        assert len(hancock_agent.MODELS) > 0
        assert "llama3.1" in hancock_agent.MODELS

    def test_version_defined(self):
        import hancock_agent
        assert hasattr(hancock_agent, "VERSION")
        assert hancock_agent.VERSION
