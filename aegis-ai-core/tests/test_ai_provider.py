"""
test_ai_provider.py - AIAnalyzer 多提供商支持单元测试

验证 AIAnalyzer._resolve_provider 的提供商自动推断逻辑：
- 默认 DeepSeek 行为
- 显式 AI_PROVIDER 环境变量（ollama / openai / custom）
- OLLAMA_BASE_URL 自动推断
- OPENAI_API_KEY 自动推断（仅在无 DeepSeek Key 时）
- 构造函数参数覆盖
"""

import pytest

# 清理测试中可能影响结果的环境变量的辅助函数
_PROVIDER_ENV_KEYS = [
    "AI_PROVIDER",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "AI_BASE_URL",
    "AI_API_KEY",
    "AI_MODEL",
]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """每个测试前清理所有提供商相关环境变量。"""
    for key in _PROVIDER_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    yield


from src.scanner.ai_analyzer import AIAnalyzer


class TestResolveProviderDefaults:
    def test_default_is_deepseek(self):
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "deepseek"
        assert "deepseek.com" in base
        assert model == "deepseek-chat"

    def test_deepseek_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-test-key")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "deepseek"
        assert key == "ds-test-key"

    def test_constructor_api_key_overrides_env(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-env-key")
        provider, key, base, model = AIAnalyzer._resolve_provider("explicit-key", None, None)
        assert key == "explicit-key"

    def test_constructor_model_override(self):
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, "deepseek-reasoner")
        assert model == "deepseek-reasoner"


class TestOllamaProvider:
    def test_explicit_ollama_provider(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "ollama"
        assert "11434" in base  # default Ollama port
        assert key == "ollama"  # sentinel value, no real key needed

    def test_ollama_via_base_url(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "ollama"
        assert base == "http://localhost:11434/v1"

    def test_ollama_custom_base_url(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://myserver:8080/v1")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert base == "http://myserver:8080/v1"

    def test_ollama_custom_model(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        monkeypatch.setenv("OLLAMA_MODEL", "mistral")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert model == "mistral"

    def test_ollama_enabled_without_api_key(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        analyzer = AIAnalyzer(enabled=True)
        assert analyzer.enabled is True
        assert analyzer.provider == "ollama"


class TestOpenAIProvider:
    def test_explicit_openai_provider(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "openai"
        assert "openai.com" in base
        assert model == "gpt-4o-mini"

    def test_openai_fallback_when_no_deepseek_key(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-only")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "openai"
        assert key == "sk-openai-only"

    def test_deepseek_wins_when_both_keys_set(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-key")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "deepseek"

    def test_openai_custom_base(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://custom.openai.proxy/v1")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert base == "https://custom.openai.proxy/v1"


class TestCustomProvider:
    def test_custom_provider(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "custom")
        monkeypatch.setenv("AI_BASE_URL", "https://my-llm.example.com/v1")
        monkeypatch.setenv("AI_API_KEY", "custom-key")
        provider, key, base, model = AIAnalyzer._resolve_provider(None, None, None)
        assert provider == "custom"
        assert base == "https://my-llm.example.com/v1"
        assert key == "custom-key"


class TestAnalyzerInit:
    def test_disabled_without_key(self):
        analyzer = AIAnalyzer(enabled=True)
        # No key available → should be disabled
        assert analyzer.enabled is False

    def test_disabled_without_key_returns_structured_config_error(self):
        analyzer = AIAnalyzer(enabled=True)
        result = analyzer.analyze_finding(
            {
                "type": "SQL_INJECTION",
                "severity": "High",
                "line": 12,
                "details": "Potential SQL injection",
                "file": "app.js",
            }
        )
        assert result.error_code == "provider_not_configured"
        assert result.error_message is not None
        assert "provider" in result.error_message.lower()

    def test_enabled_with_deepseek_key(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key")
        analyzer = AIAnalyzer(enabled=True)
        assert analyzer.enabled is True
        assert analyzer.provider == "deepseek"

    def test_provider_logged(self, monkeypatch, caplog):
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        import logging

        with caplog.at_level(logging.INFO, logger="src.scanner.ai_analyzer"):
            AIAnalyzer(enabled=True)
        assert "ollama" in caplog.text.lower()


class TestAiResponseErrors:
    def test_parse_response_without_fixed_code_marks_no_applicable_fix(self):
        analyzer = AIAnalyzer(enabled=False)
        result = analyzer._parse_ai_response(
            '{"confidence": 0.88, "risk_level": "High", "explanation": "Needs review", "fix_description": "Manually parameterize the query"}',
            {"severity": "High", "start_line": 5, "end_line": 5},
        )
        assert result.fixed_code is None
        assert result.error_code == "no_applicable_fix"
        assert result.error_message is not None

    def test_parse_invalid_json_marks_provider_unavailable(self):
        analyzer = AIAnalyzer(enabled=False)
        result = analyzer._parse_ai_response(
            "definitely not json",
            {"severity": "High", "start_line": 2, "end_line": 2},
        )
        assert result.error_code == "provider_unavailable"
        assert result.error_message is not None
