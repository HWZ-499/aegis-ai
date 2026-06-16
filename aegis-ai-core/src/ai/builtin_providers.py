"""Built-in LLM provider registration."""

from __future__ import annotations

from .llm_gateway import LLMGateway, OpenAICompatibleProvider
from .provider_config import AIProviderConfig


def build_default_gateway(config: AIProviderConfig) -> LLMGateway:
    """Create a gateway with the built-in OpenAI-compatible providers."""

    def provider_value(name: str, env_name: str, fallback: str) -> str:
        if config.provider == name:
            return config.api_base
        return config.get(env_name, fallback) or ""

    def provider_key(name: str, env_name: str, fallback: str | None = None) -> str | None:
        if config.provider == name:
            return config.api_key
        return config.get(env_name) or fallback

    def provider_model(name: str, env_name: str, fallback: str) -> str:
        if config.provider == name:
            return config.model
        return config.get(env_name, fallback) or fallback

    providers = [
        OpenAICompatibleProvider(
            name="ollama",
            api_key=provider_key("ollama", "OLLAMA_API_KEY", "ollama"),
            base_url=provider_value("ollama", "OLLAMA_BASE_URL", "http://localhost:11434/v1"),
            default_model=provider_model("ollama", "OLLAMA_MODEL", "llama3"),
            requires_api_key=False,
        ),
        OpenAICompatibleProvider(
            name="deepseek",
            api_key=provider_key("deepseek", "DEEPSEEK_API_KEY"),
            base_url=provider_value("deepseek", "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
            default_model=provider_model("deepseek", "DEEPSEEK_MODEL", "deepseek-chat"),
        ),
        OpenAICompatibleProvider(
            name="openai",
            api_key=provider_key("openai", "OPENAI_API_KEY"),
            base_url=provider_value("openai", "OPENAI_BASE_URL", "https://api.openai.com/v1"),
            default_model=provider_model("openai", "OPENAI_MODEL", "gpt-4o-mini"),
        ),
        OpenAICompatibleProvider(
            name="custom",
            api_key=provider_key("custom", "AI_API_KEY"),
            base_url=provider_value("custom", "AI_BASE_URL", ""),
            default_model=provider_model("custom", "AI_MODEL", "gpt-4o-mini"),
        ),
    ]
    return LLMGateway(providers, fallback_order=config.fallback_order)
