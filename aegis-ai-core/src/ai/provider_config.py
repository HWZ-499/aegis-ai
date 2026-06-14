"""AI provider configuration resolution.

Resolution order is explicit constructor values, process environment, then
`.env` values. API keys remain environment/.env only so editors do not need to
store secrets in workspace settings.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from dotenv import dotenv_values

KNOWN_PROVIDERS = {"deepseek", "openai", "ollama", "custom"}

PROVIDER_DEFAULT_MODELS: dict[str, str] = {
    "deepseek": "deepseek-chat",
    "openai": "gpt-4o-mini",
    "ollama": "llama3",
    "custom": "gpt-4o-mini",
}

_CONFIG_KEYS = {
    "AI_PROVIDER",
    "AI_PROVIDER_FALLBACK_ORDER",
    "AI_BASE_URL",
    "AI_API_KEY",
    "AI_MODEL",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "DEEPSEEK_MODEL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_MODEL",
    "OLLAMA_API_KEY",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
}


def _resolve_env_file() -> Path | None:
    explicit = os.getenv("AEGIS_ENV_FILE")
    candidates = [
        Path(explicit).expanduser() if explicit else None,
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[2] / ".env",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    return None


def _load_dotenv_config() -> Mapping[str, str]:
    env_file = _resolve_env_file()
    if env_file is None:
        return {}
    return {key: value for key, value in dotenv_values(env_file).items() if value is not None and isinstance(key, str)}


def _value_from_sources(key: str, dotenv_config: Mapping[str, str]) -> str | None:
    for source in (os.environ, dotenv_config):
        value = source.get(key)
        if value:
            return value
        prefixed_value = source.get(f"AEGIS_{key}")
        if prefixed_value:
            return prefixed_value
    return None


def _collect_config_values() -> dict[str, str]:
    dotenv_config = _load_dotenv_config()
    values: dict[str, str] = {}
    for key in _CONFIG_KEYS:
        value = _value_from_sources(key, dotenv_config)
        if value is not None:
            values[key] = value
    return values


@dataclass(frozen=True)
class AIProviderConfig:
    """Resolved AI provider settings plus source-backed lookup helpers."""

    provider: str
    api_key: str | None = field(default=None, repr=False)
    api_base: str = ""
    model: str = ""
    fallback_order: list[str] = field(default_factory=list)
    values: Mapping[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def from_sources(
        cls,
        api_key: str | None = None,
        api_base: str | None = None,
        model: str | None = None,
    ) -> AIProviderConfig:
        """Resolve the active provider from explicit args, env, and `.env`."""
        values = _collect_config_values()
        provider = (values.get("AI_PROVIDER") or "").lower().strip()

        def value(name: str, fallback: str | None = None) -> str | None:
            return values.get(name) or fallback

        def selected_model(name: str, fallback: str) -> str:
            return cast(str, model) if model else cast(str, value(name, fallback))

        def with_fallback_order(
            resolved_provider: str,
            resolved_key: str | None,
            resolved_base: str,
            resolved_model: str,
        ) -> AIProviderConfig:
            return cls(
                provider=resolved_provider,
                api_key=resolved_key,
                api_base=resolved_base,
                model=resolved_model,
                fallback_order=resolve_fallback_order(resolved_provider, values),
                values=values,
            )

        if provider and provider not in KNOWN_PROVIDERS:
            return with_fallback_order(
                provider,
                api_key or value("AI_API_KEY"),
                cast(str, api_base) if api_base else value("AI_BASE_URL", "") or "",
                selected_model("AI_MODEL", PROVIDER_DEFAULT_MODELS["custom"]),
            )

        if provider == "ollama" or (not provider and value("OLLAMA_BASE_URL")):
            return with_fallback_order(
                "ollama",
                api_key or value("OLLAMA_API_KEY") or "ollama",
                cast(str, api_base) if api_base else value("OLLAMA_BASE_URL", "http://localhost:11434/v1") or "",
                selected_model("OLLAMA_MODEL", PROVIDER_DEFAULT_MODELS["ollama"]),
            )

        has_openai_only = (
            not provider and not api_key and bool(value("OPENAI_API_KEY")) and not value("DEEPSEEK_API_KEY")
        )
        if provider == "openai" or has_openai_only:
            return with_fallback_order(
                "openai",
                api_key or value("OPENAI_API_KEY"),
                cast(str, api_base) if api_base else value("OPENAI_BASE_URL", "https://api.openai.com/v1") or "",
                selected_model("OPENAI_MODEL", PROVIDER_DEFAULT_MODELS["openai"]),
            )

        if provider == "custom":
            return with_fallback_order(
                "custom",
                api_key or value("AI_API_KEY"),
                cast(str, api_base) if api_base else value("AI_BASE_URL", "") or "",
                selected_model("AI_MODEL", PROVIDER_DEFAULT_MODELS["custom"]),
            )

        if not provider and not api_key and not value("DEEPSEEK_API_KEY") and not value("OPENAI_API_KEY"):
            return with_fallback_order(
                "ollama",
                value("OLLAMA_API_KEY") or "ollama",
                cast(str, api_base) if api_base else value("OLLAMA_BASE_URL", "http://localhost:11434/v1") or "",
                selected_model("OLLAMA_MODEL", PROVIDER_DEFAULT_MODELS["ollama"]),
            )

        return with_fallback_order(
            "deepseek",
            api_key or value("DEEPSEEK_API_KEY") or value("OPENAI_API_KEY"),
            cast(str, api_base) if api_base else value("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1") or "",
            selected_model("DEEPSEEK_MODEL", PROVIDER_DEFAULT_MODELS["deepseek"]),
        )

    def get(self, env_name: str, fallback: str | None = None) -> str | None:
        """Return a resolved env/.env value for provider construction."""
        return self.values.get(env_name) or fallback

    def as_tuple(self) -> tuple[str, str | None, str, str]:
        """Return the legacy tuple used by older AIAnalyzer tests."""
        return self.provider, self.api_key, self.api_base, self.model


def resolve_fallback_order(
    preferred_provider: str,
    values: Mapping[str, str] | None = None,
) -> list[str]:
    """Resolve provider fallback order from env/.env or local-first defaults."""
    config_values = values if values is not None else _collect_config_values()
    raw_order = config_values.get("AI_PROVIDER_FALLBACK_ORDER", "")
    if raw_order.strip():
        names = [name.strip().lower() for name in raw_order.split(",") if name.strip()]
    else:
        names = ["ollama", "deepseek", "openai", "custom"]

    ordered: list[str] = []
    for name in [preferred_provider, *names]:
        if name and name not in ordered:
            ordered.append(name)
    return ordered
