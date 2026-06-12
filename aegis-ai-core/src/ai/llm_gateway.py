"""LLM provider protocol and fallback gateway."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


class LLMProviderError(RuntimeError):
    """Raised when a provider cannot complete a generation request."""


class AllProvidersFailedError(LLMProviderError):
    """Raised when every configured provider fails or is unavailable."""


@dataclass(frozen=True)
class LLMRequest:
    """Provider-neutral chat completion request."""

    messages: list[dict[str, str]]
    model: str | None = None
    temperature: float = 0.3
    max_tokens: int = 2000
    timeout: float = 30.0


@dataclass(frozen=True)
class LLMResponse:
    """Provider-neutral chat completion response."""

    content: str
    provider: str
    model: str


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol implemented by all LLM providers."""

    @property
    def name(self) -> str:
        """Provider identifier used for routing."""
        ...

    @property
    def default_model(self) -> str:
        """Default model for requests that do not specify one."""
        ...

    @property
    def supports_streaming(self) -> bool:
        """Whether the provider supports streaming responses."""
        ...

    def is_configured(self) -> bool:
        """Return True when the provider has enough configuration to be called."""
        ...

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate a response for a chat request."""
        ...


@dataclass
class OpenAICompatibleProvider:
    """Provider adapter for OpenAI-compatible chat completion APIs."""

    name: str
    api_key: str | None
    base_url: str
    default_model: str
    requires_api_key: bool = True
    supports_streaming: bool = False

    def is_configured(self) -> bool:
        """Return True when base URL and required credentials are present."""
        if not self.base_url:
            return False
        if self.requires_api_key and not self.api_key:
            return False
        return True

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Call an OpenAI-compatible chat completion endpoint."""
        if not self.is_configured():
            raise LLMProviderError(f"Provider {self.name} is not configured")

        try:
            import openai
        except ImportError as exc:
            raise LLMProviderError(f"OpenAI-compatible dependency is unavailable: {exc}") from exc

        model = request.model or self.default_model
        try:
            client = openai.OpenAI(
                api_key=self.api_key or "ollama",
                base_url=self.base_url,
            )
            response = client.chat.completions.create(
                model=model,
                messages=request.messages,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
                timeout=request.timeout,
            )
        except Exception as exc:
            raise LLMProviderError(f"Provider {self.name} request failed: {type(exc).__name__}: {exc}") from exc

        content = response.choices[0].message.content or ""
        return LLMResponse(content=content, provider=self.name, model=model)


class LLMGateway:
    """Provider registry and fallback dispatcher."""

    def __init__(
        self,
        providers: list[LLMProvider] | None = None,
        fallback_order: list[str] | None = None,
    ) -> None:
        self._providers: dict[str, LLMProvider] = {}
        self._fallback_order: list[str] = []
        for provider in providers or []:
            self.register_provider(provider)
        if fallback_order is not None:
            self._fallback_order = [name for name in fallback_order if name in self._providers]

    @property
    def fallback_order(self) -> list[str]:
        """Configured fallback order."""
        return list(self._fallback_order)

    def register_provider(self, provider: LLMProvider) -> None:
        """Register or replace a provider implementation."""
        self._providers[provider.name] = provider
        if provider.name not in self._fallback_order:
            self._fallback_order.append(provider.name)

    def has_provider(self, name: str) -> bool:
        """Return whether a provider name is registered."""
        return name in self._providers

    def has_configured_provider(self, provider_names: list[str] | None = None) -> bool:
        """Return True if any provider in order can be called."""
        names = provider_names or self._fallback_order
        for name in names:
            provider = self._providers.get(name)
            if provider and provider.is_configured():
                return True
        return False

    def _ordered_provider_names(
        self,
        preferred_provider: str | None,
        fallback_order: list[str] | None,
    ) -> list[str]:
        names: list[str] = []
        for name in [preferred_provider, *(fallback_order or self._fallback_order)]:
            if not name or name in names:
                continue
            if name in self._providers:
                names.append(name)
        return names

    def generate(
        self,
        request: LLMRequest,
        *,
        preferred_provider: str | None = None,
        fallback_order: list[str] | None = None,
    ) -> LLMResponse:
        """Generate using the preferred provider, then fall back in order."""
        errors: list[str] = []
        for name in self._ordered_provider_names(preferred_provider, fallback_order):
            provider = self._providers[name]
            if not provider.is_configured():
                errors.append(f"{name}: not configured")
                continue
            try:
                return provider.generate(request)
            except Exception as exc:
                message = f"{name}: {exc}"
                errors.append(message)
                logger.warning("LLM provider failed, trying fallback if available: %s", message)

        detail = "; ".join(errors) if errors else "no providers registered"
        raise AllProvidersFailedError(f"All LLM providers failed: {detail}")
