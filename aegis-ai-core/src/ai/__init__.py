"""AI provider gateway primitives."""

from .builtin_providers import build_default_gateway
from .llm_gateway import (
    AllProvidersFailedError,
    LLMGateway,
    LLMProvider,
    LLMProviderAuthenticationError,
    LLMProviderConfigurationError,
    LLMProviderError,
    LLMProviderRateLimitError,
    LLMProviderServerError,
    LLMProviderTimeoutError,
    LLMRequest,
    LLMResponse,
    OpenAICompatibleProvider,
)
from .provider_config import AIProviderConfig, resolve_fallback_order
from .smoke import DEFAULT_SMOKE_PROMPT, LLMGatewaySmokeResult, run_llm_gateway_smoke

__all__ = [
    "AIProviderConfig",
    "AllProvidersFailedError",
    "DEFAULT_SMOKE_PROMPT",
    "LLMGateway",
    "LLMGatewaySmokeResult",
    "LLMProvider",
    "LLMProviderAuthenticationError",
    "LLMProviderConfigurationError",
    "LLMProviderError",
    "LLMProviderRateLimitError",
    "LLMRequest",
    "LLMResponse",
    "LLMProviderServerError",
    "LLMProviderTimeoutError",
    "OpenAICompatibleProvider",
    "build_default_gateway",
    "resolve_fallback_order",
    "run_llm_gateway_smoke",
]
