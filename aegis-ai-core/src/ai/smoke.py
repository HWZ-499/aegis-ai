"""Smoke-test helpers for configured LLM gateways."""

from __future__ import annotations

from dataclasses import dataclass

from .builtin_providers import build_default_gateway
from .llm_gateway import AllProvidersFailedError, LLMGateway, LLMProviderError, LLMRequest
from .provider_config import AIProviderConfig

DEFAULT_SMOKE_PROMPT = (
    "Return only this JSON object with no markdown: "
    '{"is_false_positive": false, "confidence": 0.99, "risk_level": "Low", '
    '"explanation": "smoke", "fixed_code": "pass"}'
)


@dataclass(frozen=True)
class LLMGatewaySmokeResult:
    """Structured result for a single gateway smoke run."""

    ok: bool
    preferred_provider: str
    fallback_order: list[str]
    provider: str | None = None
    model: str | None = None
    content_preview: str | None = None
    error_code: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return {
            "ok": self.ok,
            "preferred_provider": self.preferred_provider,
            "fallback_order": self.fallback_order,
            "provider": self.provider,
            "model": self.model,
            "content_preview": self.content_preview,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


def run_llm_gateway_smoke(
    *,
    config: AIProviderConfig | None = None,
    gateway: LLMGateway | None = None,
    prompt: str = DEFAULT_SMOKE_PROMPT,
    timeout: float = 20.0,
) -> LLMGatewaySmokeResult:
    """Call the configured gateway once and report whether fallback works."""
    resolved_config = config or AIProviderConfig.from_sources()
    resolved_gateway = gateway or build_default_gateway(resolved_config)
    request = LLMRequest(
        messages=[
            {
                "role": "system",
                "content": "You are a health check endpoint. Return exactly what the user requests.",
            },
            {"role": "user", "content": prompt},
        ],
        model=resolved_config.model,
        temperature=0,
        max_tokens=200,
        timeout=timeout,
    )

    try:
        response = resolved_gateway.generate(
            request,
            preferred_provider=resolved_config.provider,
            fallback_order=resolved_config.fallback_order,
        )
    except AllProvidersFailedError as exc:
        return LLMGatewaySmokeResult(
            ok=False,
            preferred_provider=resolved_config.provider,
            fallback_order=resolved_config.fallback_order,
            error_code=exc.error_code,
            error_message=str(exc),
        )
    except LLMProviderError as exc:
        return LLMGatewaySmokeResult(
            ok=False,
            preferred_provider=resolved_config.provider,
            fallback_order=resolved_config.fallback_order,
            error_code=exc.error_code,
            error_message=str(exc),
        )

    return LLMGatewaySmokeResult(
        ok=True,
        preferred_provider=resolved_config.provider,
        fallback_order=resolved_config.fallback_order,
        provider=response.provider,
        model=response.model,
        content_preview=response.content[:200],
    )
