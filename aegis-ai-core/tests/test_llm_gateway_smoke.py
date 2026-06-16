from __future__ import annotations

import os
from dataclasses import dataclass

import pytest

from src.ai import (
    AIProviderConfig,
    LLMGateway,
    LLMProviderRateLimitError,
    LLMRequest,
    LLMResponse,
    run_llm_gateway_smoke,
)


@dataclass
class FakeProvider:
    name: str
    content: str = "{}"
    configured: bool = True
    raises: Exception | None = None
    calls: int = 0

    @property
    def default_model(self) -> str:
        return f"{self.name}-model"

    @property
    def supports_streaming(self) -> bool:
        return False

    def is_configured(self) -> bool:
        return self.configured

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return LLMResponse(
            content=self.content,
            provider=self.name,
            model=request.model or self.default_model,
        )


def test_smoke_result_reports_successful_fallback() -> None:
    primary = FakeProvider("primary", raises=LLMProviderRateLimitError("too many requests"))
    fallback = FakeProvider("fallback", content='{"ok": true}')
    config = AIProviderConfig(
        provider="primary",
        model="smoke-model",
        fallback_order=["primary", "fallback"],
    )

    result = run_llm_gateway_smoke(
        config=config,
        gateway=LLMGateway([primary, fallback], fallback_order=config.fallback_order),
    )

    assert result.ok is True
    assert result.preferred_provider == "primary"
    assert result.fallback_order == ["primary", "fallback"]
    assert result.provider == "fallback"
    assert result.model == "smoke-model"
    assert primary.calls == 1
    assert fallback.calls == 1


def test_smoke_result_reports_structured_failure() -> None:
    primary = FakeProvider("primary", configured=False)
    fallback = FakeProvider("fallback", configured=False)
    config = AIProviderConfig(
        provider="primary",
        fallback_order=["primary", "fallback"],
    )

    result = run_llm_gateway_smoke(
        config=config,
        gateway=LLMGateway([primary, fallback], fallback_order=config.fallback_order),
    )

    assert result.ok is False
    assert result.error_code == "all_providers_failed"
    assert result.error_message is not None
    assert "primary(not_configured)" in result.error_message
    assert primary.calls == 0
    assert fallback.calls == 0


@pytest.mark.integration
def test_configured_llm_gateway_smoke() -> None:
    if os.getenv("AEGIS_RUN_LLM_SMOKE") != "1":
        pytest.skip("Set AEGIS_RUN_LLM_SMOKE=1 to call the configured LLM provider.")

    result = run_llm_gateway_smoke()

    assert result.ok, result.error_message
