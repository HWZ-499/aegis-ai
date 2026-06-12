from __future__ import annotations

from dataclasses import dataclass

from src.ai import LLMGateway, LLMProviderError, LLMRequest, LLMResponse


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


def test_gateway_falls_back_when_preferred_provider_fails() -> None:
    primary = FakeProvider("primary", raises=LLMProviderError("rate limited"))
    fallback = FakeProvider("fallback", content='{"ok": true}')
    gateway = LLMGateway([primary, fallback], fallback_order=["primary", "fallback"])

    response = gateway.generate(
        LLMRequest(messages=[{"role": "user", "content": "fix this"}]),
        preferred_provider="primary",
    )

    assert response.provider == "fallback"
    assert response.content == '{"ok": true}'
    assert primary.calls == 1
    assert fallback.calls == 1


def test_gateway_skips_unconfigured_provider() -> None:
    primary = FakeProvider("primary", configured=False)
    fallback = FakeProvider("fallback", content='{"ok": true}')
    gateway = LLMGateway([primary, fallback], fallback_order=["primary", "fallback"])

    response = gateway.generate(LLMRequest(messages=[]), preferred_provider="primary")

    assert response.provider == "fallback"
    assert primary.calls == 0
    assert fallback.calls == 1
