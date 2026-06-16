"""Run a configured LLM gateway smoke test."""

from __future__ import annotations

import argparse
import json
from dataclasses import replace

from src.ai import DEFAULT_SMOKE_PROMPT, AIProviderConfig, run_llm_gateway_smoke


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one configured LLM gateway smoke request.")
    parser.add_argument("--provider", default="", help="Override AI_PROVIDER for this smoke run.")
    parser.add_argument(
        "--fallback-order",
        default="",
        help="Comma-separated provider fallback order. Defaults to AI_PROVIDER_FALLBACK_ORDER or local-first defaults.",
    )
    parser.add_argument("--prompt", default="", help="Optional prompt override.")
    parser.add_argument("--timeout", type=float, default=20.0, help="Provider request timeout in seconds.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = AIProviderConfig.from_sources()
    if args.provider:
        config = replace(config, provider=args.provider.strip().lower())
    if args.fallback_order:
        order = [name.strip().lower() for name in args.fallback_order.split(",") if name.strip()]
        config = replace(config, fallback_order=order)

    result = run_llm_gateway_smoke(
        config=config,
        prompt=args.prompt or DEFAULT_SMOKE_PROMPT,
        timeout=args.timeout,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0 if result.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
