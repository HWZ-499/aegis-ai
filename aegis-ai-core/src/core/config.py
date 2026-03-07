"""
config.py — 基于 pydantic-settings 的统一配置管理。

所有配置项通过环境变量或 .env 文件注入，带类型校验和默认值。
环境变量前缀为 ``AEGIS_``（如 ``AEGIS_DEEPSEEK_API_KEY``），
也兼容无前缀形式（如 ``DEEPSEEK_API_KEY``）。
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    from pydantic import BaseModel as BaseSettings  # type: ignore[assignment]

    class SettingsConfigDict:  # type: ignore[no-redef]
        """Fallback when pydantic-settings is not installed."""

        def __init__(self, **_: object) -> None:
            pass


def _resolve_env_file() -> str:
    """
    按优先级查找 .env 文件路径。

    Returns:
        找到的 .env 路径，或 ".env"（pydantic-settings 会忽略不存在的文件）。
    """
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[2] / ".env",
    ]
    for p in candidates:
        if p.is_file():
            return str(p)
    return ""


class AegisSettings(BaseSettings):
    """Aegis AI 全局配置。"""

    model_config = SettingsConfigDict(
        env_file=_resolve_env_file(),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── AI Provider ──────────────────────────────────────────────
    deepseek_api_key: str = Field(
        default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", ""),
        description="DeepSeek API Key",
    )
    deepseek_api_url: str = Field(
        default_factory=lambda: os.getenv(
            "DEEPSEEK_API_URL",
            "https://api.deepseek.com/chat/completions",
        ),
        description="DeepSeek API endpoint URL",
    )
    openai_api_key: str = Field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", ""),
        description="OpenAI API Key (backup provider)",
    )

    # ── Database ─────────────────────────────────────────────────
    db_path: Path = Field(
        default_factory=lambda: Path(os.getenv("AEGIS_DB_PATH", "./aegis_db")),
        description="ChromaDB persistent storage path",
    )

    # ── Cache & Rate Limiting ────────────────────────────────────
    cache_ttl_seconds: int = Field(default=300, description="DeepSeek response cache TTL")
    cache_max_items: int = Field(default=128, description="Max cached responses")
    rate_limit_chat_per_min: int = Field(default=30)
    rate_limit_audit_per_min: int = Field(default=10)

    # ── CORS ─────────────────────────────────────────────────────
    cors_allow_origins: list[str] = Field(
        default_factory=lambda: [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",") if o.strip()],
        description="Allowed CORS origins (comma-separated in env var)",
    )

    # ── Logging ──────────────────────────────────────────────────
    log_level: str = Field(default="INFO", description="Root log level")
    log_json: bool = Field(default=False, description="Use JSON-structured logging")

    # ── Debug ────────────────────────────────────────────────────
    debug: bool = Field(default=False, description="Debug mode (verbose errors)")

    @property
    def has_ai(self) -> bool:
        """是否配置了任意一个 AI provider。"""
        return bool(self.deepseek_api_key or self.openai_api_key)


@lru_cache(maxsize=1)
def get_settings() -> AegisSettings:
    """
    获取全局配置单例。

    Returns:
        AegisSettings 实例（进程内缓存，仅初始化一次）。
    """
    return AegisSettings()
