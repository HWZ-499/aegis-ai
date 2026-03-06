"""
rule_schema.py

YAML 规则 DSL 的模式定义（Pydantic 模型）。

该模块只负责描述规则结构，不包含任何匹配逻辑。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class MetaVarConstraint(BaseModel):
    """对单个元变量的约束配置。

    Attributes:
        regex: 需要满足的正则表达式（可选）。
        not_regex: 不允许匹配的正则表达式（可选）。
    """

    regex: Optional[str] = None
    not_regex: Optional[str] = Field(default=None, alias="not_regex")


class WhereClause(BaseModel):
    """规则的附加过滤条件。

    当前 PoC 仅支持基于文件路径的过滤。

    Attributes:
        file_regex: 文件路径需要匹配的正则表达式。
        file_not_regex: 文件路径不允许匹配的正则表达式。
    """

    file_regex: Optional[str] = None
    file_not_regex: Optional[str] = None

    def matches(self, file_path: Path) -> bool:
        """判断给定文件路径是否满足过滤条件。

        Args:
            file_path: 源文件路径。

        Returns:
            True 表示允许该规则在此文件上生效。
        """
        text = str(file_path)
        if self.file_regex is not None and not re.search(self.file_regex, text):
            return False
        if self.file_not_regex is not None and re.search(self.file_not_regex, text):
            return False
        return True


class DslPattern(BaseModel):
    """单条模式定义。

    Attributes:
        pattern: 含有 `$VAR` 风格占位符的源码片段。
        metavariables: 针对各元变量的约束。
        where: 可选的附加过滤条件。
    """

    pattern: str
    metavariables: Dict[str, MetaVarConstraint] = Field(
        default_factory=dict,
    )
    where: Optional[WhereClause] = None


class DslRule(BaseModel):
    """完整的 DSL 规则定义。

    Attributes:
        id: 规则唯一标识，建议使用 `language.category.name` 命名空间。
        language: 目标语言（python/javascript/php/java/go）。
        severity: 严重级别（INFO/LOW/MEDIUM/HIGH/CRITICAL）。
        message: 用户可见描述，用于 Diagnostic.message / 详情。
        vuln_type: Finding 中的 type 字段，例如 HARDCODED_CREDENTIALS。
        patterns: 多个 DslPattern，任一匹配即视为触发。
    """

    id: str
    language: str
    severity: str
    message: str
    vuln_type: str
    patterns: List[DslPattern]

    @field_validator("language")
    @classmethod
    def _normalize_language(cls, value: str) -> str:
        """标准化语言标识为小写。

        Args:
            value: 原始语言标识。

        Returns:
            归一化后的语言标识。
        """
        return value.lower()

    @field_validator("severity")
    @classmethod
    def _normalize_severity(cls, value: str) -> str:
        """标准化严重级别为大写。

        Args:
            value: 原始严重级别。

        Returns:
            归一化后的严重级别。
        """
        return value.upper()


__all__ = ["MetaVarConstraint", "WhereClause", "DslPattern", "DslRule"]

