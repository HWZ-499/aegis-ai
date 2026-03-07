"""
dsl_engine.py

基于 YAML 定义的规则 DSL 的最小匹配引擎。

设计目标（PoC 阶段）：
- 使用行级正则 + 元变量约束实现轻量模式匹配；
- 不依赖 Tree-sitter，方便在任意语言规则上快速试验；
- 与现有 AST/TaintGraph 规则并存，而非替代。
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .rule_schema import DslPattern, DslRule


def load_rules_from_directory(root: Path) -> list[DslRule]:
    """从指定目录递归加载所有 YAML 规则文件。

    Args:
        root: 规则目录根路径。

    Returns:
        解析成功的 DslRule 列表。
    """
    rules: list[DslRule] = []
    if not root.exists():
        return rules

    for path in sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        try:
            rule = DslRule.model_validate(data)
        except Exception:
            continue
        rules.append(rule)
    return rules


def _build_regex_from_pattern(pattern: str) -> re.Pattern:
    """将包含 $VAR 占位符的模式字符串转换为正则表达式。

    规则（PoC 简化版）：
    - `$NAME` 被转换为命名捕获组 `(?P<NAME>...)`；
    - 若 `$NAME` 被成对引号包裹（`\"$NAME\"`），捕获组限制为 `[^\"]+`；
    - 普通情况下捕获组使用 `\\S+`；
    - 普通文本通过 `re.escape` 转义，并将空格转换为 `\\s*` 以容忍微小格式差异。

    Args:
        pattern: 包含 `$VAR` 占位符的原始模式字符串。

    Returns:
        编译后的正则表达式对象。
    """
    token_re = re.compile(r"\$(\w+)")
    regex_parts: list[str] = []
    last_index = 0

    for match in token_re.finditer(pattern):
        start = match.start()
        end = match.end()
        name = match.group(1)

        literal = pattern[last_index:start]
        if literal:
            escaped = re.escape(literal)
            escaped = escaped.replace(r"\ ", r"\s*")
            regex_parts.append(escaped)

        prev_char = pattern[start - 1] if start > 0 else ""
        next_char = pattern[end] if end < len(pattern) else ""
        if prev_char == '"' and next_char == '"':
            group_pattern = rf'(?P<{name}>[^"]+)'
        else:
            group_pattern = rf"(?P<{name}>\S+)"
        regex_parts.append(group_pattern)

        last_index = end

    trailing = pattern[last_index:]
    if trailing:
        escaped = re.escape(trailing)
        escaped = escaped.replace(r"\ ", r"\s*")
        regex_parts.append(escaped)

    full = "".join(regex_parts)
    try:
        compiled = re.compile(full)
    except re.error:
        compiled = re.compile(r"(?!x)x")
    return compiled


def match_source(rule: DslRule, source: str, file_path: Path) -> list[dict]:
    """对源码执行 DSL 规则匹配，返回 Finding 列表。

    Args:
        rule: DslRule 实例。
        source: 源代码字符串。
        file_path: 源文件路径。

    Returns:
        Finding 字典列表（尚未包含 file/language 字段）。
    """
    findings: list[dict] = []
    if not source:
        return findings

    lines = source.split("\n")
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")
        for pattern in rule.patterns:
            regex = _build_regex_from_pattern(pattern.pattern)
            where = pattern.where
            if where is not None and not where.matches(file_path):
                continue

            for match in regex.finditer(line):
                if not _metavars_satisfied(pattern, match):
                    continue
                findings.append(
                    {
                        "type": rule.vuln_type,
                        "rule_id": rule.id,
                        "severity": rule.severity,
                        "line": idx,
                        "details": rule.message,
                    },
                )
    return findings


def _metavars_satisfied(pattern: DslPattern, match: re.Match) -> bool:
    """检查元变量是否满足约束。

    Args:
        pattern: DslPattern 实例。
        match: 正则匹配结果。

    Returns:
        True 表示所有元变量均满足约束。
    """
    for name, constraint in pattern.metavariables.items():
        try:
            value = match.group(name)
        except IndexError:
            return False
        if value is None:
            return False
        if constraint.regex is not None and not re.search(constraint.regex, value):
            return False
        if constraint.not_regex is not None and re.search(constraint.not_regex, value):
            return False
    return True


__all__ = ["load_rules_from_directory", "match_source"]
