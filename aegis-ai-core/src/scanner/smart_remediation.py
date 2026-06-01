"""
smart_remediation.py - 智能修复建议引擎

从静态模板 + 当前代码上下文生成精准修复建议，不调用 AI API，延迟 < 5ms。
- 从 source_code 提取漏洞行周围的真实变量名、import 信息
- 用提取到的变量名替换模板中的占位符（如 userId -> req.body.username）
- 根据 import 推断框架，选择 framework_suggested_code
- 保持与原代码一致的缩进风格（可选）
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, cast

from .rag_enhancer import BUILTIN_REMEDIATION


@dataclass
class SmartRemediation:
    """智能修复建议结果。"""

    message: str
    suggested_code: str
    framework: str | None = None
    replacements: dict[str, str] | None = None


# 模板中常见占位符 → 替换时使用的键（与下面提取逻辑对应）
_PLACEHOLDERS = [
    "userId",
    "user_id",
    "uid",
    "id",
    "username",
    "filename",
    "path",
    "file_path",
    "cmd",
    "command",
    "query",
    "sql",
    "input",
    "data",
    "var",
]


def _add_candidate(candidates: list[str], value: str) -> None:
    candidate = value.strip()
    if candidate and candidate not in candidates:
        candidates.append(candidate)


def _string_literal_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    quote: str | None = None
    start = 0
    escaped = False

    for index, char in enumerate(text):
        if quote is None:
            if char in {"'", '"', "`"}:
                quote = char
                start = index
            continue

        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == quote:
            spans.append((start, index + 1))
            quote = None

    if quote is not None:
        spans.append((start, len(text)))
    return spans


def _overlaps_spans(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < span_end and end > span_start for span_start, span_end in spans)


def _previous_nonspace(text: str, index: int) -> str:
    cursor = index - 1
    while cursor >= 0 and text[cursor].isspace():
        cursor -= 1
    return text[cursor] if cursor >= 0 else ""


def _next_nonspace(text: str, index: int) -> str:
    cursor = index
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    return text[cursor] if cursor < len(text) else ""


def _extract_line_context(source_code: str, line_one_based: int) -> str:
    """提取漏洞行及其前后各 2 行的上下文。"""
    lines = source_code.splitlines()
    if not lines:
        return ""
    idx = max(0, min(line_one_based - 1, len(lines) - 1))
    start = max(0, idx - 2)
    end = min(len(lines), idx + 3)
    return "\n".join(lines[start:end])


def _extract_variable_candidates(context: str) -> list[str]:
    """
    从上下文中提取疑似「用户输入」变量/表达式，用于替换模板占位符。

    匹配：req.body.xxx, req.query.xxx, request.args.get('x'), request.json,
          $var, user_id, userId, filename 等。
    """
    candidates: list[str] = []
    string_spans = _string_literal_spans(context)
    source_spans: list[tuple[int, int]] = []

    # req.body.xxx / req.query.xxx / request.args / request.json
    for m in re.finditer(
        r"\b(?:req|request)\.(?:body|query|params)"
        r"(?:\.\w+|\[\s*['\"][^'\"]+['\"]\s*\])*|"
        r"request\.args\.get\s*\(\s*['\"]\w+['\"]\s*\)|"
        r"request\.(?:json|form|data)\b",
        context,
        re.IGNORECASE,
    ):
        if _overlaps_spans(m.start(), m.end(), string_spans):
            continue
        _add_candidate(candidates, m.group(0))
        source_spans.append((m.start(), m.end()))

    # $var (PHP)
    for m in re.finditer(r"\$(\w+)", context):
        if _overlaps_spans(m.start(), m.end(), string_spans):
            continue
        _add_candidate(candidates, "$" + m.group(1))

    # 常见标识符（蛇形/驼峰）
    for m in re.finditer(
        r"\b(user_?id|user_?name|filename|file_?path|path|cmd|command|query|sql|input|data|uid|id)\b",
        context,
        re.IGNORECASE,
    ):
        if _overlaps_spans(m.start(), m.end(), string_spans + source_spans):
            continue
        _add_candidate(candidates, m.group(0))
    return candidates[:5]


def _infer_framework_from_source(source_code: str, file_path: str) -> str | None:
    """从源码头部和文件路径推断框架。"""
    header = source_code.split("\n")[:60]
    header_text = "\n".join(header).lower()
    path_lower = file_path.lower()

    priority = [
        "mysql2",
        "mysql",
        "sequelize",
        "knex",
        "typeorm",
        "prisma",
        "pymysql",
        "psycopg2",
        "sqlalchemy",
        "django",
        "spring",
        "hibernate",
        "mybatis",
        "jdbc",
        "mongoose",
        "mongodb",
        "pymongo",
        "motor",
        "gorm",
        "sqlx",
        "gin",
        "echo",
        "flask",
        "express",
        "fastapi",
    ]
    for fw in priority:
        if fw in header_text or fw in path_lower:
            return fw
    return None


def _apply_replacements(text: str, replacements: dict[str, str]) -> str:
    """将模板中的占位符替换为真实变量名（大小写不敏感匹配常见占位符）。"""
    if not replacements:
        return text

    lookup = {placeholder.lower(): value for placeholder, value in replacements.items() if placeholder}
    placeholders = sorted((re.escape(key) for key in lookup), key=len, reverse=True)
    pattern = re.compile(r"\b(" + "|".join(placeholders) + r")\b", re.IGNORECASE)
    string_spans = _string_literal_spans(text)

    def replace(match: re.Match[str]) -> str:
        if _overlaps_spans(match.start(), match.end(), string_spans):
            return match.group(0)

        previous_char = _previous_nonspace(text, match.start())
        next_char = _next_nonspace(text, match.end())
        if previous_char in {".", "$"} or next_char in {".", ":"}:
            return match.group(0)

        return lookup.get(match.group(0).lower(), match.group(0))

    return pattern.sub(replace, text)


def generate_smart_remediation(
    finding: dict[str, Any],
    source_code: str,
    file_path: str,
) -> SmartRemediation:
    """
    从静态模板 + 当前代码上下文生成智能修复建议。

    不调用 AI API，延迟 < 5ms。用提取到的变量名替换模板占位符，
    并根据 import 推断框架选择 framework_suggested_code。

    Args:
        finding: 单条 finding（含 type/rule_id, line, details 等）
        source_code: 当前文件完整源码
        file_path: 当前文件路径（用于框架推断）

    Returns:
        SmartRemediation，含 message、suggested_code、framework、replacements
    """
    vuln_type = finding.get("type") or (finding.get("rule_id") or "").split("_")[0]
    rule_id = finding.get("rule_id") or vuln_type
    line_no = int(finding.get("line") or finding.get("start_line") or 1)

    builtin = cast(
        dict[str, Any],
        BUILTIN_REMEDIATION.get(vuln_type) or BUILTIN_REMEDIATION.get(rule_id) or {},
    )
    description = str(builtin.get("description", "") or "")
    raw_remediation_list = builtin.get("remediation") or []
    remediation_list = [str(item) for item in raw_remediation_list] if isinstance(raw_remediation_list, list) else []
    first_tip = remediation_list[0] if remediation_list else description

    context = _extract_line_context(source_code, line_no)
    candidates = _extract_variable_candidates(context)
    primary = candidates[0] if candidates else "user_input"
    replacements: dict[str, str] = {ph: primary for ph in _PLACEHOLDERS}

    framework = _infer_framework_from_source(source_code, file_path)
    raw_framework_code_map = builtin.get("framework_suggested_code") or {}
    framework_code_map = raw_framework_code_map if isinstance(raw_framework_code_map, dict) else {}
    suggested_code = str(builtin.get("suggested_code") or "")

    if framework and framework in framework_code_map:
        suggested_code = str(framework_code_map[framework])
    suggested_code = _apply_replacements(suggested_code, replacements)

    message = first_tip if first_tip else f"请根据 {vuln_type} 修复指南处理。"
    if description and description != first_tip:
        message = description.rstrip("。") + "。" + message

    return SmartRemediation(
        message=message,
        suggested_code=suggested_code.strip(),
        framework=framework,
        replacements=replacements,
    )


__all__ = ["SmartRemediation", "generate_smart_remediation"]
