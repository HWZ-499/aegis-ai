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
from pathlib import Path
from typing import Any, Dict, List, Optional

from .rag_enhancer import BUILTIN_REMEDIATION


@dataclass
class SmartRemediation:
    """智能修复建议结果。"""

    message: str
    suggested_code: str
    framework: Optional[str] = None
    replacements: Optional[Dict[str, str]] = None


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


def _extract_line_context(source_code: str, line_one_based: int) -> str:
    """提取漏洞行及其前后各 2 行的上下文。"""
    lines = source_code.splitlines()
    if not lines:
        return ""
    idx = max(0, min(line_one_based - 1, len(lines) - 1))
    start = max(0, idx - 2)
    end = min(len(lines), idx + 3)
    return "\n".join(lines[start:end])


def _extract_variable_candidates(context: str) -> List[str]:
    """
    从上下文中提取疑似「用户输入」变量/表达式，用于替换模板占位符。

    匹配：req.body.xxx, req.query.xxx, request.args.get('x'), request.json,
          $var, user_id, userId, filename 等。
    """
    candidates: List[str] = []
    # req.body.xxx / req.query.xxx / request.args / request.json
    for m in re.finditer(
        r"\b(?:req|request)\.(?:body|query|params)\.(\w+)|"
        r"\b(?:req|request)\.(?:body|query|params)\b|"
        r"request\.args\.get\s*\(\s*['\"](\w+)['\"]\s*\)|"
        r"request\.(?:json|form|data)\b",
        context,
        re.IGNORECASE,
    ):
        group = (m.group(1) or m.group(2) or "").strip()
        if group and group not in candidates:
            candidates.append(group)
        if not group and m.group(0) not in [c for c in candidates]:
            candidates.append(m.group(0).strip())
    # $var (PHP)
    for m in re.finditer(r"\$(\w+)", context):
        if m.group(1) not in candidates:
            candidates.append("$" + m.group(1))
    # 常见标识符（蛇形/驼峰）
    for m in re.finditer(
        r"\b(user_?id|user_?name|filename|file_?path|path|cmd|command|query|sql|input|data|uid|id)\b",
        context,
        re.IGNORECASE,
    ):
        if m.group(0) not in candidates:
            candidates.append(m.group(0))
    return candidates[: 5]


def _infer_framework_from_source(source_code: str, file_path: str) -> Optional[str]:
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


def _apply_replacements(text: str, replacements: Dict[str, str]) -> str:
    """将模板中的占位符替换为真实变量名（大小写不敏感匹配常见占位符）。"""
    result = text
    for placeholder, value in replacements.items():
        # 单词边界替换，避免误替换
        pattern = re.compile(
            r"\b" + re.escape(placeholder) + r"\b",
            re.IGNORECASE,
        )
        result = pattern.sub(value, result)
    return result


def generate_smart_remediation(
    finding: Dict[str, Any],
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

    builtin = BUILTIN_REMEDIATION.get(vuln_type) or BUILTIN_REMEDIATION.get(rule_id) or {}
    description = builtin.get("description", "")
    remediation_list = builtin.get("remediation") or []
    first_tip = remediation_list[0] if remediation_list else description

    context = _extract_line_context(source_code, line_no)
    candidates = _extract_variable_candidates(context)
    primary = candidates[0] if candidates else "user_input"
    replacements: Dict[str, str] = {ph: primary for ph in _PLACEHOLDERS}
    for i, c in enumerate(candidates):
        if i < len(_PLACEHOLDERS):
            replacements[_PLACEHOLDERS[i]] = c

    framework = _infer_framework_from_source(source_code, file_path)
    framework_code_map = builtin.get("framework_suggested_code") or {}
    suggested_code = builtin.get("suggested_code") or ""

    if framework and framework in framework_code_map:
        suggested_code = framework_code_map[framework]
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
