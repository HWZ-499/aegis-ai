"""
ai_analyzer.py - AI 分析模块

对扫描结果进行 AI 增强分析：
- 漏洞确认：使用 AI 评估漏洞的真实性
- 风险评估：结合上下文评估实际风险
- 修复代码生成：生成针对当前代码上下文的精准修复建议

设计原则：
- 可选依赖：不强制要求 AI API
- AI 漏斗策略：只对高风险发现调用 AI，降低成本
- 批量处理：支持批量分析以提高效率
- 按需触发：AI 调用仅在用户主动请求时发生，不自动批量触发
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from ..ai import AllProvidersFailedError, LLMGateway, LLMRequest, OpenAICompatibleProvider

logger = logging.getLogger(__name__)

# 框架关键词映射：import 关键词 -> 框架标签
_FRAMEWORK_IMPORT_MAP: dict[str, str] = {
    "mysql2": "mysql2",
    "mysql": "mysql",
    "pg": "pg (node-postgres)",
    "sqlite3": "sqlite3",
    "sequelize": "sequelize",
    "mongoose": "mongoose",
    "mongodb": "mongodb",
    "knex": "knex",
    "typeorm": "typeorm",
    "prisma": "prisma",
    "pymysql": "pymysql",
    "psycopg2": "psycopg2",
    "sqlalchemy": "sqlalchemy",
    "django.db": "django-orm",
    "flask_sqlalchemy": "flask-sqlalchemy",
    "peewee": "peewee",
    "express": "express",
    "fastapi": "fastapi",
    "flask": "flask",
    "django": "django",
    "aiohttp": "aiohttp",
}

_CPP_SAFE_TARGET_RE = re.compile(r"^[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*$")
_CPP_EXTENSIONS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")
_LOCAL_CPP_FIX_RULE_IDS = (
    "BUFFER_OVERFLOW",
    "ASSIGNMENT_IN_CONDITION",
    "NULL_DEREFERENCE",
    "LOCK_MISMATCH",
    "THREAD_LIFECYCLE_RISK",
)
_CPP_CIN_EXTRACTION_LINE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<stream>(?:std::)?cin)\s*>>\s*(?P<target>[A-Za-z_]\w*)"
    r"(?P<rest>(?:\s*>>\s*[^;]+)?)\s*;?\s*$"
)
_CPP_ASSIGNMENT_OPERATOR_RE = re.compile(r"(?<![=!<>+\-*/%&|^])=(?!=)")
_CPP_THREAD_CONTROL_STANDALONE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<api>TerminateThread|SuspendThread)\s*\((?P<args>.*)\)\s*;?\s*$",
    re.IGNORECASE,
)
_CPP_THREAD_CONTROL_IF_LINE_RE = re.compile(
    r"^(?P<indent>\s*)if\s*\((?P<condition>.*\b(?P<api>TerminateThread|SuspendThread)\s*\(.*)\)\s*$",
    re.IGNORECASE,
)
_CPP_NESTED_POINTER_RE = re.compile(r"\b(?P<base>[A-Za-z_]\w*)\s*->\s*(?P<field>[A-Za-z_]\w*)\s*->")
_CPP_CRITICAL_LEAVE_LINE_RE = re.compile(r"\bLeaveCriticalSection\s*\(\s*&(?P<name>[A-Za-z_]\w*)\s*\)")


@dataclass(frozen=True)
class _LocalFixReplacement:
    fixed_code: str
    fix_suggestion: str
    explanation: str
    confidence: float
    start_line: int
    end_line: int


def _normalize_vulnerability_type(value: Any) -> str:
    """Extract a canonical Aegis rule id from LSP/UI wrapper strings."""
    raw = str(value or "").strip()
    upper = raw.upper()
    for rule_id in _LOCAL_CPP_FIX_RULE_IDS:
        if re.search(rf"(?<![A-Z0-9_]){re.escape(rule_id)}(?![A-Z0-9_])", upper):
            return rule_id
    return raw


def _strip_markdown_code_fence(value: str) -> str:
    """Return code without a surrounding markdown fence, if the model added one."""
    text = value.strip()
    fence = re.fullmatch(r"```[A-Za-z0-9_+\-#]*\s*\n(?P<code>.*)\n```", text, re.DOTALL)
    if fence:
        return fence.group("code").strip()
    return text


def _first_nonempty_string(parsed: dict[str, Any], field_names: tuple[str, ...]) -> str | None:
    """Pick the first non-empty string from common AI response code fields."""
    for field_name in field_names:
        raw_value = parsed.get(field_name)
        if isinstance(raw_value, str):
            value = _strip_markdown_code_fence(raw_value)
            if value.strip():
                return value
    return None


def _coerce_line_number(value: Any, fallback: int | None) -> int | None:
    try:
        if value is None:
            return fallback
        line = int(value)
        return line if line > 0 else fallback
    except (TypeError, ValueError):
        return fallback


def _split_call_args(argument_text: str) -> list[str]:
    """Split a simple C/C++ call argument list while respecting strings and nesting."""
    args: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False

    for char in argument_text:
        if quote is not None:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue

        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
            current.append(char)
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            current.append(char)
            continue
        if char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(char)

    if current or argument_text.strip():
        args.append("".join(current).strip())
    return args


def _cpp_target_is_known_char_array(target: str, source_code: str) -> bool:
    """Conservatively prove that a C/C++ copy target is a visible fixed char array."""
    clean_target = target.strip()
    if not _CPP_SAFE_TARGET_RE.fullmatch(clean_target):
        return False

    if "->" in clean_target or "." in clean_target:
        field_name = re.split(r"->|\.", clean_target)[-1]
        struct_body_with_field = re.compile(
            r"\b(?:typedef\s+)?(?:struct|class)\b[^{;]*\{(?P<body>.*?)\}",
            re.DOTALL,
        )
        for match in struct_body_with_field.finditer(source_code):
            body = match.group("body")
            if re.search(rf"\bchar\s+{re.escape(field_name)}\s*\[[^\]]+\]", body):
                return True
        return False

    return bool(re.search(rf"\bchar\s+{re.escape(clean_target)}\s*\[[^\]]+\]", source_code))


def _build_cpp_buffer_overflow_replacement(
    finding: dict[str, Any],
    source_code: str | None,
    language: str | None,
) -> str | None:
    """Build a narrow local fallback for C/C++ strcpy into known fixed char arrays."""
    if not source_code:
        return None
    vuln_type = _normalize_vulnerability_type(finding.get("type", ""))
    file_path = str(finding.get("file") or finding.get("file_path") or "")
    lang = str(language or finding.get("language") or "").lower()
    if vuln_type != "BUFFER_OVERFLOW" or not (
        lang in {"c", "cpp", "c++"} or file_path.lower().endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"))
    ):
        return None

    line_number = _coerce_line_number(finding.get("line") or finding.get("start_line"), None)
    if line_number is None:
        return None
    lines = source_code.splitlines()
    if line_number < 1 or line_number > len(lines):
        return None

    raw_line = lines[line_number - 1]
    indent = raw_line[: len(raw_line) - len(raw_line.lstrip())]
    stripped = raw_line.strip()
    match = re.fullmatch(r"strcpy\s*\((?P<args>.*)\)\s*;?", stripped)
    if not match:
        return None

    args = _split_call_args(match.group("args"))
    if len(args) != 2:
        return None

    destination, source = args
    if not destination or not source or not _cpp_target_is_known_char_array(destination, source_code):
        return None

    return "\n".join(
        [
            f"{indent}strncpy({destination}, {source}, sizeof({destination}) - 1);",
            f"{indent}{destination}[sizeof({destination}) - 1] = '\\0';",
        ]
    )


def _is_cpp_context(finding: dict[str, Any], language: str | None) -> bool:
    file_path = str(finding.get("file") or finding.get("file_path") or "")
    lang = str(language or finding.get("language") or "").lower()
    return lang in {"c", "cpp", "c++"} or file_path.lower().endswith(_CPP_EXTENSIONS)


def _finding_source_line(finding: dict[str, Any], source_code: str | None) -> tuple[int, str] | None:
    if not source_code:
        return None
    line_number = _coerce_line_number(finding.get("line") or finding.get("start_line"), None)
    if line_number is None:
        return None
    lines = source_code.splitlines()
    if line_number < 1 or line_number > len(lines):
        return None
    return line_number, lines[line_number - 1]


def _build_cpp_cin_buffer_replacement(
    finding: dict[str, Any],
    source_code: str | None,
) -> _LocalFixReplacement | None:
    line_info = _finding_source_line(finding, source_code)
    if line_info is None or source_code is None:
        return None

    line_number, raw_line = line_info
    match = _CPP_CIN_EXTRACTION_LINE_RE.fullmatch(raw_line)
    if not match:
        return None

    target = match.group("target")
    if not _cpp_target_is_known_char_array(target, source_code):
        return None

    indent = match.group("indent")
    stream = match.group("stream")
    rest = re.sub(r"\s*>>\s*", " >> ", match.group("rest").strip()).strip()
    remaining_extractions = f" {rest}" if rest else ""
    fixed_code = "\n".join(
        [
            f"{indent}{stream}.width(sizeof({target}));",
            f"{indent}{stream} >> {target}{remaining_extractions};",
        ]
    )
    return _LocalFixReplacement(
        fixed_code=fixed_code,
        fix_suggestion="在读取固定 char 数组前设置输入宽度，限制最多写入目标数组容量。",
        explanation="C/C++ 流读取到 char 数组时，如果不限制宽度，超长输入会覆盖数组边界。",
        confidence=0.82,
        start_line=line_number,
        end_line=line_number,
    )


def _find_cpp_condition_span(line: str) -> tuple[int, int] | None:
    match = re.search(r"\b(?:if|while)\s*\(", line)
    if not match:
        return None

    open_index = line.find("(", match.start())
    if open_index < 0:
        return None

    depth = 1
    quote: str | None = None
    escaped = False
    for index in range(open_index + 1, len(line)):
        char = line[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth -= 1
            if depth == 0:
                return open_index + 1, index
    return None


def _build_cpp_assignment_condition_replacement(
    finding: dict[str, Any],
    source_code: str | None,
) -> _LocalFixReplacement | None:
    line_info = _finding_source_line(finding, source_code)
    if line_info is None:
        return None

    line_number, raw_line = line_info
    span = _find_cpp_condition_span(raw_line)
    if span is None:
        return None
    condition_start, condition_end = span
    condition = raw_line[condition_start:condition_end]
    assignment = _CPP_ASSIGNMENT_OPERATOR_RE.search(condition)
    if not assignment:
        return None

    operator_start = condition_start + assignment.start()
    operator_end = condition_start + assignment.end()
    fixed_code = f"{raw_line[:operator_start]} == {raw_line[operator_end:]}"
    return _LocalFixReplacement(
        fixed_code=fixed_code,
        fix_suggestion="将条件表达式中的单等号赋值改为相等比较，并人工确认原意不是循环取值赋值。",
        explanation="条件里使用 `=` 会先修改变量再按赋值结果判断，容易让状态或权限判断失效。",
        confidence=0.78,
        start_line=line_number,
        end_line=line_number,
    )


def _build_cpp_null_deref_replacement(
    finding: dict[str, Any],
    source_code: str | None,
) -> _LocalFixReplacement | None:
    line_info = _finding_source_line(finding, source_code)
    if line_info is None:
        return None

    line_number, raw_line = line_info
    match = _CPP_NESTED_POINTER_RE.search(raw_line)
    if not match:
        return None

    indent = raw_line[: len(raw_line) - len(raw_line.lstrip())]
    stripped = raw_line.strip()
    base = match.group("base")
    field = match.group("field")
    fixed_code = "\n".join(
        [
            f"{indent}if ({base}->{field} != NULL) {{",
            f"{indent}    {stripped}",
            f"{indent}}}",
        ]
    )
    return _LocalFixReplacement(
        fixed_code=fixed_code,
        fix_suggestion=f"在解引用 `{base}->{field}` 前补充内层指针判空。",
        explanation=f"当前代码只证明 `{base}` 非空，不能证明 `{base}->{field}` 一定存在。",
        confidence=0.68,
        start_line=line_number,
        end_line=line_number,
    )


def _expected_critical_section_from_details(details: str) -> str | None:
    for pattern in (
        r"进入\s*`(?P<name>[A-Za-z_]\w*)`",
        r"entered\s+`(?P<name>[A-Za-z_]\w*)`",
        r"entered\s+(?P<name>[A-Za-z_]\w*)",
    ):
        match = re.search(pattern, details, re.IGNORECASE)
        if match:
            return match.group("name")
    return None


def _build_cpp_lock_mismatch_replacement(
    finding: dict[str, Any],
    source_code: str | None,
) -> _LocalFixReplacement | None:
    line_info = _finding_source_line(finding, source_code)
    if line_info is None:
        return None

    details = str(finding.get("details") or finding.get("content") or "")
    expected_name = _expected_critical_section_from_details(details)
    if not expected_name:
        return None

    line_number, raw_line = line_info
    leave_match = _CPP_CRITICAL_LEAVE_LINE_RE.search(raw_line)
    if not leave_match or leave_match.group("name") == expected_name:
        return None

    fixed_code = _CPP_CRITICAL_LEAVE_LINE_RE.sub(
        f"LeaveCriticalSection(&{expected_name})",
        raw_line,
        count=1,
    )
    return _LocalFixReplacement(
        fixed_code=fixed_code,
        fix_suggestion=f"释放与最近一次进入一致的临界区 `{expected_name}`。",
        explanation="EnterCriticalSection 和 LeaveCriticalSection 对象不一致会让真正持有的锁无法释放。",
        confidence=0.84,
        start_line=line_number,
        end_line=line_number,
    )


def _build_cpp_thread_lifecycle_replacement(
    finding: dict[str, Any],
    source_code: str | None,
) -> _LocalFixReplacement | None:
    line_info = _finding_source_line(finding, source_code)
    if line_info is None:
        return None

    line_number, raw_line = line_info
    match = _CPP_THREAD_CONTROL_STANDALONE_RE.fullmatch(raw_line)
    if not match:
        conditional_match = _CPP_THREAD_CONTROL_IF_LINE_RE.fullmatch(raw_line)
        if not conditional_match:
            return None

        indent = conditional_match.group("indent")
        api = conditional_match.group("api")
        condition = conditional_match.group("condition").strip()
        stripped = raw_line.strip()
        negated = condition.startswith("!") or condition.startswith("!(")
        conservative_branch = "true" if negated else "false"
        fixed_code = "\n".join(
            [
                f"{indent}// Aegis: {api} was removed because it can interrupt a thread while it owns locks or shared state.",
                f"{indent}// Replace it with a cooperative stop/pause signal and wait for a safe point.",
                f"{indent}// Original unsafe condition kept for review:",
                f"{indent}// {stripped}",
                f"{indent}if ({conservative_branch})",
            ]
        )
        return _LocalFixReplacement(
            fixed_code=fixed_code,
            fix_suggestion=(
                f"不要在条件判断中直接调用 {api}；应改成协作式停止/暂停信号。"
                "当前预览会移除危险调用并走保守分支，必须人工确认后再应用。"
            ),
            explanation=f"{api} 无法保证目标线程在安全位置停下，条件表达式内调用还会把控制流和危险副作用绑在一起。",
            confidence=0.43,
            start_line=line_number,
            end_line=line_number,
        )

    indent = match.group("indent")
    api = match.group("api")
    stripped = raw_line.strip()
    control_word = "停止" if api.lower() == "terminatethread" else "暂停"
    action_noun = "stop" if api.lower() == "terminatethread" else "pause"
    fixed_code = "\n".join(
        [
            f"{indent}// Aegis: {api} may interrupt a thread while it owns locks or shared state.",
            f"{indent}// Replace it with a cooperative {action_noun} signal and wait for a safe point.",
            f"{indent}// Original unsafe call kept for review:",
            f"{indent}// {stripped}",
        ]
    )
    return _LocalFixReplacement(
        fixed_code=fixed_code,
        fix_suggestion=f"不要直接调用 {api}；改为设置协作式{control_word}标志/事件，由线程自己释放资源后退出或等待。",
        explanation=f"{api} 无法保证目标线程在安全位置停下，可能留下未释放锁、句柄或半更新共享状态。",
        confidence=0.56,
        start_line=line_number,
        end_line=line_number,
    )


def _build_local_cpp_fix_replacement(
    finding: dict[str, Any],
    source_code: str | None,
    language: str | None,
) -> _LocalFixReplacement | None:
    if not source_code or not _is_cpp_context(finding, language):
        return None

    vuln_type = _normalize_vulnerability_type(finding.get("type", ""))
    if vuln_type == "BUFFER_OVERFLOW":
        strcpy_replacement = _build_cpp_buffer_overflow_replacement(finding, source_code, language)
        if strcpy_replacement:
            line_number = _coerce_line_number(finding.get("line") or finding.get("start_line"), 1) or 1
            return _LocalFixReplacement(
                fixed_code=strcpy_replacement,
                fix_suggestion="将无边界 strcpy 替换为限定目标数组容量的 strncpy，并显式补充字符串终止符。",
                explanation="C/C++ 固定数组拷贝需要限制写入长度。",
                confidence=0.82,
                start_line=line_number,
                end_line=line_number,
            )
        return _build_cpp_cin_buffer_replacement(finding, source_code)

    if vuln_type == "ASSIGNMENT_IN_CONDITION":
        return _build_cpp_assignment_condition_replacement(finding, source_code)
    if vuln_type == "NULL_DEREFERENCE":
        return _build_cpp_null_deref_replacement(finding, source_code)
    if vuln_type == "LOCK_MISMATCH":
        return _build_cpp_lock_mismatch_replacement(finding, source_code)
    if vuln_type == "THREAD_LIFECYCLE_RISK":
        return _build_cpp_thread_lifecycle_replacement(finding, source_code)
    return None


def _extract_rich_context(
    file_path: str,
    vuln_line: int,
    source_code: str | None = None,
    padding: int = 10,
) -> dict[str, Any]:
    """
    提取漏洞周围的丰富上下文，供 AI 生成精准修复代码。

    Args:
        file_path: 文件路径（用于读取代码，source_code 优先）
        vuln_line: 漏洞行号（1-indexed）
        source_code: 可选的源代码字符串（优先使用，避免重复读文件）
        padding: 漏洞行前后各扩展的行数

    Returns:
        结构化上下文字典：
        {
          "vuln_snippet": str,        # 漏洞前后 ±padding 行
          "function_signature": str,  # 包含漏洞行的函数签名（含参数）
          "imports": list[str],       # 文件级 import/require 语句列表
          "local_vars": list[str],    # 漏洞行前 30 行内出现的变量名
          "framework_hints": list[str], # 从 import 推断的框架名称
          "actual_start_line": int,   # vuln_snippet 的实际起始行（1-indexed）
        }
    """
    # 读取源代码
    code = source_code
    if code is None:
        try:
            code = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.debug("_extract_rich_context: 读取文件失败 %s: %s", file_path, exc)
            return {
                "vuln_snippet": "",
                "function_signature": "",
                "imports": [],
                "local_vars": [],
                "framework_hints": [],
                "actual_start_line": vuln_line,
            }

    all_lines = code.splitlines()
    total = len(all_lines)

    # ── 1. 漏洞片段 ──────────────────────────────────────────────────
    ctx_start = max(0, vuln_line - 1 - padding)
    ctx_end = min(total, vuln_line + padding)
    vuln_snippet = "\n".join(all_lines[ctx_start:ctx_end])

    # ── 2. Import / require 语句 ─────────────────────────────────────
    imports: list[str] = []
    _import_re = re.compile(
        r"^\s*(?:"
        r"import\s+.+?from\s+['\"].+?['\"]"  # ES6 import ... from '...'
        r"|(?:const|let|var)\s+\S+\s*=\s*require\s*\(['\"].+?['\"]\s*\)"  # const x = require('...')
        r"|require\s*\(\s*['\"].+?['\"]\s*\)"  # bare require('...')
        r"|import\s+['\"].+?['\"]"  # import '...'
        r"|from\s+\S+\s+import\s+.+"  # Python from x import y
        r"|import\s+\S+"  # Python import x
        r")",
        re.MULTILINE,
    )
    for line in all_lines[:80]:  # 只取文件头部 80 行（import 通常在头部）
        if _import_re.match(line.strip()):
            imports.append(line.strip())

    # ── 3. 框架推断 ──────────────────────────────────────────────────
    import_text = "\n".join(imports).lower()
    framework_hints: list[str] = []
    for keyword, label in _FRAMEWORK_IMPORT_MAP.items():
        if keyword in import_text and label not in framework_hints:
            framework_hints.append(label)

    # 二次推断：当 import 中没有显式框架，从代码模式推断
    # （适用于 NodeGoat 这种把 db 作为构造参数传入而不直接 require mongodb 的风格）
    if not framework_hints:
        code_lower = code.lower()
        # MongoDB 特征：.collection(/ .findOne( / .aggregate( 等
        if any(sig in code_lower for sig in [".collection(", "findone(", "findandmodify(", "mongodb"]):
            framework_hints.append("mongodb")
        # Mongoose 特征：Schema / model(
        if any(sig in code_lower for sig in ["mongoose", "schema(", ".model("]):
            framework_hints.append("mongoose")
        # mysql2/mysql 特征：connection.query / pool.query
        if any(sig in code_lower for sig in ["connection.query(", "pool.query(", "connection.execute("]):
            if "mysql2" in code_lower or "mysql2" in import_text:
                framework_hints.append("mysql2")
            else:
                framework_hints.append("mysql")

    # ── 4. 包含漏洞行的函数签名 ──────────────────────────────────────
    function_signature = _find_enclosing_function_signature(all_lines, vuln_line, file_path)

    # ── 5. 近域变量名（漏洞行前 50 行内） ────────────────────────────
    local_vars = _collect_local_vars(all_lines, vuln_line, window=50)

    return {
        "vuln_snippet": vuln_snippet,
        "function_signature": function_signature,
        "imports": imports,
        "local_vars": local_vars,
        "framework_hints": framework_hints,
        "actual_start_line": ctx_start + 1,
    }


def _find_enclosing_function_signature(lines: list[str], vuln_line: int, file_path: str) -> str:
    """
    从 lines 中向上查找包含 vuln_line 的函数定义，返回其签名行。

    支持模式：
    - JS/TS function 声明：function foo(...)
    - JS/TS 箭头函数赋值：this.foo = (...) => {  /  const foo = (...) => {
    - JS/TS 方法赋值：this.method = function(...) {
    - JS 对象属性函数：key: function(...) {
    - Python def / async def
    """
    # 优先级正则列表（从最具体到最通用），依次尝试
    # 控制流关键字集合：这些行不是函数定义，即使语法上匹配
    _CF_KEYWORDS = frozenset(
        {
            "if",
            "else",
            "for",
            "while",
            "do",
            "switch",
            "try",
            "catch",
            "finally",
            "with",
            "return",
            "throw",
            "case",
            "break",
            "continue",
        }
    )

    _func_patterns = [
        # this.name = (args) => {   ← NodeGoat 风格，最优先
        re.compile(r"^\s*this\.\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"),
        # this.name = function(args) {
        re.compile(r"^\s*this\.\w+\s*=\s*(?:async\s+)?function\s*\([^)]*\)"),
        # const/let/var name = (args) => {
        re.compile(r"^\s*(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"),
        # const/let/var name = async? function(
        re.compile(r"^\s*(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?function\s*\("),
        # function name(args) {
        re.compile(r"^\s*(?:async\s+)?function\s+\w+\s*\("),
        # Python: def name( / async def name(
        re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\("),
        # key: function(  ← 对象字面量方法
        re.compile(r"^\s*\w+\s*:\s*(?:async\s+)?function\s*\("),
        # method(args) {  ← 类方法（最后匹配，排除控制流关键字）
        re.compile(r"^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{"),
    ]

    # 从漏洞行向上搜索（最多 80 行，覆盖深层嵌套函数）
    search_start = max(0, vuln_line - 2)
    for i in range(search_start, max(-1, search_start - 80), -1):
        if i >= len(lines):
            continue
        line = lines[i]
        stripped = line.strip()
        # 跳过控制流关键字开头的行（if/for/while 等不是函数定义）
        first_word = stripped.split("(")[0].split()[0] if stripped else ""
        if first_word in _CF_KEYWORDS:
            continue
        for pat in _func_patterns:
            if pat.match(line):
                return stripped

    return ""


def _collect_local_vars(lines: list[str], vuln_line: int, window: int = 30) -> list[str]:
    """
    收集漏洞行前 window 行内出现的变量名。

    收集来源：
    1. 普通赋值左侧：const/let/var name = ...
    2. 函数参数：(userName, password, callback) =>  /  function foo(a, b)
    3. Python 参数：def func(self, arg):
    4. this.method 赋值中的方法名（部分框架风格）
    """
    _KEYWORDS = frozenset(
        {
            "if",
            "while",
            "for",
            "return",
            "class",
            "function",
            "import",
            "from",
            "const",
            "let",
            "var",
            "async",
            "await",
            "new",
            "this",
            "true",
            "false",
            "null",
            "undefined",
            "export",
            "default",
            "try",
            "catch",
            "finally",
            "throw",
            "switch",
            "case",
            "break",
            "continue",
            "typeof",
            "instanceof",
            "in",
            "of",
            "do",
            "else",
            "del",
            "pass",
            "with",
            "yield",
            "lambda",
            "raise",
            "except",
            "global",
            "nonlocal",
            "def",
            "and",
            "or",
            "not",
            "is",
        }
    )

    # 匹配：const/let/var/Python 赋值
    _assign_re = re.compile(r"^\s*(?:const|let|var)?\s*(\w+)\s*(?:=|:=)")
    # 匹配：箭头函数参数列表 (a, b, c) =>
    _arrow_params_re = re.compile(r"\(([^)]*)\)\s*=>")
    # 匹配：function name(a, b) 或匿名 function(a, b)
    _func_params_re = re.compile(r"function\s*\w*\s*\(([^)]*)\)")
    # 匹配：Python def foo(self, a, b):
    _py_params_re = re.compile(r"def\s+\w+\s*\(([^)]*)\)")

    seen: dict[str, None] = {}

    start = max(0, vuln_line - 1 - window)
    end = vuln_line - 1
    for line in lines[start:end]:
        # 普通赋值
        m = _assign_re.match(line)
        if m:
            name = m.group(1)
            if name not in _KEYWORDS:
                seen[name] = None

        # 从函数参数列表中提取变量名
        for param_re in (_arrow_params_re, _func_params_re, _py_params_re):
            for pm in param_re.finditer(line):
                for raw_param in pm.group(1).split(","):
                    # 去掉类型注解和默认值：(x: string = "a") -> x
                    param_name = re.split(r"[=:?]", raw_param.strip())[0].strip()
                    param_name = re.sub(r"^[.\s*]+", "", param_name)  # 去 ...rest
                    if param_name and re.match(r"^\w+$", param_name) and param_name not in _KEYWORDS:
                        seen[param_name] = None

    return list(seen.keys())


@dataclass
class AIAnalysisResult:
    """AI 分析结果"""

    is_true_positive: bool  # 是否为真阳性
    confidence: float  # 置信度 (0-1)
    risk_level: str  # 风险等级: Critical/High/Medium/Low/Info
    explanation: str  # 分析解释
    fix_suggestion: str | None  # 修复建议文字描述
    requires_review: bool  # 是否需要人工审查
    # 精准修复字段：针对当前代码上下文由 AI 生成，按需触发时填充
    fixed_code: str | None = field(default=None)  # AI 生成的完整修复代码（可直接参考）
    fix_start_line: int | None = field(default=None)  # 建议替换的起始行（基于文件行号）
    fix_end_line: int | None = field(default=None)  # 建议替换的结束行
    error_code: str | None = field(default=None)  # 结构化错误码（用于 UI 反馈）
    error_message: str | None = field(default=None)  # 可直接展示给用户的错误描述


def build_local_fix_analysis(
    finding: dict[str, Any],
    source_code: str | None,
    language: str | None,
) -> AIAnalysisResult | None:
    """Return a deterministic local replacement for narrow, reviewable findings."""
    local = _build_local_cpp_fix_replacement(finding, source_code, language)
    if local is None:
        return None

    return AIAnalysisResult(
        is_true_positive=True,
        confidence=local.confidence,
        risk_level=str(finding.get("severity") or "High"),
        explanation=local.explanation,
        fix_suggestion=local.fix_suggestion,
        requires_review=True,
        fixed_code=local.fixed_code,
        fix_start_line=local.start_line,
        fix_end_line=local.end_line,
    )


class AIAnalyzer:
    """
    AI 分析器。

    功能：
    - 漏洞真实性评估
    - 风险等级调整
    - 修复代码生成

    支持的 AI 提供商（通过 AI_PROVIDER 环境变量或自动检测）：
    - ollama（默认本地优先）：设置 OLLAMA_BASE_URL（默认 http://localhost:11434/v1），或 AI_PROVIDER=ollama
    - deepseek：设置 DEEPSEEK_API_KEY，或 AI_PROVIDER=deepseek
    - openai：设置 OPENAI_API_KEY，或 AI_PROVIDER=openai
    - custom：设置 AI_PROVIDER=custom，同时设置 AI_BASE_URL 和 AI_API_KEY

    AI 漏斗策略：
    1. 预筛选：只对 Critical/High 级别进行 AI 分析
    2. 批量处理：相似漏洞合并分析
    3. 缓存结果：避免重复分析相同模式
    """

    # AI 分析阈值配置
    ANALYSIS_CONFIG = {
        "enabled_severities": ["Critical", "High", "Medium"],  # 降低门槛至 Medium
        "max_findings_per_batch": 10,  # 每批最大数量
        "confidence_threshold": 0.7,  # 置信度阈值
        "cache_enabled": True,  # 是否启用缓存
    }

    # 各提供商的默认模型
    _PROVIDER_DEFAULT_MODELS: dict[str, str] = {
        "deepseek": "deepseek-chat",
        "openai": "gpt-4o-mini",
        "ollama": "llama3",
        "custom": "gpt-4o-mini",
    }

    _KNOWN_PROVIDERS = {"deepseek", "openai", "ollama", "custom"}

    @staticmethod
    def _resolve_provider(
        api_key: str | None,
        api_base: str | None,
        model: str | None,
    ) -> tuple[str, str | None, str, str]:
        """
        自动推断 AI 提供商，返回 (provider, api_key, api_base, model)。

        优先级：
        1. 显式 AI_PROVIDER 环境变量
        2. 构造函数传入的 api_base（视为自定义提供商）
        3. 构造函数 api_key（视为 DeepSeek 兼容密钥）
        4. 可用的 API Key（DEEPSEEK_API_KEY > OPENAI_API_KEY）
        5. 降级为 ollama（本地优先，无需 API Key）
        """
        provider = os.getenv("AI_PROVIDER", "").lower().strip()
        resolved_key: str | None

        if provider and provider not in AIAnalyzer._KNOWN_PROVIDERS:
            return (
                provider,
                api_key or os.getenv("AI_API_KEY"),
                cast(str, api_base) if api_base else os.getenv("AI_BASE_URL", ""),
                cast(str, model) if model else os.getenv("AI_MODEL", "gpt-4o-mini"),
            )

        if provider == "ollama" or (not provider and os.getenv("OLLAMA_BASE_URL")):
            resolved_provider = "ollama"
            resolved_base = (
                cast(str, api_base) if api_base else os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            )
            resolved_key = api_key or "ollama"  # Ollama 不需要真实 API Key
            resolved_model = cast(str, model) if model else os.getenv("OLLAMA_MODEL", "llama3")
            return resolved_provider, resolved_key, resolved_base, resolved_model

        # OpenAI：显式指定，或无 DeepSeek Key 时自动降级
        has_openai_only = (
            not provider and not api_key and bool(os.getenv("OPENAI_API_KEY")) and not os.getenv("DEEPSEEK_API_KEY")
        )
        if provider == "openai" or has_openai_only:
            resolved_provider = "openai"
            resolved_base = (
                cast(str, api_base) if api_base else os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
            )
            resolved_key = api_key or os.getenv("OPENAI_API_KEY")
            resolved_model = cast(str, model) if model else os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            return resolved_provider, resolved_key, resolved_base, resolved_model

        if provider == "custom":
            resolved_provider = "custom"
            resolved_base = cast(str, api_base) if api_base else os.getenv("AI_BASE_URL", "")
            resolved_key = api_key or os.getenv("AI_API_KEY")
            resolved_model = cast(str, model) if model else os.getenv("AI_MODEL", "gpt-4o-mini")
            return resolved_provider, resolved_key, resolved_base, resolved_model

        if not provider and not api_key and not os.getenv("DEEPSEEK_API_KEY") and not os.getenv("OPENAI_API_KEY"):
            resolved_provider = "ollama"
            resolved_base = (
                cast(str, api_base) if api_base else os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            )
            resolved_key = "ollama"
            resolved_model = cast(str, model) if model else os.getenv("OLLAMA_MODEL", "llama3")
            return resolved_provider, resolved_key, resolved_base, resolved_model

        # DeepSeek（兼容 OpenAI SDK）
        resolved_provider = "deepseek"
        resolved_base = (
            cast(str, api_base) if api_base else os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
        )
        resolved_key = api_key or os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
        resolved_model = cast(str, model) if model else os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        return resolved_provider, resolved_key, resolved_base, resolved_model

    @staticmethod
    def _resolve_fallback_order(preferred_provider: str) -> list[str]:
        """Resolve provider fallback order from env or local-first defaults."""
        raw_order = os.getenv("AI_PROVIDER_FALLBACK_ORDER", "")
        if raw_order.strip():
            names = [name.strip().lower() for name in raw_order.split(",") if name.strip()]
        else:
            names = ["ollama", "deepseek", "openai", "custom"]

        ordered: list[str] = []
        for name in [preferred_provider, *names]:
            if name and name not in ordered:
                ordered.append(name)
        return ordered

    @staticmethod
    def _build_default_gateway(
        preferred_provider: str,
        resolved_key: str | None,
        resolved_base: str,
        resolved_model: str,
    ) -> LLMGateway:
        """Create the default gateway with built-in OpenAI-compatible providers."""

        def _provider_value(name: str, env_name: str, fallback: str) -> str:
            if preferred_provider == name:
                return resolved_base
            return os.getenv(env_name, fallback)

        def _provider_key(name: str, env_name: str, fallback: str | None = None) -> str | None:
            if preferred_provider == name:
                return resolved_key
            return os.getenv(env_name) or fallback

        def _provider_model(name: str, env_name: str, fallback: str) -> str:
            if preferred_provider == name:
                return resolved_model
            return os.getenv(env_name, fallback)

        providers = [
            OpenAICompatibleProvider(
                name="ollama",
                api_key=_provider_key("ollama", "OLLAMA_API_KEY", "ollama"),
                base_url=_provider_value("ollama", "OLLAMA_BASE_URL", "http://localhost:11434/v1"),
                default_model=_provider_model("ollama", "OLLAMA_MODEL", "llama3"),
                requires_api_key=False,
            ),
            OpenAICompatibleProvider(
                name="deepseek",
                api_key=_provider_key("deepseek", "DEEPSEEK_API_KEY"),
                base_url=_provider_value("deepseek", "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),
                default_model=_provider_model("deepseek", "DEEPSEEK_MODEL", "deepseek-chat"),
            ),
            OpenAICompatibleProvider(
                name="openai",
                api_key=_provider_key("openai", "OPENAI_API_KEY"),
                base_url=_provider_value("openai", "OPENAI_BASE_URL", "https://api.openai.com/v1"),
                default_model=_provider_model("openai", "OPENAI_MODEL", "gpt-4o-mini"),
            ),
            OpenAICompatibleProvider(
                name="custom",
                api_key=_provider_key("custom", "AI_API_KEY"),
                base_url=_provider_value("custom", "AI_BASE_URL", ""),
                default_model=_provider_model("custom", "AI_MODEL", "gpt-4o-mini"),
            ),
        ]
        return LLMGateway(providers)

    def __init__(
        self,
        api_key: str | None = None,
        api_base: str | None = None,
        model: str | None = None,
        enabled: bool = True,
        llm_gateway: LLMGateway | None = None,
    ) -> None:
        """
        初始化 AI 分析器。

        Args:
            api_key: AI API 密钥（默认从环境变量获取；Ollama 无需设置）
            api_base: API 基础 URL（覆盖自动推断的端点）
            model: 模型名称（覆盖各提供商的默认模型）
            enabled: 是否启用 AI 分析
            llm_gateway: 可选的外部 provider gateway，用于测试或注册自定义 provider

        提供商选择（按优先级）：
            - 设置 AI_PROVIDER=ollama + 可选 OLLAMA_BASE_URL → 使用本地 Ollama（免费、保护隐私）
            - 设置 AI_PROVIDER=openai + OPENAI_API_KEY → 使用 OpenAI
            - 设置 AI_PROVIDER=deepseek + DEEPSEEK_API_KEY → 使用 DeepSeek（默认）
            - 设置 AI_PROVIDER=custom + AI_BASE_URL + AI_API_KEY → 使用自定义兼容端点
        """
        self.provider, self.api_key, self.api_base, self.model = self._resolve_provider(api_key, api_base, model)
        self._model_override = model
        self._fallback_order = self._resolve_fallback_order(self.provider)
        self.llm_gateway = llm_gateway or self._build_default_gateway(
            self.provider,
            self.api_key,
            self.api_base,
            self.model,
        )
        self.enabled = enabled and self.llm_gateway.has_configured_provider([self.provider])

        # 分析缓存
        self._cache: dict[str, AIAnalysisResult] = {}

        if self.enabled:
            logger.info("AI 分析器已启用 (提供商: %s, 模型: %s)", self.provider, self.model)
        else:
            logger.warning(
                "AI 分析器未启用（缺少 API 密钥或已禁用）。"
                "提示：默认 AI_PROVIDER=ollama 可使用本地免费 LLM，无需 API Key。"
            )

    def should_analyze(self, finding: dict[str, Any]) -> bool:
        """
        判断是否应该对该发现进行 AI 分析（AI 漏斗）。

        Args:
            finding: 扫描发现

        Returns:
            是否应该分析
        """
        if not self.enabled:
            return False

        severity = str(finding.get("severity", "Low"))
        enabled_severities = cast(list[str], self.ANALYSIS_CONFIG["enabled_severities"])
        return severity in enabled_severities

    def analyze_finding(
        self,
        finding: dict[str, Any],
        code_context: str | None = None,
        language: str | None = None,
        source_code: str | None = None,
    ) -> AIAnalysisResult:
        """
        分析单个扫描发现。仅在用户主动触发时调用，不应自动批量执行。

        Args:
            finding: 扫描发现
            code_context: 漏洞所在函数代码块（前后各10行，非整个文件），
                          若同时提供 source_code 则优先使用后者提取 rich context
            language: 编程语言（javascript/python/php），不传时从 finding 中取
            source_code: 完整源代码字符串（用于 rich context 提取）

        Returns:
            AI 分析结果
        """
        cache_key = self._get_cache_key(
            finding,
            code_context=code_context,
            language=language,
            source_code=source_code,
        )
        if cache_key in self._cache:
            return self._cache[cache_key]

        local_result = build_local_fix_analysis(
            finding,
            source_code,
            language or finding.get("language"),
        )
        if local_result is not None:
            if self.ANALYSIS_CONFIG["cache_enabled"]:
                self._cache[cache_key] = local_result
            return local_result

        if not self.enabled:
            return self._error_analysis(
                finding,
                "provider_not_configured",
                "AI provider is not configured. Set AI_PROVIDER and the matching API key, or use Ollama for local fixes.",
            )

        # 提取 rich context（优先使用 source_code）
        file_path = finding.get("file", "")
        vuln_line = finding.get("line") or finding.get("start_line") or 1
        rich_ctx = _extract_rich_context(
            file_path=file_path,
            vuln_line=int(vuln_line),
            source_code=source_code,
            padding=10,
        )
        # 若未提供 source_code 但提供了 code_context，回填到 rich_ctx.vuln_snippet
        if not rich_ctx["vuln_snippet"] and code_context:
            rich_ctx["vuln_snippet"] = code_context

        result = self._call_ai_analysis(
            finding,
            rich_ctx=rich_ctx,
            language=language or finding.get("language"),
        )

        if result.error_code == "no_applicable_fix" or not result.fixed_code:
            local_result = build_local_fix_analysis(
                finding,
                source_code,
                language or finding.get("language"),
            )
            if local_result is not None:
                result = local_result

        if self.ANALYSIS_CONFIG["cache_enabled"]:
            self._cache[cache_key] = result

        return result

    def analyze_findings_batch(
        self, findings: list[dict[str, Any]], code_contexts: dict[str, str] | None = None
    ) -> list[tuple[dict[str, Any], AIAnalysisResult]]:
        """
        批量分析扫描发现。

        Args:
            findings: 扫描发现列表
            code_contexts: 文件路径 -> 代码上下文的映射

        Returns:
            (finding, analysis_result) 元组列表
        """
        results = []

        # 筛选需要 AI 分析的发现
        to_analyze = [f for f in findings if self.should_analyze(f)]
        skip_analyze = [f for f in findings if not self.should_analyze(f)]

        # 对需要分析的进行 AI 分析
        for finding in to_analyze:
            file_path = finding.get("file", "")
            code_context = code_contexts.get(file_path) if code_contexts else None
            result = self.analyze_finding(finding, code_context)
            results.append((finding, result))

        # 对不需要分析的返回默认结果
        for finding in skip_analyze:
            result = self._default_analysis(finding)
            results.append((finding, result))

        return results

    def _get_cache_key(
        self,
        finding: dict[str, Any],
        *,
        code_context: str | None = None,
        language: str | None = None,
        source_code: str | None = None,
    ) -> str:
        """生成绑定文件、位置、语言和代码上下文的稳定缓存键。"""
        context_material = (
            source_code
            if source_code is not None
            else code_context
            if code_context is not None
            else finding.get("code") or finding.get("snippet") or finding.get("context") or ""
        )
        context_hash = hashlib.sha256(str(context_material).encode("utf-8", errors="replace")).hexdigest()
        vuln_type = str(finding.get("type", ""))
        payload = {
            "column": finding.get("column") or finding.get("start_character") or 0,
            "context_hash": context_hash,
            "cwe": str(finding.get("cwe", "")),
            "details": str(finding.get("details", "")),
            "end_line": finding.get("end_line") or finding.get("line") or finding.get("start_line") or 0,
            "file": str(finding.get("file") or finding.get("file_path") or ""),
            "language": str(language or finding.get("language") or ""),
            "line": finding.get("line") or finding.get("start_line") or 0,
            "type": vuln_type,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        digest = hashlib.sha256(encoded.encode("utf-8", errors="replace")).hexdigest()
        return f"{vuln_type}:{digest}"

    def _default_analysis(self, finding: dict[str, Any]) -> AIAnalysisResult:
        """生成默认分析结果（不使用 AI）"""
        return AIAnalysisResult(
            is_true_positive=True,  # 假设为真阳性
            confidence=0.5,
            risk_level=finding.get("severity", "Medium"),
            explanation="未进行 AI 分析，建议人工审查。",
            fix_suggestion=None,
            requires_review=True,
        )

    def _error_analysis(
        self,
        finding: dict[str, Any],
        error_code: str,
        error_message: str,
        *,
        explanation: str | None = None,
        fix_suggestion: str | None = None,
        fixed_code: str | None = None,
    ) -> AIAnalysisResult:
        """生成带结构化错误码的结果，供 UI 给出明确反馈。"""
        return AIAnalysisResult(
            is_true_positive=True,
            confidence=0.0,
            risk_level=finding.get("severity", "Medium"),
            explanation=explanation or error_message,
            fix_suggestion=fix_suggestion,
            requires_review=True,
            fixed_code=fixed_code,
            fix_start_line=finding.get("start_line"),
            fix_end_line=finding.get("end_line"),
            error_code=error_code,
            error_message=error_message,
        )

    def _call_ai_analysis(
        self,
        finding: dict[str, Any],
        rich_ctx: dict[str, Any] | None = None,
        language: str | None = None,
    ) -> AIAnalysisResult:
        """
        调用 AI 进行分析（仅在用户主动触发时执行，不自动批量调用）。

        Args:
            finding: 扫描发现
            rich_ctx: _extract_rich_context() 返回的上下文字典
            language: 编程语言（javascript/python/php）

        Returns:
            AI 分析结果
        """
        try:
            prompt = self._build_analysis_prompt(finding, rich_ctx=rich_ctx, language=language)
            response = self.llm_gateway.generate(
                LLMRequest(
                    model=self._model_override,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "你是专业的安全代码审计专家，擅长识别和修复 Web 应用安全漏洞。"
                                "分析时必须严格按照用户要求的 JSON 格式返回结果，"
                                "不得在 JSON 外添加任何说明文字或 markdown 代码块标记。"
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=2000,
                    timeout=30,
                ),
                preferred_provider=self.provider,
                fallback_order=self._fallback_order,
            )
            return self._parse_ai_response(response.content, finding)

        except AllProvidersFailedError as e:
            logger.warning("AI provider gateway failed: %s", e)
            return self._error_analysis(
                finding,
                "provider_unavailable",
                f"AI provider request failed: {e}",
            )
        except (RuntimeError, KeyError, ValueError, OSError) as e:
            logger.warning("AI 分析失败: %s", e)
            return self._error_analysis(
                finding,
                "provider_unavailable",
                f"AI provider request failed: {e}",
            )
        except Exception as e:
            logger.warning("AI 分析未预期异常: %s: %s", type(e).__name__, e)
            return self._error_analysis(
                finding,
                "provider_unavailable",
                f"AI provider request failed: {type(e).__name__}: {e}",
            )

    def _build_analysis_prompt(
        self,
        finding: dict[str, Any],
        rich_ctx: dict[str, Any] | None = None,
        language: str | None = None,
    ) -> str:
        """
        构建上下文感知提示词，要求 AI 返回精准修复 JSON。

        Args:
            finding: 漏洞发现 dict
            rich_ctx: _extract_rich_context() 返回的上下文字典
            language: 编程语言（javascript/python/php）

        Returns:
            完整提示词字符串
        """
        lang = language or finding.get("language") or "未知"
        cwe = finding.get("cwe", "")
        vuln_type = finding.get("type", "Unknown")
        type_desc = f"{vuln_type}（{cwe}）" if cwe else vuln_type
        vuln_line = finding.get("line", "?")

        ctx = rich_ctx or {}
        framework_hints: list[str] = ctx.get("framework_hints") or []
        function_sig: str = ctx.get("function_signature") or ""
        imports: list[str] = ctx.get("imports") or []
        local_vars: list[str] = ctx.get("local_vars") or []
        vuln_snippet: str = ctx.get("vuln_snippet") or ""

        lines: list[str] = [
            f"你是一个安全工程师，需要修复以下代码中的 {type_desc} 漏洞。",
            "",
            "## 上下文",
        ]

        if framework_hints:
            lines.append(f"- 框架/库：{', '.join(framework_hints)}")
        else:
            lines.append(f"- 语言：{lang}")

        if function_sig:
            lines.append(f"- 所在函数：`{function_sig}`")

        if imports:
            # 最多展示 8 条 import
            lines.append("- 相关 import：")
            for imp in imports[:8]:
                lines.append(f"  - `{imp}`")

        if local_vars:
            lines.append(f"- 近域变量名（请优先复用这些名称，不要造新名）：{', '.join(local_vars[:15])}")

        lines += [
            "",
            "## 漏洞信息",
            f"- 类型: {type_desc}",
            f"- 严重程度: {finding.get('severity', 'Unknown')}",
            f"- 文件: {finding.get('file', 'Unknown')}",
            f"- 漏洞行: 第 {vuln_line} 行",
            f"- 描述: {finding.get('details', '')}",
        ]

        if vuln_snippet:
            actual_start = ctx.get("actual_start_line", vuln_line)
            lines += [
                "",
                f"## 漏洞代码（从第 {actual_start} 行开始）",
                f"```{lang}",
                vuln_snippet[:2000],
                "```",
            ]

        # 框架感知的修复指引
        fix_guidance = _build_framework_fix_guidance(vuln_type, framework_hints)
        if fix_guidance:
            lines += ["", "## 修复指引", fix_guidance]

        lines += [
            "",
            "## 要求",
            "请直接返回以下 JSON 对象（不要用 markdown 代码块包裹，不要添加任何额外文字）：",
            "{",
            '  "is_false_positive": false,',
            '  "confidence": 0.85,',
            '  "risk_level": "High",',
            '  "explanation": "简短解释漏洞原因（1-2句）",',
            f'  "fix_start_line": {finding.get("start_line") or vuln_line},',
            f'  "fix_end_line": {finding.get("end_line") or vuln_line},',
            '  "fixed_code": "只包含 fix_start_line 到 fix_end_line 的替换代码；保留原缩进，不要返回整个文件或整个函数",',
            '  "fix_description": "一句话说明修复思路"',
            "}",
            "",
            "fixed_code 必须是可直接替换上述行号范围的安全代码。如果需要替换多行，请同时扩大 "
            "fix_start_line/fix_end_line；不要只给自然语言建议。",
        ]

        return "\n".join(lines)

    def _parse_ai_response(
        self,
        response: str,
        finding: dict[str, Any],
    ) -> AIAnalysisResult:
        """
        解析 AI JSON 响应，两级容错降级。

        Args:
            response: AI 返回的原始文本
            finding: 原始漏洞发现（用于降级时取默认值）

        Returns:
            AIAnalysisResult
        """
        parsed: dict[str, Any] | None = None

        # 第一次尝试：直接解析整个响应
        try:
            parsed = json.loads(response.strip())
        except json.JSONDecodeError:
            pass

        # 第二次尝试：提取最外层 JSON 对象（兼容 AI 在前后加了说明文字的情况）
        if parsed is None:
            match = re.search(r"\{.*\}", response, re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group())
                except json.JSONDecodeError:
                    pass

        if parsed is None:
            logger.warning("AI 响应 JSON 解析失败，降级为默认结果。响应前200字符: %s", response[:200])
            return self._error_analysis(
                finding,
                "provider_unavailable",
                "AI provider returned an invalid response. Check the configured model or endpoint.",
            )

        confidence = float(parsed.get("confidence", 0.7))
        fixed_code = _first_nonempty_string(
            parsed,
            (
                "fixed_code",
                "replacement_code",
                "replacement",
                "suggested_code",
                "code",
            ),
        )
        start_line = _coerce_line_number(parsed.get("fix_start_line"), finding.get("start_line"))
        end_line = _coerce_line_number(parsed.get("fix_end_line"), finding.get("end_line"))
        if start_line is not None and end_line is not None and end_line < start_line:
            end_line = start_line

        result = AIAnalysisResult(
            is_true_positive=not bool(parsed.get("is_false_positive", False)),
            confidence=confidence,
            risk_level=parsed.get("risk_level") or finding.get("severity", "Medium"),
            explanation=parsed.get("explanation", ""),
            fix_suggestion=parsed.get("fix_description") or None,
            requires_review=confidence < cast(float, self.ANALYSIS_CONFIG["confidence_threshold"]),
            fixed_code=fixed_code,
            fix_start_line=start_line,
            fix_end_line=end_line,
        )
        if result.fixed_code is None:
            result.error_code = "no_applicable_fix"
            result.error_message = "AI reviewed this finding but did not return a safe replacement."
        return result

    def get_analysis_summary(self, results: list[tuple[dict[str, Any], AIAnalysisResult]]) -> dict[str, Any]:
        """
        生成分析摘要。

        Args:
            results: 分析结果列表

        Returns:
            分析摘要
        """
        total = len(results)
        true_positives = sum(1 for _, r in results if r.is_true_positive)
        needs_review = sum(1 for _, r in results if r.requires_review)

        # 按风险等级统计
        by_risk: dict[str, int] = {}
        for _, result in results:
            level = result.risk_level
            by_risk[level] = by_risk.get(level, 0) + 1

        return {
            "total_analyzed": total,
            "true_positives": true_positives,
            "likely_false_positives": total - true_positives,
            "needs_manual_review": needs_review,
            "by_risk_level": by_risk,
            "ai_enabled": self.enabled,
        }


def _build_framework_fix_guidance(vuln_type: str, framework_hints: list[str]) -> str:
    """
    根据漏洞类型和检测到的框架，生成具体的修复指引字符串。

    Args:
        vuln_type: 漏洞类型（如 SQL_INJECTION）
        framework_hints: 框架标签列表（如 ['mysql2', 'express']）

    Returns:
        修复指引字符串，供 prompt 注入使用
    """
    hints_lower = [h.lower() for h in framework_hints]

    if vuln_type == "SQL_INJECTION":
        if "mysql2" in hints_lower:
            return (
                "使用 mysql2 参数化查询：`connection.execute('SELECT * FROM t WHERE id = ?', [id])`，"
                "或 `connection.query('...WHERE id = ?', [id], callback)`。"
                "禁止字符串拼接 SQL。"
            )
        if "sequelize" in hints_lower:
            return (
                "使用 Sequelize 参数化：`Model.findAll({ where: { id: value } })` "
                "或原始查询 `sequelize.query('...WHERE id = :id', { replacements: { id } })`。"
            )
        if any(k in hints_lower for k in ("pymysql", "psycopg2")):
            return (
                "使用参数化查询：`cursor.execute('SELECT * FROM t WHERE id = %s', (id,))`。"
                "禁止 f-string/format 拼接 SQL。"
            )
        if "sqlalchemy" in hints_lower or "django-orm" in hints_lower:
            return (
                "使用 ORM 查询（filter/where）代替原始 SQL。"
                "若必须用原始 SQL，使用 `text('... WHERE id = :id').bindparams(id=val)`。"
            )
        return "使用参数化查询（Prepared Statements），禁止字符串拼接 SQL。"

    if vuln_type == "NOSQL_INJECTION":
        if "mongoose" in hints_lower:
            return (
                "使用 Mongoose 查询前对操作符字段进行类型检查："
                "`if (typeof id !== 'string') throw new Error()`，"
                "再传入 `Model.findOne({ _id: id })`。避免直接传入未验证的对象。"
            )
        if "mongodb" in hints_lower:
            return (
                "对查询字段做严格类型检查（string/ObjectId），"
                "禁止将用户对象直接作为查询条件，防止 `$where`/`$ne` 注入。"
            )
        return "对 NoSQL 查询参数做严格类型检查，避免将用户输入对象直接作为查询条件。"

    if vuln_type == "XSS":
        if "express" in hints_lower:
            return "服务端：用 `he.encode()` 或 `DOMPurify.sanitize()` 净化输出；前端避免 `innerHTML`，改用 `textContent`。"
        return "对所有输出进行 HTML 实体编码，禁止使用 `innerHTML` 直接插入用户数据。"

    if vuln_type == "RCE_COMMAND_EXEC":
        return (
            "避免 `eval`/`exec`/`child_process.exec`；若必须执行命令，使用 `child_process.execFile` 加白名单参数数组。"
        )

    if vuln_type == "PATH_TRAVERSAL":
        return "使用 `path.resolve()` 规范化路径后，断言其以允许的根目录开头（`startsWith(allowedBase)`）。"

    if vuln_type == "SSRF":
        return (
            "对目标 URL 进行严格校验：1) 解析 URL 获取主机名；2) 使用白名单限制允许访问的域名；"
            "3) 拒绝访问私有 IP 段（127.x.x.x、10.x.x.x、172.16-31.x.x、169.254.x.x）；"
            "4) 仅允许 http/https 协议。Python 示例：使用 `ipaddress` 模块校验解析后的 IP。"
        )

    if vuln_type == "BUFFER_OVERFLOW":
        return (
            "C/C++ 固定字符数组写入必须限制目标容量。"
            "对 `strcpy(dst, src)`，若 `dst` 是可见的 `char[N]` 数组或结构体数组成员，"
            "返回两行替换代码：`strncpy(dst, src, sizeof(dst) - 1);` "
            "以及 `dst[sizeof(dst) - 1] = '\\0';`。"
            "对 `cin >> buffer`，使用带宽度限制的读取方式，或扩大替换范围补充必要 include。"
            "不要继续使用 `strcpy`、`gets` 或不带宽度限制的 `cin >>`。"
        )

    return ""


# 便捷函数
def analyze_with_ai(
    findings: list[dict[str, Any]], api_key: str | None = None
) -> list[tuple[dict[str, Any], AIAnalysisResult]]:
    """
    便捷函数：使用 AI 分析扫描结果。

    Args:
        findings: 扫描结果列表
        api_key: AI API 密钥（可选）

    Returns:
        (finding, analysis_result) 元组列表
    """
    analyzer = AIAnalyzer(api_key=api_key)
    return analyzer.analyze_findings_batch(findings)


__all__ = [
    "AIAnalyzer",
    "AIAnalysisResult",
    "analyze_with_ai",
    "build_local_fix_analysis",
    "_extract_rich_context",
]
