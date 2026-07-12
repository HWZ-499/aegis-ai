"""Deterministic local C/C++ remediation builders.

This module has no LLM or provider dependencies. It returns a private replacement
model consumed by scanner.ai_analyzer's stable build_local_fix_analysis facade.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

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
