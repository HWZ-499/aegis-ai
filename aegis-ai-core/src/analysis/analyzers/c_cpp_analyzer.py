"""Focused C/C++ basic security analysis.

C/C++ remains a partial-support language. This module keeps that lightweight
pattern analysis isolated from the deprecated cross-language regex engine so
production dispatch does not need to initialize legacy analyzers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

_SEVERITY = {
    "BUFFER_OVERFLOW": "Critical",
    "FORMAT_STRING": "High",
    "MEMORY_LEAK": "High",
    "USE_AFTER_FREE": "High",
    "RCE_COMMAND_EXEC": "Critical",
    "PATH_TRAVERSAL": "High",
    "THREAD_LIFECYCLE_RISK": "High",
    "ASSIGNMENT_IN_CONDITION": "Medium",
    "NULL_DEREFERENCE": "High",
    "LOCK_MISMATCH": "High",
}

_BASIC_PATTERNS = {
    "BUFFER_OVERFLOW": (
        re.compile(r"\bstrcpy\s*\(", re.IGNORECASE),
        re.compile(r"\bstrcat\s*\(", re.IGNORECASE),
        re.compile(r"\bgets\s*\(", re.IGNORECASE),
        re.compile(r"\bsprintf\s*\(", re.IGNORECASE),
        re.compile(r"\bstrncpy\s*\(\s*[^,]+,\s*[^,]+,\s*strlen", re.IGNORECASE),
    ),
    "FORMAT_STRING": (
        re.compile(r"\bprintf\s*\(\s*[A-Za-z_]\w*\s*\)", re.IGNORECASE),
        re.compile(r"\bsprintf\s*\(\s*[^,]+,\s*[A-Za-z_]\w*\s*\)", re.IGNORECASE),
        re.compile(r"\bprintf\s*\(\s*[^,]+,\s*[^)]+\)", re.IGNORECASE),
        re.compile(r"\bsprintf\s*\(\s*[^,]+,\s*[^,]+,\s*[^)]+\)", re.IGNORECASE),
    ),
    "MEMORY_LEAK": (re.compile(r"\bmalloc\s*\([^)]+\)\s*;", re.IGNORECASE),),
    "USE_AFTER_FREE": (re.compile(r"\bfree\s*\([^)]+\)\s*;", re.IGNORECASE),),
    "RCE_COMMAND_EXEC": (
        re.compile(r"\bsystem\s*\(", re.IGNORECASE),
        re.compile(r"\bexecve\s*\(", re.IGNORECASE),
        re.compile(r"\bexecvp\s*\(", re.IGNORECASE),
    ),
    "PATH_TRAVERSAL": (re.compile(r"\bfopen\s*\(\s*.*\+", re.IGNORECASE),),
}

_CHAR_ARRAY_DECL_RE = re.compile(r"\bchar\s+(?!\*)\s*(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<size>\d+)\s*\]")
_STRCPY_LITERAL_RE = re.compile(
    r"""\bstrcpy\s*\(\s*(?P<dest>[^,]+?)\s*,\s*(?P<src>(?:u8|u|U|L)?"(?:\\.|[^"\\])*")\s*\)""",
    re.IGNORECASE,
)
_CIN_RE = re.compile(r"\bcin\b")
_STREAM_EXTRACT_RE = re.compile(r">>\s*(?P<name>[A-Za-z_]\w*)")
_THREAD_CONTROL_RE = re.compile(r"\b(?P<api>TerminateThread|SuspendThread)\s*\(", re.IGNORECASE)
_CONDITION_RE = re.compile(r"\b(?:if|while)\s*\((?P<condition>.*)\)")
_ASSIGNMENT_OPERATOR_RE = re.compile(r"(?<![=!<>+\-*/%&|^])=(?!=)")
_INTENTIONAL_ASSIGNMENT_SENTINEL_COMPARE_RE = re.compile(
    r"^\s*\(\s*.+?(?<![=!<>+\-*/%&|^])=(?!=).+?\)\s*"
    r"(?:==|!=|<=|>=|<|>)\s*(?:EOF|NULL|nullptr|-?0)\s*$"
)
_NESTED_POINTER_RE = re.compile(r"\b(?P<base>[A-Za-z_]\w*)\s*->\s*(?P<field>[A-Za-z_]\w*)\s*->")
_SHALLOW_GUARD_RE = re.compile(
    r"\bif\s*\(\s*(?P<base>[A-Za-z_]\w*)\s*(?:!=\s*(?:NULL|nullptr|0))?\s*\)",
    re.IGNORECASE,
)
_CRITICAL_ENTER_RE = re.compile(r"\bEnterCriticalSection\s*\(\s*&(?P<name>[A-Za-z_]\w*)\s*\)")
_CRITICAL_LEAVE_RE = re.compile(r"\bLeaveCriticalSection\s*\(\s*&(?P<name>[A-Za-z_]\w*)\s*\)")


def _strip_cpp_line(line: str) -> str:
    """Remove line comments and string contents before matching code tokens."""
    if "//" in line:
        in_quote = False
        for index in range(len(line) - 1):
            if line[index] == '"' and (index == 0 or line[index - 1] != "\\"):
                in_quote = not in_quote
            elif line[index : index + 2] == "//" and not in_quote:
                line = line[:index]
                break
    line = re.sub(r"/\*.*?\*/", "", line)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', line).strip()


def _finding(
    line: int,
    vuln_type: str,
    details: str,
    *,
    confidence: str = "Medium",
) -> dict[str, Any]:
    return {
        "line": line,
        "type": vuln_type,
        "severity": _SEVERITY[vuln_type],
        "details": details,
        "content": details,
        "confidence": confidence,
        "source": "C/C++Rule",
    }


def _char_array_sizes(code: str) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for line in code.splitlines():
        for match in _CHAR_ARRAY_DECL_RE.finditer(_strip_cpp_line(line)):
            size = int(match.group("size"))
            if size > 0:
                sizes[match.group("name")] = size
    return sizes


def _destination_name(expression: str) -> str | None:
    match = re.search(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*$", expression.strip())
    if match:
        return match.group(1)
    match = re.search(r"\b([A-Za-z_]\w*)\s*$", expression.strip())
    return match.group(1) if match else None


def _string_literal_length(raw_literal: str) -> int:
    match = re.match(r'(?:u8|u|U|L)?"(?P<body>(?:\\.|[^"\\])*)"$', raw_literal.strip())
    if not match:
        return len(raw_literal)
    body = match.group("body")
    length = 0
    index = 0
    while index < len(body):
        length += 1
        if body[index] != "\\":
            index += 1
            continue
        index += 1
        if index >= len(body):
            break
        if body[index] in {"x", "X"}:
            index += 1
            while index < len(body) and body[index] in "0123456789abcdefABCDEF":
                index += 1
            continue
        if body[index] in "01234567":
            consumed = 0
            while index < len(body) and body[index] in "01234567" and consumed < 3:
                index += 1
                consumed += 1
            continue
        index += 1
    return length


def _safe_strcpy_literal_lines(code: str) -> set[int]:
    sizes = _char_array_sizes(code)
    safe_lines: set[int] = set()
    for line_number, line in enumerate(code.splitlines(), 1):
        match = _STRCPY_LITERAL_RE.search(line)
        if not match:
            continue
        destination = _destination_name(match.group("dest"))
        destination_size = sizes.get(destination or "")
        if destination_size is not None and _string_literal_length(match.group("src")) + 1 <= destination_size:
            safe_lines.add(line_number)
    return safe_lines


def _scan_basic_patterns(code: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        code_only = _strip_cpp_line(line)
        for vuln_type, patterns in _BASIC_PATTERNS.items():
            if any(pattern.search(code_only) for pattern in patterns):
                findings.append(
                    _finding(
                        line_number,
                        vuln_type,
                        f"C/C++: 发现 {vuln_type} 风险 - {line.strip()[:60]}",
                    )
                )
    return findings


def _scan_cin(code: str) -> list[dict[str, Any]]:
    sizes = _char_array_sizes(code)
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        code_only = _strip_cpp_line(line)
        if not _CIN_RE.search(code_only) or "setw" in code_only:
            continue
        for match in _STREAM_EXTRACT_RE.finditer(code_only):
            name = match.group("name")
            size = sizes.get(name)
            if size is not None:
                findings.append(
                    _finding(
                        line_number,
                        "BUFFER_OVERFLOW",
                        f"C/C++: cin 写入固定 char[{size}] 数组 `{name}`，未限制输入长度 - {line.strip()[:60]}",
                        confidence="High",
                    )
                )
                break
    return findings


def _scan_thread_lifecycle(code: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        match = _THREAD_CONTROL_RE.search(_strip_cpp_line(line))
        if match:
            api = match.group("api")
            findings.append(
                _finding(
                    line_number,
                    "THREAD_LIFECYCLE_RISK",
                    f"C/C++: {api} 可能在线程持锁或修改共享状态时强制中断，造成资源泄漏或死锁 - {line.strip()[:60]}",
                )
            )
    return findings


def _scan_assignments_in_conditions(code: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        match = _CONDITION_RE.search(_strip_cpp_line(line))
        if (
            match
            and _ASSIGNMENT_OPERATOR_RE.search(match.group("condition"))
            and not _INTENTIONAL_ASSIGNMENT_SENTINEL_COMPARE_RE.search(match.group("condition"))
        ):
            findings.append(
                _finding(
                    line_number,
                    "ASSIGNMENT_IN_CONDITION",
                    f"C/C++: 条件表达式中出现赋值运算，可能导致状态/权限判断失效 - {line.strip()[:60]}",
                )
            )
    return findings


def _recent_condition(lines: list[str], line_index: int, base: str) -> str | None:
    for previous in range(line_index - 1, max(-1, line_index - 6), -1):
        code_only = _strip_cpp_line(lines[previous])
        if "if" in code_only and base in code_only:
            match = _CONDITION_RE.search(code_only)
            if match:
                return match.group("condition")
    return None


def _guards_inner_pointer(condition: str, base: str, field: str) -> bool:
    normalized = re.sub(r"\s+", "", condition)
    if f"{base}->{field}" in normalized:
        return True
    return bool(
        re.search(
            rf"\b{re.escape(base)}\s*->\s*\w*(?:num|count)\w*\s*>\s*0\b",
            condition,
            re.IGNORECASE,
        )
    )


def _scan_nested_pointer_dereferences(code: str) -> list[dict[str, Any]]:
    lines = code.splitlines()
    findings: list[dict[str, Any]] = []
    for line_index, line in enumerate(lines):
        code_only = _strip_cpp_line(line)
        for match in _NESTED_POINTER_RE.finditer(code_only):
            base = match.group("base")
            field = match.group("field")
            condition = _recent_condition(lines, line_index, base)
            if not condition or _guards_inner_pointer(condition, base, field):
                continue
            if not _SHALLOW_GUARD_RE.search(f"if({condition})"):
                continue
            findings.append(
                _finding(
                    line_index + 1,
                    "NULL_DEREFERENCE",
                    (
                        f"C/C++: 只检查 `{base}` 后继续解引用 `{base}->{field}`，"
                        f"`{field}` 为空时可能崩溃 - {line.strip()[:60]}"
                    ),
                )
            )
            break
    return findings


def _scan_critical_section_mismatches(code: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    stack: list[tuple[str, int]] = []
    for line_number, line in enumerate(code.splitlines(), 1):
        code_only = _strip_cpp_line(line)
        enter = _CRITICAL_ENTER_RE.search(code_only)
        if enter:
            stack.append((enter.group("name"), line_number))
            continue
        leave = _CRITICAL_LEAVE_RE.search(code_only)
        if not leave or not stack:
            continue
        leave_name = leave.group("name")
        enter_name, enter_line = stack[-1]
        if leave_name == enter_name:
            stack.pop()
            continue
        findings.append(
            _finding(
                line_number,
                "LOCK_MISMATCH",
                (
                    f"C/C++: 第 {enter_line} 行进入 `{enter_name}`，但这里释放 `{leave_name}`，"
                    f"可能导致临界区未释放或死锁 - {line.strip()[:60]}"
                ),
            )
        )
        stack.clear()
    return findings


def _deduplicate(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    by_key: dict[tuple[int, str], dict[str, Any]] = {}
    for finding in findings:
        key = (int(finding.get("line", 0) or 0), str(finding.get("type", "")))
        existing = by_key.get(key)
        if existing is None or severity_order.get(str(finding.get("severity", "")), 0) > severity_order.get(
            str(existing.get("severity", "")), 0
        ):
            by_key[key] = finding
    return sorted(by_key.values(), key=lambda item: int(item.get("line", 0) or 0))


def enhance_c_cpp_findings(code: str, findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add focused contextual checks and apply C/C++ false-positive filters."""
    combined = [
        *findings,
        *_scan_cin(code),
        *_scan_thread_lifecycle(code),
        *_scan_assignments_in_conditions(code),
        *_scan_nested_pointer_dereferences(code),
        *_scan_critical_section_mismatches(code),
    ]
    safe_strcpy_lines = _safe_strcpy_literal_lines(code)
    filtered = [
        finding
        for finding in combined
        if not (
            finding.get("type") == "BUFFER_OVERFLOW"
            and int(finding.get("line", 0) or 0) in safe_strcpy_lines
            and "strcpy" in str(finding.get("details", finding.get("content", "")))
        )
    ]
    return _deduplicate(filtered)


def analyze_c_cpp_source(code: str) -> list[dict[str, Any]]:
    """Analyze C/C++ using the maintained partial-support rule set."""
    return enhance_c_cpp_findings(code, _scan_basic_patterns(code))


__all__ = ["analyze_c_cpp_source", "enhance_c_cpp_findings"]
