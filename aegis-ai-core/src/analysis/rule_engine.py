"""
rule_engine.py - 规则引擎统一入口

设计目标：
- 提供统一的规则注册表（Rule Registry）；
- 为不同语言返回默认规则集合；
- 暴露 analyze_python / analyze_javascript / analyze_php 便捷函数，
  供 ProjectScanner、LSP Server、FastAPI 服务层统一调用。

已注册规则（共 18 条 AST + 8 条 PHP AST + Regex 补充）：
- Python: RCE、SQL 注入、XSS、路径遍历、硬编码凭证、反序列化、SSRF（含通用正则）
- JavaScript/TypeScript: RCE、SQL 注入、XSS、路径遍历、硬编码凭证、反序列化、NoSQL 注入、SSRF
- PHP: SQL 注入、RCE、XSS、开放重定向、路径遍历、反序列化、NoSQL 注入、硬编码凭证（AST 精确层 + Regex 补充层）
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, cast

from .analyzers.go_analyzer import GoAnalyzer
from .analyzers.java_analyzer import JavaAnalyzer
from .analyzers.javascript_analyzer import JavaScriptAnalyzer
from .analyzers.php_analyzer import PhpAnalyzer
from .analyzers.python_analyzer import PythonAnalyzer
from .base import SecurityRule
from .dsl import load_dsl_rules_for_language
from .rules import (
    GoDeserializationAstRule,
    GoHardcodedCredentialsAstRule,
    GoNoSQLInjectionAstRule,
    GoOpenRedirectAstRule,
    GoPathTraversalAstRule,
    GoRCEAstRule,
    GoSQLInjectionAstRule,
    GoXSSAstRule,
    JavaDeserializationAstRule,
    JavaHardcodedCredentialsAstRule,
    JavaNoSQLInjectionAstRule,
    JavaOpenRedirectAstRule,
    JavaPathTraversalAstRule,
    JavaRCEAstRule,
    JavaScriptDeserializationAstRule,
    JavaScriptHardcodedCredentialsAstRule,
    JavaScriptNoSQLInjectionAstRule,
    JavaScriptOpenRedirectAstRule,
    JavaScriptPathTraversalAstRule,
    JavaScriptRCEAstRule,
    JavaScriptSQLInjectionAstRule,
    JavaScriptSSRFAstRule,
    JavaScriptXSSAstRule,
    JavaSQLInjectionAstRule,
    JavaXSSAstRule,
    PhpDeserializationAstRule,
    PhpHardcodedCredentialsAstRule,
    PhpNoSQLInjectionAstRule,
    PhpOpenRedirectAstRule,
    PhpOpenRedirectRule,
    PhpPathTraversalAstRule,
    PhpRCEAstRule,
    PhpRCERule,  # deprecated: kept for backward compat
    PhpSQLInjectionAstRule,
    PhpSQLInjectionRule,  # deprecated: kept for backward compat
    PhpXSSAstRule,
    PhpXSSRule,  # deprecated: kept for backward compat
    PythonDeserializationAstRule,
    PythonHardcodedCredentialsAstRule,
    PythonNoSQLInjectionAstRule,
    PythonOpenRedirectAstRule,
    PythonPathTraversalAstRule,
    PythonRCEAstRule,
    PythonSQLInjectionAstRule,
    PythonSSRFAstRule,
    PythonXSSAstRule,
    SQLInjectionRegexRule,
)

logger = logging.getLogger(__name__)


_PHP_RCE_SINK_CALL_RE = re.compile(
    r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
    re.IGNORECASE,
)
_PHP_SUPERGLOBAL_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", re.IGNORECASE)
_PHP_HIGH_RISK_SQL_SOURCE_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[", re.IGNORECASE)
_PHP_VAR_RE = re.compile(r"\$([A-Za-z_]\w*)")
_PHP_ASSIGN_RE = re.compile(r"^\s*\$(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<expr>.+?)\s*;?\s*$")
_PHP_LITERAL_EXPR_PART = r"""(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"|\d+|__DIR__|__FILE__)"""
_PHP_LITERAL_COMMAND_EXPR_RE = re.compile(
    rf"^\s*{_PHP_LITERAL_EXPR_PART}(?:\s*\.\s*{_PHP_LITERAL_EXPR_PART})*\s*$",
    re.IGNORECASE,
)
_PHP_SETUP_SCRIPT_PREFIXES = (
    "setup",
    "install",
    "migrate",
    "upgrade",
    "seed",
    "bootstrap",
    "fixture",
    "deploy",
    "init",
)
_PHP_SHELL_META_RE = re.compile(r"[|&;`<>]")
_PHP_REGEX_NEARLINE_DEDUPE_TYPES = frozenset(
    {
        "SQL_INJECTION",
        "RCE_COMMAND_EXEC",
        "XSS_RISK",
        "PATH_TRAVERSAL",
        "OPEN_REDIRECT",
        "DESERIALIZATION",
    }
)
_PHP_AST_NEARLINE_DEDUPE_TYPES = frozenset(
    {
        "SQL_INJECTION",
        "RCE_COMMAND_EXEC",
        "XSS_RISK",
        "PATH_TRAVERSAL",
        "OPEN_REDIRECT",
        "DESERIALIZATION",
    }
)
_JS_NEARLINE_DEDUPE_TYPES = frozenset({"XSS_RISK"})


def _extract_first_php_call_argument(raw_line: str) -> str | None:
    """
    从 `system(...)` / `shell_exec(...)` 等调用中提取第一个参数表达式。

    仅用于 Regex 补充层 FP 过滤，不做完整 PHP 语法解析。
    """
    sink_match = _PHP_RCE_SINK_CALL_RE.search(raw_line)
    if sink_match is None:
        return None

    start = sink_match.end()
    in_single_quote = False
    in_double_quote = False
    escaped = False
    nested_parentheses = 0
    idx = start

    while idx < len(raw_line):
        ch = raw_line[idx]

        if escaped:
            escaped = False
            idx += 1
            continue
        if ch == "\\" and (in_single_quote or in_double_quote):
            escaped = True
            idx += 1
            continue

        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            idx += 1
            continue
        if ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            idx += 1
            continue

        if in_single_quote or in_double_quote:
            idx += 1
            continue

        if ch == "(":
            nested_parentheses += 1
        elif ch == ")":
            if nested_parentheses == 0:
                return raw_line[start:idx].strip()
            nested_parentheses -= 1
        elif ch == "," and nested_parentheses == 0:
            return raw_line[start:idx].strip()

        idx += 1

    return None


def _is_setup_like_php_file(path: Path) -> bool:
    """判断是否为安装/初始化类脚本（通常为低风险运维命令场景）。"""
    basename = path.name.lower()
    return any(basename.startswith(prefix) or basename == f"{prefix}.php" for prefix in _PHP_SETUP_SCRIPT_PREFIXES)


def _php_regex_sqli_is_numeric_guarded(lines: list[str], line: int) -> bool:
    """
    Filter PHP regex SQLi hits where the only high-risk variables in the SQL
    text are constrained by a digit-only guard before the query is reachable.
    """
    line_idx = line - 1
    if line_idx < 0 or line_idx >= len(lines):
        return False

    raw_line = lines[line_idx]
    if not re.search(r"\b(?:SELECT|UPDATE|INSERT|DELETE|REPLACE|WHERE|FROM|INTO)\b", raw_line, re.IGNORECASE):
        return False

    vars_in_sql = set(_PHP_VAR_RE.findall(raw_line))
    if not vars_in_sql:
        return False

    high_risk_vars = [var for var in vars_in_sql if _php_var_has_high_risk_source(lines, var, line_idx)]
    if not high_risk_vars:
        return False

    return all(_php_var_is_numeric_guarded(lines, var, line_idx) for var in high_risk_vars)


def _php_var_has_high_risk_source(lines: list[str], var_name: str, before_idx: int, depth: int = 0) -> bool:
    if depth > 3:
        return False

    assignment = _php_latest_assignment(lines, var_name, before_idx)
    if assignment is None:
        return False

    _, expr = assignment
    if _PHP_HIGH_RISK_SQL_SOURCE_RE.search(expr):
        return True

    for inner in _PHP_VAR_RE.findall(expr):
        if inner != var_name and _php_var_has_high_risk_source(lines, inner, before_idx, depth + 1):
            return True
    return False


def _php_var_is_numeric_guarded(lines: list[str], var_name: str, sink_idx: int) -> bool:
    assignment = _php_latest_assignment(lines, var_name, sink_idx)
    assignment_idx = assignment[0] if assignment is not None else sink_idx
    assignment_expr = assignment[1] if assignment is not None else ""

    if re.search(r"^\s*(?:\(?\s*(?:int|integer|float|double)\s*\)?|intval|floatval|abs)\s*\(", assignment_expr):
        return True

    guarded_exprs = {f"${var_name}"}
    if assignment_expr:
        guarded_exprs.add(assignment_expr)

    return _php_has_numeric_guard_for_exprs(lines, guarded_exprs, assignment_idx, sink_idx)


def _php_has_numeric_guard_for_exprs(
    lines: list[str],
    exprs: set[str],
    assignment_idx: int,
    sink_idx: int,
) -> bool:
    normalized_exprs = {_php_normalize_expr(expr) for expr in exprs if expr}
    if not normalized_exprs:
        return False

    for guard_idx in range(0, min(sink_idx + 1, len(lines))):
        condition = _php_extract_if_condition(lines[guard_idx])
        if not condition:
            continue
        guarded = {
            _php_normalize_expr(expr)
            for expr in _php_numeric_guard_exprs(condition)
            if _php_normalize_expr(expr) in normalized_exprs
        }
        if not guarded:
            continue

        if _php_is_negative_numeric_guard(condition):
            if _php_else_block_contains_lines(lines, guard_idx, {assignment_idx, sink_idx}):
                return True
            if _php_guard_failure_block_exits(lines, guard_idx) and guard_idx < assignment_idx <= sink_idx:
                return True
        elif _php_block_contains_lines(lines, guard_idx, {assignment_idx, sink_idx}):
            return True

    return False


def _php_latest_assignment(lines: list[str], var_name: str, before_idx: int) -> tuple[int, str] | None:
    for idx in range(min(before_idx - 1, len(lines) - 1), -1, -1):
        match = _PHP_ASSIGN_RE.match(lines[idx].strip())
        if match and match.group("var") == var_name:
            return idx, match.group("expr").strip()
    return None


def _php_extract_if_condition(line: str) -> str | None:
    match = re.search(r"\bif\s*\((.*)\)", line)
    return match.group(1) if match is not None else None


def _php_numeric_guard_exprs(condition: str) -> list[str]:
    result: list[str] = []
    for match in re.finditer(
        r"preg_match\s*\(\s*(['\"])(?P<pattern>.*?)(?<!\\)\1\s*,\s*(?P<expr>[^,)]+)",
        condition,
        re.IGNORECASE,
    ):
        if _php_is_digit_only_regex(match.group("pattern")):
            result.append(match.group("expr").strip())

    for match in re.finditer(r"\b(?:ctype_digit|is_numeric)\s*\(\s*(?P<expr>[^)]+)\)", condition, re.IGNORECASE):
        result.append(match.group("expr").strip())

    for match in re.finditer(
        r"\bfilter_var\s*\(\s*(?P<expr>[^,]+)\s*,\s*FILTER_VALIDATE_(?:INT|FLOAT)\b",
        condition,
        re.IGNORECASE,
    ):
        result.append(match.group("expr").strip())

    return result


def _php_is_digit_only_regex(pattern: str) -> bool:
    stripped = pattern.strip()
    if stripped.startswith("/") and stripped.count("/") >= 2:
        stripped = stripped[1 : stripped.rfind("/")]
    normalized = re.sub(r"\s+", "", stripped.replace("\\\\d", r"\d").replace("\\d", r"\d"))
    return normalized in {r"^\d+$", "^[0-9]+$", "^[[:digit:]]+$"}


def _php_is_negative_numeric_guard(condition: str) -> bool:
    if re.search(r"!\s*(?:preg_match|ctype_digit|is_numeric|filter_var)\s*\(", condition, re.IGNORECASE):
        return True
    return (
        re.search(
            r"(?:preg_match|ctype_digit|is_numeric|filter_var)\s*\([^)]*\)\s*(?:={2,3}|!==?)\s*(?:false|0)",
            condition,
            re.IGNORECASE,
        )
        is not None
    )


def _php_normalize_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr).replace('"', "'")


def _php_else_block_contains_lines(lines: list[str], guard_idx: int, target_indices: set[int]) -> bool:
    guard_end = _php_find_block_end(lines, guard_idx)
    if guard_end is None:
        return False
    else_idx = _php_find_else_open_line(lines, guard_end)
    if else_idx is None:
        return False
    return _php_block_contains_lines(lines, else_idx, target_indices)


def _php_guard_failure_block_exits(lines: list[str], guard_idx: int) -> bool:
    guard_end = _php_find_block_end(lines, guard_idx)
    if guard_end is None:
        return False
    block_text = "\n".join(lines[guard_idx : guard_end + 1])
    return re.search(r"\b(?:return|exit|die|throw)\b", block_text, re.IGNORECASE) is not None


def _php_block_contains_lines(lines: list[str], open_idx: int, target_indices: set[int]) -> bool:
    block_end = _php_find_block_end(lines, open_idx)
    if block_end is None:
        return False
    return all(open_idx <= target_idx <= block_end for target_idx in target_indices)


def _php_find_block_end(lines: list[str], open_idx: int) -> int | None:
    depth = 0
    saw_open = False
    for idx in range(open_idx, len(lines)):
        for ch in lines[idx]:
            if ch == "{":
                depth += 1
                saw_open = True
            elif ch == "}" and saw_open:
                depth -= 1
                if depth == 0:
                    return idx
    return None


def _php_find_else_open_line(lines: list[str], guard_end_idx: int) -> int | None:
    for idx in range(guard_end_idx, min(guard_end_idx + 4, len(lines))):
        line = lines[idx].strip()
        if not line:
            continue
        if "else" not in line:
            if idx == guard_end_idx:
                continue
            return None
        if "{" in line:
            return idx
        for next_idx in range(idx + 1, min(idx + 3, len(lines))):
            if lines[next_idx].strip().startswith("{"):
                return next_idx
        return None
    return None


def _dedupe_php_nearby_findings(findings: list[dict]) -> list[dict]:
    """
    PHP 结果后处理：合并 AST/Regex 在近邻行重复产生的同类 finding。

    规则：同 (type, rule_id/source, details) 在 4 行内仅保留首条。
    """
    deduped: list[dict] = []
    last_line_by_key: dict[tuple[str, str, str], int] = {}

    for finding in sorted(findings, key=lambda item: int(item.get("line", 0))):
        vuln_type = finding.get("type", "")
        if vuln_type not in _PHP_AST_NEARLINE_DEDUPE_TYPES:
            deduped.append(finding)
            continue

        line = int(finding.get("line", 0))
        identity = str(finding.get("rule_id") or finding.get("source") or "")
        details = str(finding.get("details") or "")
        key = (vuln_type, identity, details)
        previous_line = last_line_by_key.get(key)

        if previous_line is not None and abs(line - previous_line) <= 4:
            continue

        last_line_by_key[key] = line
        deduped.append(finding)

    # 恢复原有行序，便于下游稳定展示
    return sorted(deduped, key=lambda item: int(item.get("line", 0)))


def _dedupe_nearby_findings(
    findings: list[dict],
    target_types: set[str] | frozenset[str],
    window: int,
) -> list[dict]:
    """
    通用近邻去重：同 (type, rule_id/source, details) 在 window 行内仅保留首条。
    """
    deduped: list[dict] = []
    last_line_by_key: dict[tuple[str, str, str], int] = {}

    for finding in sorted(findings, key=lambda item: int(item.get("line", 0))):
        vuln_type = str(finding.get("type", ""))
        if vuln_type not in target_types:
            deduped.append(finding)
            continue

        line = int(finding.get("line", 0))
        identity = str(finding.get("rule_id") or finding.get("source") or "")
        details = str(finding.get("details") or "")
        key = (vuln_type, identity, details)
        previous_line = last_line_by_key.get(key)
        if previous_line is not None and abs(line - previous_line) <= window:
            continue

        last_line_by_key[key] = line
        deduped.append(finding)

    return sorted(deduped, key=lambda item: int(item.get("line", 0)))


def get_default_rules_for_language(
    language: str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[SecurityRule]:
    """
    根据语言返回默认规则集合。

    Args:
        language: 语言标识符（"python"、"javascript"、"typescript"、"php"等）。
        include_dsl: 是否加载 DSL 规则（用于 AST vs DSL 对比实验）。

    Returns:
        对应语言的 SecurityRule 实例列表。PHP 规则通过 analyze_php() 调用，
        此处返回实例以便外部查询已注册规则。
    """
    language = language.lower()

    if language == "python":
        rules: list[SecurityRule] = [
            PythonRCEAstRule(),
            SQLInjectionRegexRule(),
            PythonSQLInjectionAstRule(),
            PythonXSSAstRule(),
            PythonPathTraversalAstRule(),
            PythonHardcodedCredentialsAstRule(),
            PythonDeserializationAstRule(),
            PythonNoSQLInjectionAstRule(),
            PythonOpenRedirectAstRule(),
            PythonSSRFAstRule(),
        ]
        if include_dsl:
            rules.extend(
                load_dsl_rules_for_language(
                    "python",
                    extra_dirs=extra_rule_dirs,
                    allowed_root=rules_allowed_root,
                )
            )
        return rules

    if language in ("javascript", "typescript"):
        # 污点图由 JavaScriptAnalyzer 内 TaintAnalyzer.analyze_tree 独家构建，规则通过 context.taint_graph 查询
        rules = [
            JavaScriptRCEAstRule(),
            JavaScriptSQLInjectionAstRule(),
            JavaScriptXSSAstRule(),
            JavaScriptPathTraversalAstRule(),
            JavaScriptHardcodedCredentialsAstRule(),
            JavaScriptDeserializationAstRule(),
            JavaScriptNoSQLInjectionAstRule(),
            JavaScriptOpenRedirectAstRule(),
            JavaScriptSSRFAstRule(),
        ]
        if include_dsl:
            rules.extend(
                load_dsl_rules_for_language(
                    language,
                    extra_dirs=extra_rule_dirs,
                    allowed_root=rules_allowed_root,
                )
            )
        return rules

    if language == "php":
        return [
            PhpSQLInjectionAstRule(),
            PhpRCEAstRule(),
            PhpXSSAstRule(),
            PhpOpenRedirectAstRule(),
            PhpPathTraversalAstRule(),
            PhpDeserializationAstRule(),
            PhpNoSQLInjectionAstRule(),
            PhpHardcodedCredentialsAstRule(),
        ]

    if language == "java":
        return [
            JavaRCEAstRule(),
            JavaSQLInjectionAstRule(),
            JavaXSSAstRule(),
            JavaPathTraversalAstRule(),
            JavaHardcodedCredentialsAstRule(),
            JavaDeserializationAstRule(),
            JavaNoSQLInjectionAstRule(),
            JavaOpenRedirectAstRule(),
        ]

    if language == "go":
        rules = [
            GoRCEAstRule(),
            GoSQLInjectionAstRule(),
            GoXSSAstRule(),
            GoPathTraversalAstRule(),
            GoHardcodedCredentialsAstRule(),
            GoDeserializationAstRule(),
            GoNoSQLInjectionAstRule(),
            GoOpenRedirectAstRule(),
        ]
        if include_dsl:
            rules.extend(
                load_dsl_rules_for_language(
                    "go",
                    extra_dirs=extra_rule_dirs,
                    allowed_root=rules_allowed_root,
                )
            )
        return rules

    return []


_LANGUAGE_ANALYZER_MAP: dict[str, type[Any]] = {
    "python": PythonAnalyzer,
    "javascript": JavaScriptAnalyzer,
    "typescript": JavaScriptAnalyzer,
    "java": JavaAnalyzer,
    "go": GoAnalyzer,
    "php": PhpAnalyzer,
}


def _analyze_with(
    language: str,
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[dict]:
    """统一入口：按语言选择分析器并执行分析，分析器失败时抛出 RuntimeError。"""
    from src.scanner.baseline import filter_suppressed_findings

    path = Path(file_path)
    rules = get_default_rules_for_language(
        language,
        include_dsl=include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
    )
    analyzer_cls = _LANGUAGE_ANALYZER_MAP.get(language)
    if analyzer_cls is None:
        return []
    analyzer = analyzer_cls(rules)
    try:
        if language in ("javascript", "typescript"):
            raw = analyzer.analyze(code, path, language=language)
        else:
            raw = analyzer.analyze(code, path)
        filtered = cast(list[dict[str, Any]], filter_suppressed_findings(raw, code))
        if language in ("javascript", "typescript"):
            filtered = _dedupe_nearby_findings(filtered, target_types=_JS_NEARLINE_DEDUPE_TYPES, window=6)
        return filtered
    except (RuntimeError, ValueError) as exc:
        logger.exception("_analyze_with(%s) failed for %s", language, path)
        raise RuntimeError(f"{language} analyzer failed for {path}: {exc}") from exc


def analyze_python(
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 Python 文件。分析器失败时抛出 RuntimeError。"""
    return _analyze_with(
        "python",
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
    )


def analyze_javascript(
    code: str,
    file_path: Path | str,
    language: str = "javascript",
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 JavaScript/TypeScript 文件。分析器失败时抛出 RuntimeError。"""
    return _analyze_with(
        language,
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
    )


def analyze_java(
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 Java 文件。分析器失败时抛出 RuntimeError。"""
    return _analyze_with(
        "java",
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
    )


def analyze_go(
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 Go 文件。分析器失败时抛出 RuntimeError。"""
    return _analyze_with(
        "go",
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
    )


def _merge_basic_findings(primary_findings: list[dict], regex_findings: list[dict]) -> list[dict]:
    """Merge legacy multi-language and regex findings by line/type."""
    findings_by_key: dict[tuple[int, str], dict[str, Any]] = {}
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    def _normalized(finding: dict, source: str) -> dict[str, Any]:
        details = finding.get("details", finding.get("content", ""))
        return {
            "line": finding.get("line", 0),
            "type": finding.get("type", "Unknown"),
            "severity": finding.get("severity", "Medium"),
            "details": details,
            "source": finding.get("source", source),
            **{
                k: v
                for k, v in finding.items()
                if k not in ("line", "type", "severity", "details", "content", "source")
            },
        }

    for finding in primary_findings:
        normalized = _normalized(finding, "AST+Regex")
        key = (int(normalized.get("line", 0) or 0), str(normalized.get("type", "")))
        findings_by_key[key] = normalized

    for finding in regex_findings:
        normalized = _normalized(finding, "Regex")
        key = (int(normalized.get("line", 0) or 0), str(normalized.get("type", "")))
        existing = findings_by_key.get(key)
        if existing is None:
            findings_by_key[key] = normalized
            continue
        existing_severity = severity_order.get(str(existing.get("severity", "")), 0)
        new_severity = severity_order.get(str(normalized.get("severity", "")), 0)
        if new_severity > existing_severity:
            findings_by_key[key] = normalized

    return sorted(findings_by_key.values(), key=lambda item: int(item.get("line", 0) or 0))


def analyze_c_cpp(code: str, file_path: Path | str) -> list[dict]:
    """
    Analyze C/C++ files with the shared basic support path.

    This intentionally remains a lightweight fallback, not full C/C++ AST/taint support.
    """
    from .multi_language_ast import analyze_code_multi_language
    from .security_rules import filter_cpp_findings, scan_code_locally

    path = Path(file_path)
    try:
        multi_language_findings = analyze_code_multi_language(code, file_path=str(path))
    except (RuntimeError, ValueError):
        logger.exception("analyze_c_cpp (multi-language) failed for %s", path)
        multi_language_findings = []

    try:
        regex_findings = scan_code_locally(code, file_path=str(path))
    except (RuntimeError, ValueError):
        logger.exception("analyze_c_cpp (regex) failed for %s", path)
        regex_findings = []

    return cast(
        list[dict],
        filter_cpp_findings(code, _merge_basic_findings(multi_language_findings, regex_findings)),
    )


def analyze_php(code: str, file_path: Path | str) -> list[dict]:
    """
    分析单个 PHP 文件。

    双引擎策略：
    1. **AST 精确层**（PhpSQLInjectionAstRule 等 8 条 Tree-sitter AST 规则）：
       通过 PhpAnalyzer 驱动 visit() 生命周期，产出高置信度 finding。
    2. **Regex 补充层**（scan_code_locally）：宽泛正则，兜底覆盖 AST
       尚未追踪到的场景。

    去重规则：若 AST 层在某行已报某类型，则丢弃 Regex 在同行同类型的报告，
    避免重复诊断展示给用户。

    返回格式与 analyze_python / analyze_javascript 统一。
    """
    from .security_rules import scan_code_locally

    path = Path(file_path)

    # ── 1. AST 精确层 ──
    results = _analyze_with("php", code, path)
    ast_covered: set[tuple[int, str]] = set()
    ast_lines_by_type: dict[str, list[int]] = {}
    for f in results:
        ast_covered.add((f["line"], f["type"]))
        ast_lines_by_type.setdefault(f["type"], []).append(f["line"])

    # ── 2. Regex 补充层 ──
    try:
        raw_findings = scan_code_locally(code, file_path=str(path))
    except (RuntimeError, ValueError):
        logger.exception("analyze_php (regex) failed for %s", path)
        raw_findings = []

    lines_of_code = code.split("\n")
    for f in raw_findings:
        line = f.get("line", 1)
        vuln_type = f.get("type", "UNKNOWN")
        if (line, vuln_type) in ast_covered:
            continue
        if vuln_type in _PHP_REGEX_NEARLINE_DEDUPE_TYPES:
            near_ast_lines = ast_lines_by_type.get(vuln_type, [])
            if any(abs(line - ast_line) <= 3 for ast_line in near_ast_lines):
                continue
        # 正则层：unserialize(..., allowed_classes) 视为安全，不补充报告
        if vuln_type == "DESERIALIZATION" and 1 <= line <= len(lines_of_code):
            raw_line = lines_of_code[line - 1]
            if "allowed_classes" in raw_line:
                continue
        if vuln_type == "SQL_INJECTION" and 1 <= line <= len(lines_of_code):
            if _php_regex_sqli_is_numeric_guarded(lines_of_code, int(line)):
                continue
        # 正则层：PHP RCE 仅当参数为字面量（无 $var / $_GET 等）时不报告，避免常量命令误报
        if vuln_type == "RCE_COMMAND_EXEC" and 1 <= line <= len(lines_of_code):
            raw_line = lines_of_code[line - 1]
            first_arg = _extract_first_php_call_argument(raw_line)
            if (
                first_arg is not None
                and _PHP_SUPERGLOBAL_RE.search(first_arg) is None
                and _PHP_LITERAL_COMMAND_EXPR_RE.fullmatch(first_arg)
            ):
                # 常量命令默认视为低风险，不补充报告；
                # 但复杂 shell 管道命令仍保留，除非在 setup/install 等脚本中。
                if _is_setup_like_php_file(path) or _PHP_SHELL_META_RE.search(first_arg) is None:
                    continue
        results.append(
            {
                "type": vuln_type,
                "severity": f.get("severity", "Medium"),
                "line": line,
                "start_line": line,
                "end_line": line,
                "start_character": 0,
                "end_character": 999,
                "details": f.get("content", ""),
                "confidence": f.get("confidence", "medium"),
                "source": "PHP-Regex",
            }
        )

    return _dedupe_php_nearby_findings(results)


__all__ = [
    "get_default_rules_for_language",
    "analyze_python",
    "analyze_javascript",
    "analyze_java",
    "analyze_go",
    "analyze_php",
    "analyze_c_cpp",
    # Deprecated: old PHP line-level rules, kept for backward compat
    "PhpSQLInjectionRule",
    "PhpRCERule",
    "PhpXSSRule",
    "PhpOpenRedirectRule",
    # Backward-compatible re-exports from deprecated modules
    "analyze_code_ast",
    "scan_code_locally",
    "VULN_SIGNATURES",
    "VULN_SEVERITY",
]

# ---------------------------------------------------------------------------
# Backward-compatible re-exports from deprecated modules
# ---------------------------------------------------------------------------
from .ast_analyzer import analyze_code_ast as analyze_code_ast  # noqa: E402, F401
from .security_rules import VULN_SEVERITY as VULN_SEVERITY  # noqa: E402, F401
from .security_rules import VULN_SIGNATURES as VULN_SIGNATURES  # noqa: E402, F401
from .security_rules import scan_code_locally as scan_code_locally  # noqa: E402, F401
