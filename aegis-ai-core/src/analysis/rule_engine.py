"""
rule_engine.py - 规则引擎统一入口

设计目标：
- 提供统一的规则注册表（Rule Registry）；
- 为不同语言返回默认规则集合；
- 暴露 analyze_python / analyze_javascript / analyze_php 便捷函数，
  供 ProjectScanner、LSP Server、FastAPI 服务层统一调用。

已注册规则：
- Python: RCE、SQL 注入、XSS、路径遍历、硬编码凭证、反序列化、开放重定向、NoSQL 注入、SSRF
- JavaScript/TypeScript: RCE、SQL 注入、XSS、路径遍历、硬编码凭证、反序列化、开放重定向、NoSQL 注入、SSRF
- PHP: SQL 注入、RCE、XSS、开放重定向、路径遍历、反序列化、NoSQL 注入、
  硬编码凭证、SSRF，生产入口全部由 AST/污点规则负责。
- Java/Go: RCE、SQL 注入、XSS、路径遍历、硬编码凭证、反序列化、开放重定向、NoSQL 注入、SSRF
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeAlias, cast

from .analyzers.go_analyzer import GoAnalyzer
from .analyzers.java_analyzer import JavaAnalyzer
from .analyzers.javascript_analyzer import JavaScriptAnalyzer
from .analyzers.php_analyzer import PhpAnalyzer
from .analyzers.python_analyzer import PythonAnalyzer
from .base import SecurityRule
from .dsl import load_dsl_rules_for_language
from .dsl.rule_schema import DslRule
from .languages import AnalysisLanguage, normalize_analysis_language
from .rules import (
    GoDeserializationAstRule,
    GoHardcodedCredentialsAstRule,
    GoNoSQLInjectionAstRule,
    GoOpenRedirectAstRule,
    GoPathTraversalAstRule,
    GoRCEAstRule,
    GoSQLInjectionAstRule,
    GoSSRFAstRule,
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
    JavaSSRFAstRule,
    JavaXSSAstRule,
    PhpDeserializationAstRule,
    PhpHardcodedCredentialsAstRule,
    PhpNoSQLInjectionAstRule,
    PhpOpenRedirectAstRule,
    PhpPathTraversalAstRule,
    PhpRCEAstRule,
    PhpSQLInjectionAstRule,
    PhpSSRFAstRule,
    PhpXSSAstRule,
    PythonDeserializationAstRule,
    PythonHardcodedCredentialsAstRule,
    PythonNoSQLInjectionAstRule,
    PythonOpenRedirectAstRule,
    PythonPathTraversalAstRule,
    PythonRCEAstRule,
    PythonSQLInjectionAstRule,
    PythonSSRFAstRule,
    PythonXSSAstRule,
)

logger = logging.getLogger(__name__)

RuleDefinitionMap: TypeAlias = dict[str, tuple[DslRule, ...]]
RuleFactory: TypeAlias = Callable[[], SecurityRule]


_PHP_AST_NEARLINE_DEDUPE_TYPES = frozenset(
    {
        "SQL_INJECTION",
        "PATH_TRAVERSAL",
        "OPEN_REDIRECT",
        "DESERIALIZATION",
    }
)
_JS_NEARLINE_DEDUPE_TYPES = frozenset({"XSS_RISK"})


def _dedupe_php_nearby_findings(findings: list[dict]) -> list[dict]:
    """
    PHP 结果后处理：合并 AST 在近邻行重复产生的同类 finding。

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
    dsl_rule_definitions: RuleDefinitionMap | None = None,
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
    normalized = normalize_analysis_language(language)
    if normalized is None:
        return []

    rule_factories = _DEFAULT_RULE_FACTORIES.get(normalized)
    if rule_factories is None:
        return []

    rules: list[SecurityRule] = [factory() for factory in rule_factories]
    if include_dsl:
        rules.extend(
            load_dsl_rules_for_language(
                normalized,
                extra_dirs=extra_rule_dirs,
                allowed_root=rules_allowed_root,
                preloaded_rules=dsl_rule_definitions.get(normalized, ()) if dsl_rule_definitions is not None else None,
            )
        )
    return rules


_DEFAULT_RULE_FACTORIES: dict[AnalysisLanguage, tuple[RuleFactory, ...]] = {
    "python": (
        PythonRCEAstRule,
        PythonSQLInjectionAstRule,
        PythonXSSAstRule,
        PythonPathTraversalAstRule,
        PythonHardcodedCredentialsAstRule,
        PythonDeserializationAstRule,
        PythonNoSQLInjectionAstRule,
        PythonOpenRedirectAstRule,
        PythonSSRFAstRule,
    ),
    # 污点图由 JavaScriptAnalyzer 内 TaintAnalyzer.analyze_tree 独家构建，规则通过 context.taint_graph 查询。
    "javascript": (
        JavaScriptRCEAstRule,
        JavaScriptSQLInjectionAstRule,
        JavaScriptXSSAstRule,
        JavaScriptPathTraversalAstRule,
        JavaScriptHardcodedCredentialsAstRule,
        JavaScriptDeserializationAstRule,
        JavaScriptNoSQLInjectionAstRule,
        JavaScriptOpenRedirectAstRule,
        JavaScriptSSRFAstRule,
    ),
    "typescript": (
        JavaScriptRCEAstRule,
        JavaScriptSQLInjectionAstRule,
        JavaScriptXSSAstRule,
        JavaScriptPathTraversalAstRule,
        JavaScriptHardcodedCredentialsAstRule,
        JavaScriptDeserializationAstRule,
        JavaScriptNoSQLInjectionAstRule,
        JavaScriptOpenRedirectAstRule,
        JavaScriptSSRFAstRule,
    ),
    "php": (
        PhpSQLInjectionAstRule,
        PhpRCEAstRule,
        PhpXSSAstRule,
        PhpOpenRedirectAstRule,
        PhpPathTraversalAstRule,
        PhpDeserializationAstRule,
        PhpSSRFAstRule,
        PhpNoSQLInjectionAstRule,
        PhpHardcodedCredentialsAstRule,
    ),
    "java": (
        JavaRCEAstRule,
        JavaSQLInjectionAstRule,
        JavaXSSAstRule,
        JavaPathTraversalAstRule,
        JavaHardcodedCredentialsAstRule,
        JavaDeserializationAstRule,
        JavaNoSQLInjectionAstRule,
        JavaOpenRedirectAstRule,
        JavaSSRFAstRule,
    ),
    "go": (
        GoRCEAstRule,
        GoSQLInjectionAstRule,
        GoXSSAstRule,
        GoPathTraversalAstRule,
        GoHardcodedCredentialsAstRule,
        GoDeserializationAstRule,
        GoNoSQLInjectionAstRule,
        GoOpenRedirectAstRule,
        GoSSRFAstRule,
    ),
}


_LANGUAGE_ANALYZER_MAP: dict[AnalysisLanguage, type[Any]] = {
    "python": PythonAnalyzer,
    "javascript": JavaScriptAnalyzer,
    "typescript": JavaScriptAnalyzer,
    "java": JavaAnalyzer,
    "go": GoAnalyzer,
    "php": PhpAnalyzer,
}


def _analyze_with(
    language: AnalysisLanguage,
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
    dsl_rule_definitions: RuleDefinitionMap | None = None,
) -> list[dict]:
    """统一入口：按语言选择分析器并执行分析，分析器失败时抛出 RuntimeError。"""
    from src.scanner.baseline import filter_suppressed_findings

    path = Path(file_path)
    rules = get_default_rules_for_language(
        language,
        include_dsl=include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
        dsl_rule_definitions=dsl_rule_definitions,
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
    dsl_rule_definitions: RuleDefinitionMap | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 Python 文件。分析器失败时抛出 RuntimeError。"""
    return _analyze_with(
        "python",
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
        dsl_rule_definitions=dsl_rule_definitions,
    )


def analyze_javascript(
    code: str,
    file_path: Path | str,
    language: str = "javascript",
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
    dsl_rule_definitions: RuleDefinitionMap | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 JavaScript/TypeScript 文件。分析器失败时抛出 RuntimeError。"""
    normalized = normalize_analysis_language(language) or "javascript"
    if normalized not in {"javascript", "typescript"}:
        normalized = "javascript"
    return _analyze_with(
        normalized,
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
        dsl_rule_definitions=dsl_rule_definitions,
    )


def analyze_java(
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
    dsl_rule_definitions: RuleDefinitionMap | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 Java 文件。分析器失败时抛出 RuntimeError。"""
    return _analyze_with(
        "java",
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
        dsl_rule_definitions=dsl_rule_definitions,
    )


def analyze_go(
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
    dsl_rule_definitions: RuleDefinitionMap | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 Go 文件。分析器失败时抛出 RuntimeError。"""
    return _analyze_with(
        "go",
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
        dsl_rule_definitions=dsl_rule_definitions,
    )


def analyze_c_cpp(code: str, file_path: Path | str) -> list[dict]:
    """
    Analyze C/C++ files with the maintained basic-support rules.

    This intentionally remains lightweight rather than full C/C++ AST/taint
    support, but it no longer dispatches through deprecated analyzers.
    """
    from .analyzers.c_cpp_analyzer import analyze_c_cpp_source

    return cast(list[dict], analyze_c_cpp_source(code))


def analyze_php(
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
    dsl_rule_definitions: RuleDefinitionMap | None = None,
) -> list[dict]:
    """
    分析单个 PHP 文件。

    PHP 生产分析已统一为 Tree-sitter AST 规则与污点分析，不再执行
    legacy 正则补充层。返回格式与其他语言入口一致。
    """
    path = Path(file_path)
    results = _analyze_with(
        "php",
        code,
        path,
        include_dsl=include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
        dsl_rule_definitions=dsl_rule_definitions,
    )
    return _dedupe_php_nearby_findings(results)


def analyze_source(
    code: str,
    file_path: Path | str,
    language: str | None = None,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
    dsl_rule_definitions: RuleDefinitionMap | None = None,
) -> list[dict]:
    """
    Analyze one source file through the canonical production dispatch path.

    Language aliases are normalized centrally and unknown file types return an
    empty result. Compatibility helpers such as ``analyze_python`` remain
    public, but production callers should use this function.
    """
    normalized = normalize_analysis_language(language, file_path)
    if normalized is None:
        return []
    if normalized in {"c", "cpp"}:
        return analyze_c_cpp(code, file_path)

    results = _analyze_with(
        normalized,
        code,
        file_path,
        include_dsl=include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
        dsl_rule_definitions=dsl_rule_definitions,
    )
    if normalized == "php":
        return _dedupe_php_nearby_findings(results)
    return results


__all__ = [
    "get_default_rules_for_language",
    "analyze_python",
    "analyze_javascript",
    "analyze_java",
    "analyze_go",
    "analyze_php",
    "analyze_c_cpp",
    "analyze_source",
]
