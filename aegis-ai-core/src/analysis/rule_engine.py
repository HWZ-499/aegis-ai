"""
rule_engine.py - 规则引擎统一入口

设计目标：
- 提供统一的规则注册表（Rule Registry）；
- 为不同语言返回默认规则集合；
- 暴露 analyze_python / analyze_javascript / analyze_php 便捷函数，
  供 ProjectScanner、LSP Server、FastAPI 服务层统一调用。

已注册规则（共 16 条 + PHP TaintGraph 4 条）：
- Python: RCE、SQL 注入、XSS、路径遍历、硬编码凭证、反序列化（含通用正则）
- JavaScript/TypeScript: RCE、SQL 注入、XSS、路径遍历、硬编码凭证、反序列化、NoSQL 注入
- PHP: SQL 注入、RCE、XSS、开放重定向（TaintGraph 精确层 + Regex 补充层）
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .analyzers.go_analyzer import GoAnalyzer
from .analyzers.java_analyzer import JavaAnalyzer
from .analyzers.javascript_analyzer import JavaScriptAnalyzer
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
    JavaScriptXSSAstRule,
    JavaSQLInjectionAstRule,
    JavaXSSAstRule,
    PhpDeserializationRule,
    PhpHardcodedCredentialsRule,
    PhpNoSQLInjectionRule,
    PhpOpenRedirectRule,
    PhpPathTraversalRule,
    PhpRCERule,
    # PHP TaintGraph 规则（analyze_php 内部延迟导入，此处仅供类型提示）
    PhpSQLInjectionRule,
    PhpXSSRule,
    PythonDeserializationAstRule,
    PythonHardcodedCredentialsAstRule,
    PythonNoSQLInjectionAstRule,
    PythonOpenRedirectAstRule,
    PythonPathTraversalAstRule,
    PythonRCEAstRule,
    PythonSQLInjectionAstRule,
    PythonXSSAstRule,
    SQLInjectionRegexRule,
)

logger = logging.getLogger(__name__)


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
            PhpSQLInjectionRule(),
            PhpRCERule(),
            PhpXSSRule(),
            PhpOpenRedirectRule(),
            PhpPathTraversalRule(),
            PhpDeserializationRule(),
            PhpNoSQLInjectionRule(),
            PhpHardcodedCredentialsRule(),
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
}


def _analyze_with(
    language: str,
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[dict]:
    """统一入口：按语言选择分析器并执行分析，异常时记录日志并返回空列表。"""
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
        return filter_suppressed_findings(raw, code)
    except Exception:
        logger.exception("_analyze_with(%s) failed for %s", language, path)
        return []


def analyze_python(
    code: str,
    file_path: Path | str,
    include_dsl: bool = True,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[dict]:
    """使用新规则引擎分析单个 Python 文件。TDD 10.1：异常时返回空列表。"""
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
    """使用新规则引擎分析单个 JavaScript/TypeScript 文件。TDD 10.1：异常时返回空列表。"""
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
    """使用新规则引擎分析单个 Java 文件。TDD 10.1：异常时返回空列表。"""
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
    """使用新规则引擎分析单个 Go 文件。异常时返回空列表。"""
    return _analyze_with(
        "go",
        code,
        file_path,
        include_dsl,
        extra_rule_dirs=extra_rule_dirs,
        rules_allowed_root=rules_allowed_root,
    )


def analyze_php(code: str, file_path: Path | str) -> list[dict]:
    """
    分析单个 PHP 文件。

    双引擎策略：
    1. **TaintGraph 精确层**（PhpSQLInjectionRule / PhpRCERule / PhpXSSRule /
       PhpOpenRedirectRule）：基于行级赋值链追踪，产出带 taint_source_line /
       related_locations 的高置信度 finding。
    2. **Regex 补充层**（scan_code_locally）：宽泛正则，兜底覆盖 TaintGraph
       尚未追踪到的场景。

    去重规则：若 TaintGraph 在某行已报某类型，则丢弃 Regex 在同行同类型的报告，
    避免重复诊断展示给用户。

    返回格式与 analyze_python / analyze_javascript 统一。
    """
    from .security_rules import scan_code_locally

    path = Path(file_path)
    results: list[dict] = []

    # ── 1. TaintGraph 精确层 ──
    taint_rules = [
        PhpSQLInjectionRule(),
        PhpRCERule(),
        PhpXSSRule(),
        PhpOpenRedirectRule(),
        PhpPathTraversalRule(),
        PhpDeserializationRule(),
        PhpNoSQLInjectionRule(),
        PhpHardcodedCredentialsRule(),
    ]
    taint_covered: set[tuple[int, str]] = set()  # (line, vuln_type)

    for rule in taint_rules:
        try:
            for f in rule.analyze(code, path):
                results.append(f)
                taint_covered.add((f["line"], f["type"]))
        except Exception:
            logger.exception("PHP TaintGraph rule %s failed for %s", type(rule).__name__, path)

    # ── 2. Regex 补充层 ──
    try:
        raw_findings = scan_code_locally(code, file_path=str(path))
    except Exception:
        logger.exception("analyze_php (regex) failed for %s", path)
        raw_findings = []

    lines_of_code = code.split("\n")
    for f in raw_findings:
        line = f.get("line", 1)
        vuln_type = f.get("type", "UNKNOWN")
        if (line, vuln_type) in taint_covered:
            continue
        # 正则层：unserialize(..., allowed_classes) 视为安全，不补充报告
        if vuln_type == "DESERIALIZATION" and 1 <= line <= len(lines_of_code):
            raw_line = lines_of_code[line - 1]
            if "allowed_classes" in raw_line:
                continue
        # 正则层：PHP RCE 仅当参数为字面量（无 $var / $_GET 等）时不报告，避免常量命令误报
        if vuln_type == "RCE_COMMAND_EXEC" and 1 <= line <= len(lines_of_code):
            raw_line = lines_of_code[line - 1]
            if re.search(r"\$(_(?:GET|POST|REQUEST|COOKIE)|\w+)", raw_line) is None and re.search(
                r"\b(system|exec|shell_exec|passthru|popen)\s*\(\s*['\"][^'\"]*['\"]\s*\)",
                raw_line,
                re.IGNORECASE,
            ):
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

    return results


__all__ = [
    "get_default_rules_for_language",
    "analyze_python",
    "analyze_javascript",
    "analyze_java",
    "analyze_go",
    "analyze_php",
    "PhpSQLInjectionRule",
    "PhpRCERule",
    "PhpXSSRule",
    "PhpOpenRedirectRule",
]
