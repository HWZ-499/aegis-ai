"""
php_taint_rules.py - 基于 PhpTaintGraph 的 PHP 安全规则集（已废弃）

.. deprecated::
    本模块中的行级 TaintGraph 规则已被 ``rules/{vuln_type}/php_ast_rule.py``
    中的 Tree-sitter AST 规则替代。rule_engine.analyze_php() 不再调用这些类。
    仅保留导出以维持向后兼容，将在后续版本中移除。

原设计目标：
- 每条规则都产出带完整污点链信息的 finding；
- finding 携带 taint_source_line / taint_var / related_locations，
  LSP 层可直接将 Source 位置映射为 relatedInformation；
- 净化路径降级为 Low 而非跳过，供人工复查。

接口说明（v2.0 重构）：
- 继承 SecurityRule 基类，接入主引擎规则框架；
- 实现 visit(node, context) 接口（兼容 AST 节点遍历模型）；
- 保留 analyze(code, file_path) 接口（向后兼容，供 rule_engine.analyze_php 调用）；
- 在 after_file() 中基于行级 PhpTaintGraph 完成分析（Tree-sitter AST 尚未完整支持 PHP 污点）。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ...base import AnalysisContext, SecurityRule
from ...security_rules import _PHP_SINK_PATTERNS, _PHP_SOURCE_RE, PhpTaintGraph  # noqa: F401

# ─────────────────────────────────────────────────────────────────
# 常量
# ─────────────────────────────────────────────────────────────────

# 各 vuln_type → CWE 编号
_CWE_MAP: dict[str, str] = {
    "SQL_INJECTION": "CWE-89",
    "RCE_COMMAND_EXEC": "CWE-78",
    "XSS_RISK": "CWE-79",
    "OPEN_REDIRECT": "CWE-601",
    "PATH_TRAVERSAL": "CWE-22",
    "DESERIALIZATION": "CWE-502",
    "NOSQL_INJECTION": "CWE-943",
    "HARDCODED_CREDENTIALS": "CWE-798",
}

# Sink 类型过滤表：每个 Rule 只关心自己的 vuln_type
_SQLI_TYPES = frozenset(["SQL_INJECTION"])
_RCE_TYPES = frozenset(["RCE_COMMAND_EXEC"])
_XSS_TYPES = frozenset(["XSS_RISK"])
_REDIR_TYPES = frozenset(["OPEN_REDIRECT"])
_PATH_TRAVERSAL_TYPES = frozenset(["PATH_TRAVERSAL"])
_DESERIALIZATION_TYPES = frozenset(["DESERIALIZATION"])

# 参数化查询识别：第一个字符串参数含占位符，且存在第二个参数
_PARAM_PLACEHOLDER_RE = re.compile(r"""['"][^'"]*(?:\?|%s|%\([\w]+\)s|:\w+)[^'"]*['"]""", re.IGNORECASE)
_PARAM_BIND_RE = re.compile(r"""(execute|query)\s*\([^,]+,[^)]+\)""", re.IGNORECASE)

# htmlspecialchars / htmlentities / strip_tags（XSS 净化判断用）
_HTML_ESCAPE_RE = re.compile(
    r"\b(htmlspecialchars|htmlentities|strip_tags|esc_html|wp_kses)\s*\(",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────
# 基础函数
# ─────────────────────────────────────────────────────────────────


def _make_finding(
    vuln_type: str,
    severity: str,
    line: int,
    file_path: str,
    taint_var: str,
    taint_source_line: int,
    sink_snippet: str,
    confidence: str = "high",
    sanitized: bool = False,
    extra_note: str = "",
) -> dict[str, Any]:
    """
    构造统一格式的 PHP TaintGraph finding。

    携带 ``related_locations``，LSP 层可直接渲染 Source 位置。
    """
    cwe = _CWE_MAP.get(vuln_type, "")
    if sanitized:
        note = "（变量经过净化函数处理，建议人工确认净化是否充分）"
        severity = "Low"
        confidence = "low"
    else:
        note = ""

    if extra_note:
        note = f"{extra_note} {note}".strip()

    details = (
        f"[TaintGraph] {vuln_type}：污点变量 {taint_var} "
        f"源自第 {taint_source_line} 行用户输入，"
        f"{'经净化函数处理后' if sanitized else '未经净化地'}"
        f"流入 Sink（第 {line} 行）。"
        f"{note}"
    )

    return {
        "type": vuln_type,
        "severity": severity,
        "line": line,
        "start_line": line,
        "end_line": line,
        "start_character": 0,
        "end_character": 999,
        "details": details,
        "file": file_path,
        "cwe": cwe,
        "taint_var": taint_var,
        "taint_source_line": taint_source_line,
        "confidence": confidence,
        "source": "PHP-TaintGraph",
        "sink_snippet": sink_snippet[:120],
        # LSP related_locations：标记 Source 行
        "related_locations": [
            {
                "file_path": file_path,
                "start_line": taint_source_line,
                "end_line": taint_source_line,
                "start_character": 0,
                "end_character": 999,
                "message": (f"SOURCE: {taint_var} 在此行被赋值为用户输入"),
            }
        ],
    }


def _extract_sink_var(line: str, vuln_type: str) -> str | None:
    """
    从 Sink 调用行提取第一个污点参数变量名。

    覆盖：
    - echo/print $var / echo "..." . $var
    - header("Location: " . $var)
    - $db->query($sql) / shell_exec($cmd)
    """
    if vuln_type in ("XSS_RISK",):
        # echo/print：语句形式
        m = re.search(
            r"\b(?:echo|print)\s+(?:[^$]*\.\s*)?(\$[\w]+)",
            line,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)

    if vuln_type == "OPEN_REDIRECT":
        # header("Location: " . $var)
        m = re.search(
            r"""header\s*\(\s*['"][Ll]ocation\s*:['"]\s*\.\s*(\$[\w]+)""",
            line,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)
        # header($var) 或 header("loc:" . $var)
        m = re.search(r"\(\s*(?:[^$)\"']+)?\s*(\$[\w]+)", line)
        if m:
            return m.group(1)

    if vuln_type in ("PATH_TRAVERSAL", "DESERIALIZATION"):
        # 第一个参数变量：file_get_contents($path)、unserialize($data)
        m = re.search(r"\(\s*(?:[^$)\"']*['\"][^'\"]*['\"]\s*\.\s*)?(\$[\w]+)", line)
        if m:
            return m.group(1)

    # 通用：圆括号内第一个 $var（跳过字符串字面量前缀）
    m = re.search(
        r"""\(\s*(?:[^$)\"']*['"][^'"]*['"]\s*\.\s*)?(\$[\w]+)""",
        line,
    )
    return m.group(1) if m else None


def _is_parameterized(line: str) -> bool:
    """
    判断 SQL 调用行是否使用参数化查询（安全形式）。

    检测：execute("...?", ...) / execute("...%s", ...) / prepare(
    """
    if re.search(r"->prepare\s*\(|::prepare\s*\(", line, re.IGNORECASE):
        return True
    if _PARAM_PLACEHOLDER_RE.search(line) and _PARAM_BIND_RE.search(line):
        return True
    return False


# ─────────────────────────────────────────────────────────────────
# 规则类
# ─────────────────────────────────────────────────────────────────


class _PhpTaintBaseRule(SecurityRule):
    """
    PHP TaintGraph 规则基类（v2.0：继承 SecurityRule）。

    架构说明：
    - 继承 SecurityRule 以接入主引擎框架（PhpAnalyzer / rule_engine）；
    - visit() 是空操作（PHP 规则不逐节点遍历 AST）；
    - after_file() 中基于行级 PhpTaintGraph 完成分析，产出 findings；
    - 保留 analyze() 接口供向后兼容调用（rule_engine.analyze_php）。

    子类只需声明 ``_VULN_TYPES`` 和可选覆盖 ``_extra_filter`` / ``_skip_sanitized``。
    """

    #: 本规则关注的漏洞类型集合
    _VULN_TYPES: frozenset = frozenset()

    def __init__(self) -> None:
        # 从 _VULN_TYPES 自动推断 rule_id 和 severity
        vuln_type = next(iter(self._VULN_TYPES), "PHP_RULE")
        severity_map = {
            "SQL_INJECTION": "High",
            "RCE_COMMAND_EXEC": "Critical",
            "XSS_RISK": "High",
            "OPEN_REDIRECT": "Medium",
            "PATH_TRAVERSAL": "High",
            "DESERIALIZATION": "High",
            "HARDCODED_CREDENTIALS": "High",
        }
        super().__init__(
            rule_id=f"{vuln_type}_PHP_TAINT",
            severity=severity_map.get(vuln_type, "High"),
            languages=["php"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        PHP TaintGraph 规则不逐节点检测，此方法为空操作。
        实际分析在 after_file() 中完成（全文行级扫描）。
        """

    def after_file(self, context: AnalysisContext) -> None:
        """
        在文件遍历结束后执行行级 PhpTaintGraph 分析，产出 findings。
        """
        source = context.extras.get("source", "")
        if not source:
            return
        findings = self.analyze(source, context.file_path)
        for f in findings:
            context.add_finding(f)

    def analyze(self, code: str, file_path: str | Path) -> list[dict]:
        """
        对 PHP 源码执行污点分析（向后兼容接口）。

        Args:
            code:      PHP 源码字符串
            file_path: 文件路径（用于 finding.file 字段）

        Returns:
            finding 列表，格式与 analyze_python/analyze_javascript 一致。
        """
        fp = str(file_path)
        lines = code.split("\n")
        taint = PhpTaintGraph(lines)
        findings: list[dict] = []

        for idx, raw_line in enumerate(lines):
            line_num = idx + 1
            line = raw_line.strip()

            for sink_re, vuln_type, base_severity in _PHP_SINK_PATTERNS:
                if vuln_type not in self._VULN_TYPES:
                    continue
                if not sink_re.search(line):
                    continue

                # 子类额外过滤（如参数化查询、HTML 净化）
                if self._extra_filter(line, vuln_type):
                    continue

                arg_var = _extract_sink_var(line, vuln_type)
                if not arg_var:
                    # 兜底：取行中第一个 $var
                    m = re.search(r"(\$[\w]+)", line)
                    arg_var = m.group(1) if m else None

                if not arg_var:
                    continue

                # 传入 line_num 使 is_tainted/is_sanitized 能进行 CFG 行范围感知
                if taint.is_tainted(arg_var, line_num):
                    findings.append(
                        _make_finding(
                            vuln_type=vuln_type,
                            severity=base_severity,
                            line=line_num,
                            file_path=fp,
                            taint_var=arg_var,
                            taint_source_line=taint.get_source_line(arg_var),
                            sink_snippet=line,
                            confidence="high",
                            sanitized=False,
                        )
                    )
                elif taint.is_sanitized(arg_var, line_num):
                    # 净化路径：若子类决定跳过净化 finding 则直接 continue
                    if self._skip_sanitized(line, vuln_type, arg_var, taint):
                        continue
                    # 否则降级 Low 供人工复查
                    findings.append(
                        _make_finding(
                            vuln_type=vuln_type,
                            severity="Low",
                            line=line_num,
                            file_path=fp,
                            taint_var=arg_var,
                            taint_source_line=taint.get_source_line(arg_var),
                            sink_snippet=line,
                            confidence="low",
                            sanitized=True,
                        )
                    )
                else:
                    # 变量不在追踪表中，但 Sink 行本身直接含 Source 超全局变量
                    # 例如：echo $_GET['xss'];  （无中间赋值变量）
                    if _PHP_SOURCE_RE.search(line) and not self._extra_filter(line, vuln_type):
                        src_m = re.search(
                            r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)\s*\[",
                            line,
                            re.IGNORECASE,
                        )
                        direct_src = src_m.group(0).rstrip("[") if src_m else "$_INPUT"
                        findings.append(
                            {
                                "type": vuln_type,
                                "severity": base_severity,
                                "line": line_num,
                                "start_line": line_num,
                                "end_line": line_num,
                                "start_character": 0,
                                "end_character": 999,
                                "details": (
                                    f"[TaintGraph] {vuln_type}："
                                    f"用户输入 {direct_src} 直接流入 Sink（第 {line_num} 行），无中间变量。"
                                ),
                                "file": fp,
                                "cwe": _CWE_MAP.get(vuln_type, ""),
                                "taint_var": direct_src,
                                "taint_source_line": line_num,
                                "confidence": "high",
                                "source": "PHP-TaintGraph",
                                "sink_snippet": line[:120],
                                "related_locations": [],
                            }
                        )

        return self._dedup(findings)

    def _extra_filter(self, line: str, vuln_type: str) -> bool:
        """
        额外过滤（子类可覆盖）。

        返回 True 表示跳过该行（连 Low finding 也不输出）。
        """
        return False

    def _skip_sanitized(
        self,
        line: str,
        vuln_type: str,
        arg_var: str,
        taint: PhpTaintGraph,
    ) -> bool:
        """
        是否跳过已净化路径的 Low finding（子类可覆盖）。

        默认 False：降级为 Low 供人工复查。
        RCE 等规则可覆盖为 True 以完全静默已净化路径。
        """
        return False

    @staticmethod
    def _dedup(findings: list[dict]) -> list[dict]:
        """
        去重：同一（line, type, taint_var）只保留第一条。
        """
        seen: set = set()
        result: list[dict] = []
        for f in findings:
            key = (f["line"], f["type"], f.get("taint_var", ""))
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result


class PhpSQLInjectionRule(_PhpTaintBaseRule):
    """
    PHP SQL 注入检测规则（TaintGraph 精确版）。

    Source：``$_GET / $_POST / $_REQUEST / $_COOKIE`` 等
    Sink  ：``$db->query() / $db->execute() / mysql_query()`` 等
    TN    ：参数化查询（``prepare() / execute("...?", ...)``）
    TN    ：强类型整数守护（``intval / is_numeric`` → 整数不可注入 SQL）
    """

    _VULN_TYPES: frozenset = frozenset(["SQL_INJECTION"])

    # 强类型整数化净化函数：整数类型无法注入 SQL
    _SQLI_INT_SANITIZERS = re.compile(
        r"\b(intval|floatval|abs|is_numeric|ctype_digit|number_format|round|ceil|floor)\s*\(",
        re.IGNORECASE,
    )

    def _extra_filter(self, line: str, vuln_type: str) -> bool:
        """参数化查询 → 跳过。"""
        return _is_parameterized(line)

    def _skip_sanitized(
        self,
        line: str,
        vuln_type: str,
        arg_var: str,
        taint: PhpTaintGraph,
    ) -> bool:
        """
        对 SQLi：若净化链包含强类型整数化函数（intval/is_numeric 等），
        或变量在 CFG 守护块内（行范围级 sanitized），则完全跳过 Low finding。

        整数类型的变量无法进行 SQL 注入，Low 降级无实际意义。
        """
        # 直接检查 _range_sanitized（CFG 守护）— 已通过 is_sanitized 确认
        # 这里只需检查净化函数链
        source_expr = taint.get_source_expr(arg_var)
        if source_expr and self._SQLI_INT_SANITIZERS.search(source_expr):
            return True

        # 追溯 sanitized 链最多 3 跳
        visited: set[str] = set()
        queue = [arg_var]
        for _ in range(3):
            if not queue:
                break
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            expr = taint.get_source_expr(current)
            if not expr:
                continue
            if self._SQLI_INT_SANITIZERS.search(expr):
                return True
            inner_m = re.search(r"(\$[\w]+)", expr)
            if inner_m and inner_m.group(1) != current:
                queue.append(inner_m.group(1))

        # 若是 CFG 行范围级守护（_range_sanitized），也跳过 Low
        # 因为守护条件本身已隐含强类型约束
        if arg_var in taint._range_sanitized:
            return True

        return False


class PhpRCERule(_PhpTaintBaseRule):
    """
    PHP 命令执行检测规则（TaintGraph 精确版）。

    Source：超全局变量
    Sink  ：``shell_exec / exec / system / passthru / popen / proc_open``
    TN    ：变量经过 intval / ctype_digit / is_numeric 等强类型净化（整数化后无法注入命令）
    """

    _VULN_TYPES: frozenset = frozenset(["RCE_COMMAND_EXEC"])

    # 对 RCE 而言足以阻断命令注入的强类型净化函数
    _RCE_SAFE_SANITIZERS = re.compile(
        r"\b(intval|floatval|abs|ctype_digit|ctype_alpha|ctype_alnum"
        r"|is_numeric|number_format|round|ceil|floor|stripslashes"
        r"|strip_tags|filter_var|preg_replace)\s*\(",
        re.IGNORECASE,
    )

    def _skip_sanitized(
        self,
        line: str,
        vuln_type: str,
        arg_var: str,
        taint: PhpTaintGraph,
    ) -> bool:
        """
        对 RCE 规则：若污点变量已被标记为 sanitized（经过净化函数处理过的路径），
        则完全跳过该 finding（不输出 Low finding），避免噪音。

        RCE 的净化路径（如 intval、stripslashes + is_numeric 守护）通常意味着
        开发者已有意识地进行了类型或内容限制，Low 级别 finding 在这里没有实际价值，
        反而会稀释真实 Critical/High 告警。

        修复了 DVWA impossible.php 等"已修复"代码被误报 RCE 的问题。
        """
        # 直接检查：arg_var 已在 sanitized 集合中，且污点链上任意节点含净化函数
        # 用宽松策略：只要进入 sanitized 路径就跳过（对 RCE 精确度优先）
        if taint.is_sanitized(arg_var):
            return True

        # 另外检查：Sink 行自身含强类型守护（如 intval($var) 直接在 exec 参数中）
        if self._RCE_SAFE_SANITIZERS.search(line):
            return True

        # 追溯 sanitized_vars 中的任意一跳是否含净化函数（最多 3 跳）
        visited: set[str] = set()
        queue = [arg_var]
        for _ in range(3):
            if not queue:
                break
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            expr = taint.get_source_expr(current)
            if not expr:
                continue
            if self._RCE_SAFE_SANITIZERS.search(expr):
                return True
            inner = re.search(r"(\$[\w]+)", expr)
            if inner and inner.group(1) != current:
                queue.append(inner.group(1))
        return False


class PhpXSSRule(_PhpTaintBaseRule):
    """
    PHP XSS 检测规则（TaintGraph 精确版）。

    Source：超全局变量
    Sink  ：``echo / print``（直接输出用户数据）
    TN    ：参数被 ``htmlspecialchars / htmlentities / strip_tags`` 处理
    """

    _VULN_TYPES: frozenset = frozenset(["XSS_RISK"])

    def _extra_filter(self, line: str, vuln_type: str) -> bool:
        """
        若 echo/print 的参数已经过 HTML 净化函数包裹，则跳过。

        例如：``echo htmlspecialchars($user_input);``
        """
        if _HTML_ESCAPE_RE.search(line):
            return True
        return False


class PhpOpenRedirectRule(_PhpTaintBaseRule):
    """
    PHP 开放重定向检测规则（TaintGraph 精确版）。

    Source：超全局变量
    Sink  ：``header("Location: " . $var)``
    """

    _VULN_TYPES: frozenset = frozenset(["OPEN_REDIRECT"])


# 路径遍历净化：basename / realpath 等
_PATH_SANITIZER_RE = re.compile(
    r"\b(basename|realpath|dirname|pathinfo)\s*\(",
    re.IGNORECASE,
)
# 反序列化净化：unserialize 的 allowed_classes 等
_DESERIALIZE_SAFE_RE = re.compile(
    r"unserialize\s*\([^,]+,\s*\[[^\]]*allowed_classes",
    re.IGNORECASE,
)


class PhpPathTraversalRule(_PhpTaintBaseRule):
    """
    PHP 路径遍历检测规则（TaintGraph 精确版）。

    Source：$_GET / $_POST / $_REQUEST
    Sink  ：file_get_contents / include / require / fopen / readfile
    TN    ：basename() / realpath() + 白名单目录校验
    """

    _VULN_TYPES: frozenset = frozenset(["PATH_TRAVERSAL"])

    def _extra_filter(self, line: str, vuln_type: str) -> bool:
        """净化函数包裹 → 跳过。"""
        return bool(_PATH_SANITIZER_RE.search(line))

    def _skip_sanitized(
        self,
        line: str,
        vuln_type: str,
        arg_var: str,
        taint: PhpTaintGraph,
    ) -> bool:
        """路径经 basename/realpath 等净化后不再报告（含 Low）。"""
        return True


class PhpDeserializationRule(_PhpTaintBaseRule):
    """
    PHP 反序列化检测规则（TaintGraph 精确版）。

    Source：$_GET / $_POST / $_REQUEST
    Sink  ：unserialize() / json_decode()（后接危险操作时）
    TN    ：allowed_classes 参数检查
    """

    _VULN_TYPES: frozenset = frozenset(["DESERIALIZATION"])

    def _extra_filter(self, line: str, vuln_type: str) -> bool:
        """unserialize(..., ['allowed_classes' => ...]) → 跳过。"""
        return bool(_DESERIALIZE_SAFE_RE.search(line))


# 轻量级 PHP NoSQL 注入检测（模式匹配）


class PhpNoSQLInjectionRule(SecurityRule):
    """
    PHP NoSQL 注入检测规则（模式匹配）。

    目标场景：
    - MongoDB / ODM 查询中直接使用超全局变量（$_GET/$_POST/$_REQUEST/$_COOKIE）作为查询条件。

    示例（应被检测到）::

        $collection->find(['user' => $_GET['user']]);
    """

    _PHP_NOSQL_SINK_RE = re.compile(
        r"""
        (?:\$[A-Za-z_]\w*\s*->\s*
           (?:find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|aggregate)
        )
        \s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)\s*\[
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    def __init__(self) -> None:
        super().__init__(
            rule_id="NOSQL_INJECTION_PHP_TAINT",
            severity="High",
            languages=["php"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """NoSQL 规则不依赖逐节点访问，仅在 after_file 中做行级模式匹配。"""

    def after_file(self, context: AnalysisContext) -> None:
        for finding in self.analyze(
            context.extras.get("source", "") or "",
            context.file_path or "",
        ):
            context.add_finding(finding)

    def analyze(self, code: str, file_path: str | Path) -> list[dict]:
        """
        对 PHP 源码进行 NoSQL 注入模式扫描，返回 finding 列表。

        目前采用轻量行级正则，后续可视情况升级为基于 PhpTaintGraph 的数据流分析。
        """
        fp = str(file_path)
        lines = code.split("\n")
        findings: list[dict] = []
        for idx, raw_line in enumerate(lines):
            line_num = idx + 1
            line = raw_line.strip()
            m = self._PHP_NOSQL_SINK_RE.search(line)
            if not m:
                continue

            src_m = re.search(
                r"\$_(GET|POST|REQUEST|COOKIE)\s*\[",
                line,
                re.IGNORECASE,
            )
            taint_var = src_m.group(0).rstrip("[") if src_m else "$_INPUT"

            findings.append(
                {
                    "type": "NOSQL_INJECTION",
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "line": line_num,
                    "start_line": line_num,
                    "end_line": line_num,
                    "details": (
                        "检测到 PHP 代码中使用超全局变量直接构造 NoSQL 查询条件，"
                        "存在 NoSQL 注入风险，建议进行白名单过滤或参数绑定。"
                    ),
                    "file": fp,
                    "cwe": _CWE_MAP.get("NOSQL_INJECTION", ""),
                    "source": "PHP-Pattern",
                },
            )
        return findings


# 硬编码凭证模式：$password = "..." / define("DB_PASSWORD", "...") / 'api_key' => '...'
_CREDENTIAL_ASSIGN_RE = re.compile(
    r"(?:^\s*(\$[\w]*password[\w]*|\$[\w]*secret[\w]*|\$api[_\w]*key)\s*=\s*['\"][^'\"]+['\"]"
    r"|define\s*\(\s*['\"](\w*PASSWORD\w*|\w*SECRET\w*|\w*API_KEY\w*)['\"]\s*,\s*['\"][^'\"]+['\"]"
    r"|['\"](?:api[_\w]*key|password|secret)['\"]\s*=>\s*['\"][^'\"]+['\"])",
    re.IGNORECASE,
)
# 排除：环境变量引用、占位符（不含 secret 子串，避免误排真实密码如 mySecretPass123）
_CREDENTIAL_EXCLUDE_RE = re.compile(
    r"getenv\s*\(|get_cfg_var\s*\(|['\"](?:xxx|xxx\.xxx|your[_\w]*|placeholder|changeme|redact)['\"]",
    re.IGNORECASE,
)
_TEST_FILE_NAMES = frozenset(["test", "example", "mock", "stub", "sample", "fixture"])


class PhpHardcodedCredentialsRule(SecurityRule):
    """
    PHP 硬编码凭证检测规则（模式匹配）。

    模式：$password = "..."、define("DB_PASSWORD", "...")、'api_key' => '...'
    排除：环境变量引用、占位符、测试文件。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="HARDCODED_CREDENTIALS_PHP_TAINT",
            severity="High",
            languages=["php"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        pass

    def after_file(self, context: AnalysisContext) -> None:
        for f in self.analyze(
            context.extras.get("source", "") or "",
            context.file_path or "",
        ):
            context.add_finding(f)

    def analyze(self, code: str, file_path: str | Path) -> list[dict]:
        """对 PHP 源码扫描硬编码凭证模式，返回 finding 列表（供 rule_engine.analyze_php 调用）。"""
        fp = str(file_path)
        stem = Path(fp).stem.lower()
        if any(stem.startswith(n) or stem == n for n in _TEST_FILE_NAMES):
            return []
        lines = code.split("\n")
        findings: list[dict] = []
        for idx, raw_line in enumerate(lines):
            line_num = idx + 1
            line = raw_line.strip()
            if not _CREDENTIAL_ASSIGN_RE.search(line):
                continue
            if _CREDENTIAL_EXCLUDE_RE.search(line):
                continue
            findings.append(
                {
                    "type": "HARDCODED_CREDENTIALS",
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "line": line_num,
                    "start_line": line_num,
                    "end_line": line_num,
                    "details": "检测到疑似硬编码凭证（密码/API Key/Secret），建议使用环境变量或密钥管理服务。",
                    "file": fp,
                    "cwe": _CWE_MAP.get("HARDCODED_CREDENTIALS", ""),
                    "source": "PHP-TaintGraph",
                }
            )
        return findings


__all__ = [
    "PhpSQLInjectionRule",
    "PhpRCERule",
    "PhpXSSRule",
    "PhpOpenRedirectRule",
    "PhpPathTraversalRule",
    "PhpDeserializationRule",
    "PhpNoSQLInjectionRule",
    "PhpHardcodedCredentialsRule",
]
