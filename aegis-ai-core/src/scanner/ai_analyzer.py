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

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
        except Exception as exc:
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


class AIAnalyzer:
    """
    AI 分析器。

    功能：
    - 漏洞真实性评估
    - 风险等级调整
    - 修复代码生成

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

    def __init__(
        self,
        api_key: str | None = None,
        api_base: str | None = None,
        model: str = "deepseek-chat",
        enabled: bool = True,
    ) -> None:
        """
        初始化 AI 分析器。

        Args:
            api_key: AI API 密钥（默认从环境变量获取）
            api_base: API 基础 URL
            model: 模型名称
            enabled: 是否启用 AI 分析
        """
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.api_base = api_base or os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
        self.model = model
        self.enabled = enabled and bool(self.api_key)

        # 分析缓存
        self._cache: dict[str, AIAnalysisResult] = {}

        if self.enabled:
            logger.info("AI 分析器已启用 (模型: %s)", model)
        else:
            logger.warning("AI 分析器未启用（缺少 API 密钥或已禁用）")

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

        severity = finding.get("severity", "Low")
        return severity in self.ANALYSIS_CONFIG["enabled_severities"]

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
        cache_key = self._get_cache_key(finding)
        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self.enabled:
            return self._default_analysis(finding)

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

    def _get_cache_key(self, finding: dict[str, Any]) -> str:
        """生成缓存键"""
        vuln_type = finding.get("type", "")
        details = finding.get("details", "")[:100]
        return f"{vuln_type}:{hash(details)}"

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
            import openai

            client = openai.OpenAI(
                api_key=self.api_key,
                base_url=self.api_base,
            )

            prompt = self._build_analysis_prompt(finding, rich_ctx=rich_ctx, language=language)

            response = client.chat.completions.create(
                model=self.model,
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
            )

            return self._parse_ai_response(response.choices[0].message.content, finding)

        except Exception as e:
            logger.warning("AI 分析失败: %s", e)
            return self._default_analysis(finding)

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
            '  "fixed_code": "修复后的完整代码：保留原函数签名和变量名，使用检测到的框架 API，只替换有问题的语句",',
            '  "fix_description": "一句话说明修复思路"',
            "}",
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
            return self._default_analysis(finding)

        confidence = float(parsed.get("confidence", 0.7))
        fixed_code = parsed.get("fixed_code") or None
        if fixed_code is not None and not fixed_code.strip():
            fixed_code = None

        return AIAnalysisResult(
            is_true_positive=not bool(parsed.get("is_false_positive", False)),
            confidence=confidence,
            risk_level=parsed.get("risk_level") or finding.get("severity", "Medium"),
            explanation=parsed.get("explanation", ""),
            fix_suggestion=parsed.get("fix_description") or None,
            requires_review=confidence < self.ANALYSIS_CONFIG["confidence_threshold"],
            fixed_code=fixed_code,
            fix_start_line=finding.get("start_line"),
            fix_end_line=finding.get("end_line"),
        )

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
        by_risk = {}
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


__all__ = ["AIAnalyzer", "AIAnalysisResult", "analyze_with_ai", "_extract_rich_context"]
