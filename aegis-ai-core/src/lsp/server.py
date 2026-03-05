"""
server.py - Aegis AI Language Server Protocol 实现

基于 pygls 框架，监听 textDocument/didOpen、didSave、didChange 事件，
调用 rule_engine 对打开/保存/编辑的文件执行安全扫描，并将 finding 转换为
LSP Diagnostic 发布到客户端（VSCode / Cursor）。通信方式: stdio。

TDD 对齐：
- 7.2 主诊断支持字符级 range，related_locations 映射为 Diagnostic.relatedInformation
- 7.3 发布前校验文档 version，避免脏数据
- M1 Code Action：对 Aegis 诊断提供「查看修复建议」与可选「插入建议注释」
- M2 didChange + debounce：输入时防抖后更新诊断；同一 URI 仅保留最新一次待执行任务
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import unquote, urlparse, quote

from lsprotocol import types as lsp
from pygls.lsp.server import LanguageServer

logger = logging.getLogger(__name__)

# M1：内置修复建议（与 rag_enhancer 结构一致，避免 LSP 层依赖 scanner）
from ..scanner.rag_enhancer import BUILTIN_REMEDIATION
# A：AI 修复建议（可选），与 CLI 共享 AIAnalyzer 实现
try:
    from ..scanner.ai_analyzer import AIAnalyzer
    AI_ANALYZER_AVAILABLE = True
except Exception:  # ImportError 或 openai 未安装等
    AI_ANALYZER_AVAILABLE = False
    AIAnalyzer = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# 常量 & 映射
# ---------------------------------------------------------------------------

#: 文件扩展名 -> 分析语言
EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".pyw": "python",
    ".php": "php",
    ".phtml": "php",
    ".php5": "php",
}

#: Scanner severity -> LSP DiagnosticSeverity
SEVERITY_MAP: Dict[str, lsp.DiagnosticSeverity] = {
    "Critical": lsp.DiagnosticSeverity.Error,
    "critical": lsp.DiagnosticSeverity.Error,
    "High": lsp.DiagnosticSeverity.Error,
    "high": lsp.DiagnosticSeverity.Error,
    "Medium": lsp.DiagnosticSeverity.Warning,
    "medium": lsp.DiagnosticSeverity.Warning,
    "Low": lsp.DiagnosticSeverity.Information,
    "low": lsp.DiagnosticSeverity.Information,
    "Info": lsp.DiagnosticSeverity.Hint,
    "info": lsp.DiagnosticSeverity.Hint,
}

# M2：didChange 防抖（秒）；同一 URI 仅保留最新一次待执行验证
DEBOUNCE_SECONDS: float = 0.4
_pending_validation: Dict[str, threading.Timer] = {}
_pending_lock: threading.Lock = threading.Lock()


# ---------------------------------------------------------------------------
# 跨文件分析工作区上下文
# ---------------------------------------------------------------------------


class WorkspaceContext:
    """
    工作区级别的跨文件分析上下文。

    在后台线程中构建 import graph 和依赖关系，
    为 ``scan_document`` 提供跨文件污点信息。
    """

    def __init__(self) -> None:
        self._analyzer: Optional[Any] = None
        self._project_path: Optional[str] = None
        self._building: bool = False
        self._lock = threading.Lock()
        self._init_options: Dict[str, Any] = {}

    def configure(self, init_options: Dict[str, Any]) -> None:
        """存储客户端传入的初始化配置。"""
        self._init_options = init_options or {}

    @property
    def disabled_rules(self) -> List[str]:
        return self._init_options.get("disabled_rules", [])

    @property
    def severity_minimum(self) -> str:
        return self._init_options.get("severity_minimum", "Low")

    @property
    def scan_on_save(self) -> bool:
        return self._init_options.get("scan_on_save", True)

    @property
    def scan_on_change(self) -> bool:
        return self._init_options.get("scan_on_change", True)

    def build_graph_async(self, project_path: str) -> None:
        """在后台线程中构建依赖图（不阻塞 LSP 事件循环）。"""
        with self._lock:
            if self._building:
                return
            self._building = True
            self._project_path = project_path

        def _build() -> None:
            try:
                from ..analysis.taint.cross_file_analyzer import CrossFileAnalyzer
                analyzer = CrossFileAnalyzer(Path(project_path))
                analyzer.scan_project()
                with self._lock:
                    self._analyzer = analyzer
                logger.info(
                    "Cross-file dependency graph built for %s", project_path
                )
            except Exception:
                logger.exception("Failed to build cross-file graph")
            finally:
                with self._lock:
                    self._building = False

        t = threading.Thread(target=_build, daemon=True)
        t.start()

    def get_cross_file_findings(self, file_path: str) -> List[Dict]:
        """
        获取与 ``file_path`` 相关的跨文件污点发现。

        Returns:
            finding dict 列表，可直接合并到单文件扫描结果。
        """
        with self._lock:
            analyzer = self._analyzer
        if analyzer is None:
            return []
        try:
            paths = analyzer.find_cross_file_taint_paths()
            results: List[Dict] = []
            for p in paths:
                d = p.to_dict()
                if d["sink"]["file"] == file_path or d["source"]["file"] == file_path:
                    results.append({
                        "type": d.get("vuln_type", "CROSS_FILE_TAINT"),
                        "severity": d.get("severity", "High"),
                        "line": d["sink"]["line"],
                        "details": d.get("description", "Cross-file taint path detected"),
                        "file_path": d["sink"]["file"],
                        "source": "CrossFileAnalyzer",
                        "related_locations": [
                            {
                                "file_path": step["file"],
                                "start_line": step["line"],
                                "message": step.get("expr", ""),
                            }
                            for step in d.get("path", [])
                        ],
                    })
            return results
        except Exception:
            logger.debug("Cross-file findings retrieval failed", exc_info=True)
            return []

    def invalidate(self) -> None:
        """文件变更后标记图需要重建。"""
        if self._project_path:
            self.build_graph_async(self._project_path)


_workspace_ctx = WorkspaceContext()


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def detect_language(file_path: str) -> Optional[str]:
    """
    根据文件扩展名检测编程语言。

    Args:
        file_path: 文件路径字符串

    Returns:
        语言标识符（``"javascript"`` / ``"typescript"`` / ``"python"``），
        如果无法识别则返回 ``None``。
    """
    suffix = Path(file_path).suffix.lower()
    return EXTENSION_LANGUAGE_MAP.get(suffix)


def uri_to_filepath(uri: str) -> str:
    """
    将 ``file://`` URI 转换为本地文件路径。

    Args:
        uri: LSP 文档 URI（如 ``file:///c%3A/Users/foo/bar.js``）

    Returns:
        本地文件系统路径字符串。
    """
    parsed = urlparse(uri)
    # 解码百分号编码（如 %3A -> :）
    raw_path = unquote(parsed.path)
    # Windows: /c:/Users/... -> c:/Users/...
    if len(raw_path) >= 3 and raw_path[0] == "/" and raw_path[2] == ":":
        raw_path = raw_path[1:]
    return raw_path


def _filepath_to_uri(file_path: str) -> str:
    """
    将本地文件路径转为 LSP 的 file URI。
    """
    path = Path(file_path).resolve()
    raw = path.as_posix()
    if raw.startswith("/"):
        return "file://" + quote(raw)
    return "file:///" + quote(raw)


def finding_to_diagnostic(finding: Dict, document_uri: str) -> lsp.Diagnostic:
    """
    将 rule_engine 的 finding dict 转换为 LSP Diagnostic。

    支持 TDD 7.1/7.2：字符级 range（start_line/start_character/end_line/end_character）、
    related_locations 映射为 Diagnostic.relatedInformation。
    """
    # 主诊断 range：优先字符级，否则退化为整行
    if all(k in finding for k in ("start_line", "end_line")):
        start_line = max(finding.get("start_line", 1) - 1, 0)
        end_line = max(finding.get("end_line", 1) - 1, 0)
        start_char = finding.get("start_character", 0)
        end_char = finding.get("end_character", 999)
        range_ = lsp.Range(
            start=lsp.Position(line=start_line, character=start_char),
            end=lsp.Position(line=end_line, character=end_char),
        )
    else:
        line = max(finding.get("line", 1) - 1, 0)
        range_ = lsp.Range(
            start=lsp.Position(line=line, character=0),
            end=lsp.Position(line=line, character=999),
        )

    severity_str = finding.get("severity", "Medium")
    severity = SEVERITY_MAP.get(severity_str, lsp.DiagnosticSeverity.Warning)
    message = finding.get("details", finding.get("message", "Security issue detected"))
    code = finding.get("type", "UNKNOWN")

    # ── TaintGraph 污点链附加信息（PHP-TaintGraph 来源）──
    # 将 source 行号和变量名直接嵌入消息，悬停即可看到完整流向
    finding_source = finding.get("source", "")
    if finding_source == "PHP-TaintGraph" and finding.get("taint_var"):
        taint_var  = finding["taint_var"]
        src_line   = finding.get("taint_source_line", 0)
        sink_line  = finding.get("line", 0)
        confidence = finding.get("confidence", "")
        cwe        = finding.get("cwe", "")
        chain_info = (
            f"\n\n[污点链] {taint_var}"
            f" (第 {src_line} 行 Source"
            f" → 第 {sink_line} 行 Sink)"
        )
        if cwe:
            chain_info += f"  {cwe}"
        if confidence == "low":
            chain_info += "\n⚠ 变量已经过净化函数，建议人工确认净化充分性。"
        message = message.rstrip() + chain_info

    # M1：悬停时即可见修复建议 + 建议修复后的代码（不依赖 Code Action 菜单）
    remediation = _get_remediation_for_rule(str(code).strip())
    if remediation and (remediation.get("remediation") or remediation.get("description")):
        first_tip = (remediation.get("remediation") or [])[0] if remediation.get("remediation") else remediation.get("description", "")
        if first_tip:
            message = message.rstrip()
            if not message.endswith("。"):
                message += "。"
            message += "\n修复建议: " + first_tip
        # PHP 来源：使用 PHP 专属修复示例，不显示 JS 示例
        if finding_source == "PHP-TaintGraph":
            php_code = _PHP_REMEDIATION_CODE.get(str(code).strip())
            if php_code:
                message += "\n建议修复代码 (PHP):\n" + php_code.strip()
        else:
            # 框架感知：优先选择与当前文件匹配的框架专用示例
            framework_code = _pick_framework_suggested_code(
                remediation, finding.get("file", "")
            )
            if framework_code:
                message += "\n建议修复代码:\n" + framework_code.strip()
            elif remediation.get("suggested_code"):
                message += "\n建议修复代码:\n" + remediation["suggested_code"].strip()

    # related_locations -> Diagnostic.relatedInformation（TDD 7.2）
    related: List[lsp.DiagnosticRelatedInformation] = []
    for loc in finding.get("related_locations") or []:
        if not isinstance(loc, dict):
            continue
        loc_file = loc.get("file_path") or loc.get("file") or finding.get("file", "")
        if not loc_file:
            continue
        r_start = max((loc.get("start_line") or 1) - 1, 0)
        r_end = max((loc.get("end_line") or loc.get("start_line") or 1) - 1, 0)
        r_sc = loc.get("start_character", 0)
        r_ec = loc.get("end_character", 999)
        loc_uri = document_uri if loc_file == finding.get("file") else _filepath_to_uri(loc_file)
        loc_range = lsp.Range(
            start=lsp.Position(line=r_start, character=r_sc),
            end=lsp.Position(line=r_end, character=r_ec),
        )
        related.append(
            lsp.DiagnosticRelatedInformation(
                location=lsp.Location(uri=loc_uri, range=loc_range),
                message=loc.get("message", ""),
            )
        )

    return lsp.Diagnostic(
        range=range_,
        message=message,
        severity=severity,
        source="Aegis AI",
        code=code,
        related_information=related if related else None,
    )


def _get_remediation_for_rule(rule_id: str) -> Dict[str, Any]:
    """
    根据规则类型（如 NOSQL_INJECTION）返回内置修复建议。
    M1：供 Code Action 使用，与 rag_enhancer.BUILTIN_REMEDIATION 一致。
    """
    return BUILTIN_REMEDIATION.get(rule_id, {})


# PHP 专属修复示例代码（TaintGraph finding 时使用，替代 rag_enhancer 里的 JS 示例）
_PHP_REMEDIATION_CODE: Dict[str, str] = {
    "SQL_INJECTION": (
        "// PHP 参数化查询（PDO）\n"
        "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
        "$stmt->bindParam(':id', $id, PDO::PARAM_INT);\n"
        "$stmt->execute();"
    ),
    "RCE_COMMAND_EXEC": (
        "// PHP 命令执行：使用白名单验证，避免直接传入用户输入\n"
        "$allowed = ['ls', 'pwd', 'whoami'];\n"
        "if (in_array($cmd, $allowed)) {\n"
        "    shell_exec(escapeshellcmd($cmd));\n"
        "}"
    ),
    "XSS_RISK": (
        "// PHP XSS 防御：使用 htmlspecialchars 转义输出\n"
        "echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');"
    ),
    "OPEN_REDIRECT": (
        "// PHP 开放重定向防御：使用白名单验证目标 URL\n"
        "$allowed_urls = ['https://example.com/page1', 'https://example.com/page2'];\n"
        "if (in_array($url, $allowed_urls)) {\n"
        "    header('Location: ' . $url);\n"
        "} else {\n"
        "    header('Location: /error');\n"
        "}"
    ),
}


def _pick_framework_suggested_code(remediation: Dict[str, Any], file_path: str) -> Optional[str]:
    """
    从 BUILTIN_REMEDIATION 条目中选取与当前文件框架匹配的专用示例代码。

    读取文件头部 import 语句推断框架（轻量版，避免引入 ai_analyzer 循环依赖）。
    若无法匹配则返回 None，由调用方回退到通用 suggested_code。

    Args:
        remediation: BUILTIN_REMEDIATION 中单个漏洞类型的 dict
        file_path: 当前文件路径（用于读取 import）

    Returns:
        框架专用示例代码字符串或 None
    """
    framework_code_map: Dict[str, str] = remediation.get("framework_suggested_code") or {}
    if not framework_code_map:
        return None

    # 快速读取文件头部推断框架（最多 60 行）
    try:
        path = Path(file_path)
        header = ""
        with path.open(encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= 60:
                    break
                header += line
        header_lower = header.lower()
    except Exception:
        return None

    # 按优先级匹配
    priority = [
        "mysql2", "mysql", "sequelize", "knex", "typeorm", "prisma",
        "pymysql", "psycopg2", "sqlalchemy", "django-orm",
        "mongoose", "mongodb",
    ]
    for fw in priority:
        if fw in header_lower and fw in framework_code_map:
            return framework_code_map[fw]

    return None


def _remediation_to_comment_text(rule_id: str) -> str:
    """将修复建议格式化为可插入的注释文本（多行）。"""
    data = _get_remediation_for_rule(rule_id)
    if not data:
        return f"// Aegis: {rule_id} - 请查阅安全修复指南"
    lines = [f"// Aegis 修复建议 ({rule_id}):", f"// {data.get('description', '')}"]
    for i, s in enumerate(data.get("remediation") or [], 1):
        lines.append(f"//   {i}. {s}")
    refs = data.get("references") or []
    if refs:
        lines.append("// 参考:")
        for r in refs[:3]:
            lines.append(f"//   {r}")
    return "\n".join(lines)


def _extract_code_context(
    source: str,
    start_line: int,
    end_line: int,
    padding: int = 10,
) -> tuple:
    """
    提取漏洞所在代码块（含前后 padding 行上下文）。

    用于 Code Action 触发 AI 分析时，仅传漏洞周围代码而非整个文件，
    以降低 Token 消耗并提升 AI 生成修复代码的精准度。

    Args:
        source: 文件完整源代码
        start_line: 漏洞起始行（1-indexed）
        end_line: 漏洞结束行（1-indexed）
        padding: 上下各扩展的行数

    Returns:
        (code_snippet, actual_start_line): 代码片段和实际起始行号（1-indexed）
    """
    lines = source.splitlines()
    total = len(lines)
    ctx_start = max(0, start_line - 1 - padding)
    ctx_end = min(total, end_line + padding)
    snippet = "\n".join(lines[ctx_start:ctx_end])
    return snippet, ctx_start + 1


def scan_document(source: str, file_path: str) -> List[Dict]:
    """
    调用 rule_engine 对源代码执行安全扫描。

    Args:
        source: 文件源代码
        file_path: 文件路径

    Returns:
        finding 列表。
    """
    language = detect_language(file_path)
    if language is None:
        return []

    # 延迟导入，避免在模块加载时就触发 tree-sitter 初始化
    from ..analysis.rule_engine import analyze_javascript, analyze_php, analyze_python

    try:
        if language == "python":
            return analyze_python(source, file_path)
        elif language in ("javascript", "typescript"):
            return analyze_javascript(source, file_path, language=language)
        elif language == "php":
            return analyze_php(source, file_path)
    except Exception:
        logger.exception("Scan failed for %s", file_path)
        return []

    return []


# ---------------------------------------------------------------------------
# Server 创建
# ---------------------------------------------------------------------------


def create_server() -> LanguageServer:
    """
    创建并配置 Aegis AI Language Server 实例。

    Returns:
        已注册事件处理器的 ``LanguageServer`` 实例。
    """
    server = LanguageServer("aegis-ai-lsp", "v0.1.0")

    @server.feature(lsp.INITIALIZE)
    def on_initialize(params: lsp.InitializeParams) -> None:
        """初始化时读取客户端配置，启动跨文件图构建。"""
        init_opts = params.initialization_options or {}
        _workspace_ctx.configure(init_opts)

        root = None
        if params.root_path:
            root = params.root_path
        elif params.root_uri:
            root = uri_to_filepath(params.root_uri)
        if root:
            _workspace_ctx.build_graph_async(root)

    @server.feature(lsp.TEXT_DOCUMENT_DID_OPEN)
    def did_open(params: lsp.DidOpenTextDocumentParams) -> None:
        """文件打开时执行安全扫描并发布 Diagnostics。"""
        uri = params.text_document.uri
        _cancel_pending_validation(uri)
        _validate_document(server, uri, params.text_document.text)

    @server.feature(lsp.TEXT_DOCUMENT_DID_SAVE)
    def did_save(params: lsp.DidSaveTextDocumentParams) -> None:
        """文件保存时重新扫描并更新 Diagnostics。"""
        if not _workspace_ctx.scan_on_save:
            return
        text = params.text
        if text is None:
            doc = server.workspace.get_text_document(params.text_document.uri)
            text = doc.source
        _cancel_pending_validation(params.text_document.uri)
        _validate_document(server, params.text_document.uri, text)
        _workspace_ctx.invalidate()

    @server.feature(lsp.TEXT_DOCUMENT_DID_CHANGE)
    def did_change(params: lsp.DidChangeTextDocumentParams) -> None:
        """M2：文件内容变更时防抖后重新扫描并更新 Diagnostics。"""
        if not _workspace_ctx.scan_on_change:
            return
        uri = params.text_document.uri
        _cancel_pending_validation(uri)
        timer = threading.Timer(
            DEBOUNCE_SECONDS,
            _debounced_validate,
            args=(server, uri),
        )
        timer.daemon = True
        with _pending_lock:
            _pending_validation[uri] = timer
        timer.start()

    @server.feature(
        lsp.TEXT_DOCUMENT_CODE_ACTION,
        lsp.CodeActionOptions(code_action_kinds=[lsp.CodeActionKind.QuickFix]),
    )
    def code_action(params: lsp.CodeActionParams) -> List[lsp.CodeAction]:
        """
        M1：对 Aegis AI 的 Diagnostic 提供 Code Action。
        仅处理 context.diagnostics 中 source 为 "Aegis AI" 的项。
        """
        actions: List[lsp.CodeAction] = []
        uri = params.text_document.uri
        aegis_diagnostics = [
            d for d in (params.context.diagnostics or [])
            if (getattr(d, "source", None) or "").strip().lower() == "aegis ai"
        ]
        if not aegis_diagnostics:
            return actions

        # 懒加载 AI 分析器（仅在需要 AI 修复建议时创建）
        ai_analyzer: Optional[Any] = getattr(server, "_ai_analyzer", None)
        if AI_ANALYZER_AVAILABLE and ai_analyzer is None:
            try:
                ai_analyzer = AIAnalyzer()
                setattr(server, "_ai_analyzer", ai_analyzer)
            except Exception:
                ai_analyzer = None

        for diag in aegis_diagnostics:
            rule_id = getattr(diag, "code", None) or ""
            if isinstance(rule_id, lsp.CodeDescription):
                rule_id = ""
            rule_id = str(rule_id).strip() or "UNKNOWN"
            remediation = _get_remediation_for_rule(rule_id)
            comment_text = _remediation_to_comment_text(rule_id)
            insert_line = diag.range.start.line
            insert_pos = lsp.Position(line=insert_line, character=0)

            # M1 4.3：插入修复建议注释
            new_text = comment_text + "\n"
            edit = lsp.WorkspaceEdit(
                changes={
                    uri: [
                        lsp.TextEdit(range=lsp.Range(start=insert_pos, end=insert_pos), new_text=new_text),
                    ]
                }
            )
            actions.append(
                lsp.CodeAction(
                    title=f"Aegis: 插入修复建议注释（{rule_id}）",
                    kind=lsp.CodeActionKind.QuickFix,
                    diagnostics=[diag],
                    edit=edit,
                )
            )

            # M1 4.4：若有 suggested_code，提供「应用示例代码」Quick Fix
            suggested = (remediation or {}).get("suggested_code")
            if suggested and isinstance(suggested, str) and suggested.strip():
                code_text = suggested.strip() + "\n"
                code_edit = lsp.WorkspaceEdit(
                    changes={
                        uri: [
                            lsp.TextEdit(
                                range=lsp.Range(start=insert_pos, end=insert_pos),
                                new_text=code_text,
                            ),
                        ]
                    }
                )
                actions.append(
                    lsp.CodeAction(
                        title=f"Aegis: 应用示例代码（{rule_id}）",
                        kind=lsp.CodeActionKind.QuickFix,
                        diagnostics=[diag],
                        edit=code_edit,
                    )
                )

            # A：若启用 AI 分析，为高危诊断提供「AI 修复建议」
            # 触发原则：仅在用户主动点击灯泡图标时执行，单次单条，不批量触发
            if ai_analyzer is not None and getattr(ai_analyzer, "enabled", False):
                severity_str = "Medium"
                if diag.severity == lsp.DiagnosticSeverity.Error:
                    severity_str = "High"
                elif diag.severity == lsp.DiagnosticSeverity.Warning:
                    severity_str = "Medium"
                elif diag.severity == lsp.DiagnosticSeverity.Information:
                    severity_str = "Low"
                elif diag.severity == lsp.DiagnosticSeverity.Hint:
                    severity_str = "Info"

                diag_start_line = diag.range.start.line + 1
                diag_end_line = diag.range.end.line + 1
                file_path_str = uri_to_filepath(uri)
                lang = detect_language(file_path_str)

                finding_like: Dict[str, Any] = {
                    "type": rule_id,
                    "severity": severity_str,
                    "file": file_path_str,
                    "line": diag_start_line,
                    "start_line": diag_start_line,
                    "end_line": diag_end_line,
                    "details": diag.message,
                    "language": lang,
                }

                try:
                    if ai_analyzer.should_analyze(finding_like):
                        # 获取完整源代码，传给 rich context 提取器
                        doc_source: Optional[str] = None
                        try:
                            doc = server.workspace.get_text_document(uri)
                            doc_source = doc.source
                        except Exception:
                            pass

                        result = ai_analyzer.analyze_finding(
                            finding_like,
                            language=lang,
                            source_code=doc_source,
                        )

                        if result:
                            # ── 高置信度（>= 0.75）且有修复代码：直接替换漏洞行 ──
                            if (
                                result.fixed_code
                                and result.confidence >= 0.75
                                and not result.requires_review
                            ):
                                # 替换整个漏洞 range（保留缩进：从 result.fixed_code 原样写入）
                                replace_range = lsp.Range(
                                    start=lsp.Position(line=diag.range.start.line, character=0),
                                    end=lsp.Position(
                                        line=diag.range.end.line,
                                        character=diag.range.end.character,
                                    ),
                                )
                                fixed_text = result.fixed_code
                                if not fixed_text.endswith("\n"):
                                    fixed_text += "\n"
                                replace_edit = lsp.WorkspaceEdit(
                                    changes={
                                        uri: [
                                            lsp.TextEdit(
                                                range=replace_range,
                                                new_text=fixed_text,
                                            ),
                                        ]
                                    }
                                )
                                actions.append(
                                    lsp.CodeAction(
                                        title=f"Aegis: ✓ 应用 AI 精准修复（{rule_id}，置信度 {result.confidence:.0%}）",
                                        kind=lsp.CodeActionKind.QuickFix,
                                        diagnostics=[diag],
                                        edit=replace_edit,
                                        is_preferred=True,
                                    )
                                )

                            # ── 低置信度或无 fixed_code：插入注释说明 ──
                            else:
                                comment_lines = [
                                    f"// Aegis AI 修复建议 ({rule_id}):",
                                    f"// 置信度: {result.confidence:.2f} | 风险等级: {result.risk_level}",
                                ]
                                if result.requires_review:
                                    comment_lines.append("// ⚠ AI 建议需人工复核。")

                                if result.fix_suggestion:
                                    comment_lines.append(f"// 修复思路: {result.fix_suggestion}")

                                if result.fixed_code:
                                    comment_lines.append("// --- AI 修复参考代码 ---")
                                    comment_lines += [
                                        f"//   {ln}" for ln in result.fixed_code.splitlines()
                                    ]

                                ai_comment = "\n".join(comment_lines)
                                ai_edit = lsp.WorkspaceEdit(
                                    changes={
                                        uri: [
                                            lsp.TextEdit(
                                                range=lsp.Range(start=insert_pos, end=insert_pos),
                                                new_text=ai_comment + "\n",
                                            ),
                                        ]
                                    }
                                )
                                actions.append(
                                    lsp.CodeAction(
                                        title=f"Aegis: 插入 AI 修复建议注释（{rule_id}）",
                                        kind=lsp.CodeActionKind.QuickFix,
                                        diagnostics=[diag],
                                        edit=ai_edit,
                                    )
                                )
                except Exception:
                    # AI 分析失败时静默忽略，不影响其他 CodeAction
                    logger.exception("AI remediation generation failed for %s", rule_id)
        return actions

    return server


def _cancel_pending_validation(uri: str) -> None:
    """M2：取消该 URI 的待执行防抖验证（限流：同一文档仅保留最新一次）。"""
    with _pending_lock:
        timer = _pending_validation.pop(uri, None)
    if timer is not None:
        try:
            timer.cancel()
        except Exception:
            pass


def _debounced_validate(server: LanguageServer, uri: str) -> None:
    """M2：防抖到期后从 workspace 取当前文档内容并执行验证。"""
    with _pending_lock:
        _pending_validation.pop(uri, None)
    try:
        doc = server.workspace.get_text_document(uri)
        source = doc.source
    except Exception:
        server.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(uri=uri, diagnostics=[])
        )
        return
    _validate_document(server, uri, source)


def _validate_document(server: LanguageServer, uri: str, source: str) -> None:
    """
    内部：扫描文档并发布 Diagnostics。

    TDD 7.3：发布前校验文档 version，若已变更则丢弃本次结果并清空诊断。
    Status Bar：扫描前发送 ``aegis/scanStart``，完成后发送 ``aegis/scanEnd``
    （含 ``issueCount``），供前端 Status Bar 实时更新。
    """
    file_path = uri_to_filepath(uri)
    language = detect_language(file_path)

    if language is None:
        server.text_document_publish_diagnostics(
            lsp.PublishDiagnosticsParams(uri=uri, diagnostics=[])
        )
        return

    # ── 通知前端：扫描开始 ───────────────────────────────────────────────────
    try:
        server.send_notification("aegis/scanStart", {"uri": uri})
    except Exception:
        pass  # 静默忽略，不影响核心扫描逻辑

    # 记录扫描开始时的文档版本（若有）
    version_before: Optional[int] = None
    try:
        doc = server.workspace.get_text_document(uri)
        version_before = doc.version
    except Exception:
        pass

    findings = scan_document(source, file_path)

    # 合并跨文件分析结果
    cross_file_findings = _workspace_ctx.get_cross_file_findings(file_path)
    if cross_file_findings:
        findings = findings + cross_file_findings
        logger.info(
            "Merged %d cross-file findings for %s",
            len(cross_file_findings), file_path,
        )

    # 过滤已禁用的规则
    disabled = set(_workspace_ctx.disabled_rules)
    if disabled:
        findings = [
            f for f in findings
            if f.get("type", f.get("rule_id", "")) not in disabled
        ]

    # 过滤低于最低严重度的发现
    _severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    min_sev = _severity_order.get(_workspace_ctx.severity_minimum, 1)
    if min_sev > 1:
        findings = [
            f for f in findings
            if _severity_order.get(f.get("severity", "Medium"), 2) >= min_sev
        ]

    # 发布前再次读取版本；若文档已被用户修改，丢弃本次结果并清空诊断
    try:
        doc = server.workspace.get_text_document(uri)
        if version_before is not None and doc.version != version_before:
            logger.info(
                "Document %s version changed (%s -> %s), skipping publish",
                uri, version_before, doc.version,
            )
            server.text_document_publish_diagnostics(
                lsp.PublishDiagnosticsParams(uri=uri, diagnostics=[])
            )
            try:
                server.send_notification("aegis/scanEnd", {"uri": uri, "issueCount": 0})
            except Exception:
                pass
            return
    except Exception:
        pass

    diagnostics = [finding_to_diagnostic(f, uri) for f in findings]
    issue_count = len(diagnostics)
    logger.info(
        "Published %d diagnostics for %s (%s)",
        issue_count,
        file_path,
        language,
    )
    server.text_document_publish_diagnostics(
        lsp.PublishDiagnosticsParams(uri=uri, diagnostics=diagnostics)
    )

    # ── 通知前端：扫描结束（含问题数量，驱动 Status Bar 更新）─────────────
    try:
        server.send_notification("aegis/scanEnd", {"uri": uri, "issueCount": issue_count})
    except Exception:
        pass
