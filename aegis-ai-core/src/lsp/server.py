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

import concurrent.futures
import fnmatch
import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote, unquote, urlparse

if TYPE_CHECKING:
    from ..analysis.taint.cross_file_analyzer import CrossFileAnalyzer

from lsprotocol import types as lsp
from pygls.lsp.server import LanguageServer

from ..analysis.dependency_tracker import DependencyTracker
from ..analysis.incremental_analyzer import IncrementalAnalyzer
from ..scanner.baseline import Baseline
from ..scanner.rag_enhancer import BUILTIN_REMEDIATION
from ..scanner.smart_remediation import generate_smart_remediation

# A：AI 修复建议（可选），与 CLI 共享 AIAnalyzer 实现
try:
    from ..scanner.ai_analyzer import AIAnalyzer

    AI_ANALYZER_AVAILABLE = True
except ImportError:
    AI_ANALYZER_AVAILABLE = False
    AIAnalyzer = None  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)

# P1-1：扫描失败时向客户端发送 aegis/scanError 通知
NOTIFICATION_SCAN_ERROR = "aegis/scanError"


class ScanError(Exception):
    """扫描过程发生异常时抛出，供 _validate_document 捕获并通知客户端。"""


# ---------------------------------------------------------------------------
# 常量 & 映射
# ---------------------------------------------------------------------------

#: 文件扩展名 -> 分析语言
EXTENSION_LANGUAGE_MAP: dict[str, str] = {
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
    ".java": "java",
    ".go": "go",
}

#: Scanner severity -> LSP DiagnosticSeverity
SEVERITY_MAP: dict[str, lsp.DiagnosticSeverity] = {
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

# P1-3：单文件扫描超时（秒）；超时则记录警告并返回空结果
SCAN_TIMEOUT_SECONDS: float = 30.0
# P1-3：单文件大小上限（字节）；超过则跳过
MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2 MB
_pending_validation: dict[str, threading.Timer] = {}
_pending_lock: threading.Lock = threading.Lock()

# O3: 每个 URI 的 findings 缓存，用于 aegis/getTaintPath 等后续查询
_findings_cache: dict[str, list[dict]] = {}

# O5: 增量分析器实例和依赖追踪器实例
_incremental_analyzer = IncrementalAnalyzer()
_dependency_tracker = DependencyTracker()


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
        self._analyzer: CrossFileAnalyzer | None = None
        self._project_path: str | None = None
        self._building: bool = False
        self._lock = threading.Lock()
        self._init_options: dict[str, Any] = {}

    def configure(self, init_options: dict[str, Any]) -> None:
        """存储客户端传入的初始化配置。"""
        self._init_options = init_options or {}

    @property
    def disabled_rules(self) -> list[str]:
        return cast(list[str], self._init_options.get("disabled_rules", []))

    @property
    def severity_minimum(self) -> str:
        return cast(str, self._init_options.get("severity_minimum", "Low"))

    @property
    def scan_on_save(self) -> bool:
        return cast(bool, self._init_options.get("scan_on_save", True))

    @property
    def scan_on_change(self) -> bool:
        return cast(bool, self._init_options.get("scan_on_change", True))

    @property
    def exclude_patterns(self) -> list[str]:
        return cast(list[str], self._init_options.get("exclude_patterns", []))

    @property
    def experimental_cross_file(self) -> bool:
        return cast(bool, self._init_options.get("experimental_cross_file", False))

    def build_graph_async(self, project_path: str) -> None:
        """在后台线程中构建依赖图（不阻塞 LSP 事件循环）。"""
        if not self.experimental_cross_file:
            return
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
                logger.info("Cross-file dependency graph built for %s", project_path)
            except (ImportError, RuntimeError, OSError):
                logger.exception("Failed to build cross-file graph")
            finally:
                with self._lock:
                    self._building = False

        t = threading.Thread(target=_build, daemon=True)
        t.start()

    def get_cross_file_findings(self, file_path: str) -> list[dict]:
        """
        获取与 ``file_path`` 相关的跨文件发现。

        当前跨文件污点追踪尚未实现，始终返回空列表。
        保留接口供未来扩展。

        Returns:
            finding dict 列表，当前为空。
        """
        if not self.experimental_cross_file:
            return []
        return []

    def invalidate(self) -> None:
        """文件变更后标记图需要重建。"""
        if self._project_path:
            self.build_graph_async(self._project_path)


_workspace_ctx = WorkspaceContext()


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def detect_language(file_path: str) -> str | None:
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


def _coerce_payload(value: Any) -> dict[str, Any]:
    """
    将 pygls 自定义 feature/command 的参数统一转成 dict。

    某些情况下 pygls 会把 JSON object 反序列化成带属性的 Object，
    不能直接调用 ``.get()``。
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    try:
        items = getattr(value, "items", None)
        if callable(items):
            return dict(items())
    except (RuntimeError, TypeError, ValueError):
        pass
    try:
        data = vars(value)
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if not k.startswith("_")}
    except TypeError:
        pass
    return {}


def _comment_prefix_for_language(language: str | None) -> str:
    """返回对应语言的单行注释前缀。"""
    if (language or "").lower() == "python":
        return "#"
    return "//"


def _build_comment_block(lines: list[str], language: str | None, indent: str = "") -> str:
    """按语言生成多行注释块，并保留当前行缩进。"""
    prefix = _comment_prefix_for_language(language)
    rendered: list[str] = []
    for line in lines:
        if not line:
            rendered.append(indent + prefix)
        else:
            rendered.append(f"{indent}{prefix} {line}")
    return "\n".join(rendered)


def _indent_block(text: str, indent: str) -> str:
    """为多行文本整体补齐缩进。"""
    return "\n".join((indent + line) if line else line for line in text.splitlines())


_AEGIS_COMMENT_MARKERS = (
    "Aegis 修复建议",
    "Aegis AI 修复建议",
)


def _is_aegis_generated_comment(line: str) -> bool:
    """判断当前行是否为 Aegis 生成的修复建议注释。"""
    stripped = line.strip()
    if not stripped.startswith(("#", "//")):
        return False
    return any(marker in stripped for marker in _AEGIS_COMMENT_MARKERS)


def _find_aegis_comment_block(lines: list[str], zero_based_line: int) -> tuple[int, int] | None:
    """
    找到包含当前行的 Aegis 注释块。

    Returns:
        (start_line, end_line_exclusive)；若当前行不在 Aegis 注释块中则返回 ``None``。
    """
    if zero_based_line < 0 or zero_based_line >= len(lines):
        return None

    if not lines[zero_based_line].strip().startswith(("#", "//")):
        return None

    marker_line: int | None = None
    cursor = zero_based_line
    while cursor >= 0 and lines[cursor].strip().startswith(("#", "//")):
        if _is_aegis_generated_comment(lines[cursor]):
            marker_line = cursor
            break
        cursor -= 1

    if marker_line is None:
        return None

    end = marker_line + 1
    while end < len(lines) and lines[end].strip().startswith(("#", "//")):
        end += 1

    return marker_line, end


def _is_path_excluded(file_path: str, project_root: str | None, patterns: list[str]) -> bool:
    """按 VS Code 传入的 glob 模式判断当前路径是否应跳过扫描。"""
    if not patterns:
        return False
    path = Path(file_path)
    normalized_full = path.as_posix()
    normalized_rel = normalized_full
    if project_root:
        try:
            normalized_rel = path.relative_to(Path(project_root)).as_posix()
        except ValueError:
            normalized_rel = normalized_full

    candidates = {normalized_full, normalized_rel, "/" + normalized_rel}
    for pattern in patterns:
        normalized_pattern = pattern.replace("\\", "/")
        for candidate in candidates:
            if fnmatch.fnmatch(candidate, normalized_pattern):
                return True
    return False


def _is_actionable_example_code(snippet: str) -> bool:
    """
    判断 suggested_code 是否包含真正可替换的代码。

    纯注释示例不应暴露为「应用示例代码」，否则用户会误以为已完成修复。
    """
    for raw_line in snippet.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(("//", "#", "/*", "*", "*/", "<!--")):
            continue
        return True
    return False


def _get_line_indent(doc_lines: list[str], zero_based_line: int) -> str:
    """获取指定行的前导缩进。"""
    if 0 <= zero_based_line < len(doc_lines):
        current_line = doc_lines[zero_based_line]
        return current_line[: len(current_line) - len(current_line.lstrip())]
    return ""


def _replacement_range_for_diagnostic(diag: lsp.Diagnostic, doc_lines: list[str]) -> lsp.Range:
    """
    生成适合代码替换的 range：从起始行行首到结束行行尾。
    """
    start_line = diag.range.start.line
    end_line = diag.range.end.line
    if 0 <= end_line < len(doc_lines):
        end_char = len(doc_lines[end_line])
    else:
        end_char = diag.range.end.character
    return lsp.Range(
        start=lsp.Position(line=start_line, character=0),
        end=lsp.Position(line=end_line, character=end_char),
    )


def _build_action_guidance(has_example_fix: bool) -> str:
    """统一 hover/tree 说明，明确哪些动作会改代码，哪些只是建议或抑制。"""
    example_line = (
        "应用示例修复代码: 会替换代码并触发复扫。"
        if has_example_fix
        else "应用示例修复代码: 当前规则没有安全替换模板，灯泡中不会显示此操作。"
    )
    return "\n".join(
        [
            "Aegis 可用操作:",
            "- 应用 AI 精准修复: 会替换代码并触发复扫（需要已配置 AI）。",
            f"- {example_line}",
            "- 插入修复建议注释: 只会插入建议，不会修复代码。",
            "- 插入 AI 修复建议: 只会插入建议，不会修复代码（需要已配置 AI）。",
            "- Ignore / Add to baseline: 接受并隐藏当前问题，不是修复代码。",
        ]
    )


def _filepath_to_uri(file_path: str) -> str:
    """
    将本地文件路径转为 LSP 的 file URI。
    """
    path = Path(file_path).resolve()
    raw = path.as_posix()
    if raw.startswith("/"):
        return "file://" + quote(raw)
    return "file:///" + quote(raw)


def finding_to_diagnostic(
    finding: dict,
    document_uri: str,
    source_code: str | None = None,
    file_path: str | None = None,
) -> lsp.Diagnostic:
    """
    将 rule_engine 的 finding dict 转换为 LSP Diagnostic。

    支持 TDD 7.1/7.2：字符级 range、related_locations → relatedInformation。
    当提供 source_code 与 file_path 时，使用智能模板生成精准修复建议（变量名替换 + 框架推断）。
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
    example_fix_available = False

    # ── TaintGraph 污点链附加信息（PHP-TaintGraph 来源）──
    # 将 source 行号和变量名直接嵌入消息，悬停即可看到完整流向
    finding_source = finding.get("source", "")
    if finding_source == "PHP-TaintGraph" and finding.get("taint_var"):
        taint_var = finding["taint_var"]
        src_line = finding.get("taint_source_line", 0)
        sink_line = finding.get("line", 0)
        confidence = finding.get("confidence", "")
        cwe = finding.get("cwe", "")
        chain_info = f"\n\n[污点链] {taint_var} (第 {src_line} 行 Source → 第 {sink_line} 行 Sink)"
        if cwe:
            chain_info += f"  {cwe}"
        if confidence == "low":
            chain_info += "\n⚠ 变量已经过净化函数，建议人工确认净化充分性。"
        message = message.rstrip() + chain_info

    # M1：悬停时即可见修复建议 + 建议修复后的代码（智能模板：变量名替换 + 框架推断）
    fp = file_path or finding.get("file", "")
    if source_code and fp:
        try:
            smart = generate_smart_remediation(finding, source_code, fp)
            message = message.rstrip()
            if not message.endswith("。"):
                message += "。"
            message += "\n修复建议: " + smart.message
            if smart.suggested_code:
                message += "\n建议修复代码:\n" + smart.suggested_code
                example_fix_available = _is_actionable_example_code(smart.suggested_code)
        except (RuntimeError, ValueError, KeyError) as e:
            logger.debug("Smart remediation failed for %s: %s", fp, e)
    if not (source_code and fp) or not message.count("建议修复代码"):
        remediation = _get_remediation_for_rule(str(code).strip())
        if remediation and (remediation.get("remediation") or remediation.get("description")):
            first_tip = (
                (remediation.get("remediation") or [])[0]
                if remediation.get("remediation")
                else remediation.get("description", "")
            )
            if first_tip and "修复建议:" not in message:
                message = message.rstrip()
                if not message.endswith("。"):
                    message += "。"
                message += "\n修复建议: " + first_tip
            if "建议修复代码" not in message:
                if finding_source == "PHP-TaintGraph":
                    php_code = _PHP_REMEDIATION_CODE.get(str(code).strip())
                    if php_code:
                        message += "\n建议修复代码 (PHP):\n" + php_code.strip()
                        example_fix_available = _is_actionable_example_code(php_code)
                else:
                    framework_code = _pick_framework_suggested_code(remediation, fp or finding.get("file", ""))
                    if framework_code:
                        message += "\n建议修复代码:\n" + framework_code.strip()
                        example_fix_available = _is_actionable_example_code(framework_code)
                    elif remediation.get("suggested_code"):
                        suggested_code = remediation["suggested_code"].strip()
                        message += "\n建议修复代码:\n" + suggested_code
                        example_fix_available = _is_actionable_example_code(suggested_code)

    if "Aegis 可用操作:" not in message:
        message = message.rstrip() + "\n\n" + _build_action_guidance(example_fix_available)

    # related_locations -> Diagnostic.relatedInformation（TDD 7.2）
    related: list[lsp.DiagnosticRelatedInformation] = []
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

    # O3：将完整 taint path 数据附加到 diagnostic.data 供 Webview 使用
    diag_data: dict[str, Any] = {}
    taint_analysis = finding.get("taint_analysis") or {}
    full_path = taint_analysis.get("full_path")
    if full_path and taint_analysis.get("has_taint_path"):
        diag_data["taintPath"] = full_path
    elif finding.get("taint_details"):
        diag_data["taintPath"] = finding["taint_details"]

    return lsp.Diagnostic(
        range=range_,
        message=message,
        severity=severity,
        source="Aegis AI",
        code=code,
        related_information=related if related else None,
        data=diag_data if diag_data else None,
    )


def _get_remediation_for_rule(rule_id: str) -> dict[str, Any]:
    """
    根据规则类型（如 NOSQL_INJECTION）返回内置修复建议。
    M1：供 Code Action 使用，与 rag_enhancer.BUILTIN_REMEDIATION 一致。
    """
    return cast(dict[str, Any], BUILTIN_REMEDIATION.get(rule_id, {}))


# PHP 专属修复示例代码（TaintGraph finding 时使用，替代 rag_enhancer 里的 JS 示例）
_PHP_REMEDIATION_CODE: dict[str, str] = {
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
        "// PHP XSS 防御：使用 htmlspecialchars 转义输出\necho htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');"
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


def _pick_framework_suggested_code(remediation: dict[str, Any], file_path: str) -> str | None:
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
    framework_code_map: dict[str, str] = remediation.get("framework_suggested_code") or {}
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
    except OSError as e:
        logger.debug("Failed to read file header for framework detection: %s", e)
        return None

    # 按优先级匹配
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
        "django-orm",
        "mongoose",
        "mongodb",
    ]
    for fw in priority:
        if fw in header_lower and fw in framework_code_map:
            return framework_code_map[fw]

    return None


def _remediation_to_comment_text(rule_id: str, language: str | None = None) -> str:
    """将修复建议格式化为可插入的注释文本（多行）。"""
    data = _get_remediation_for_rule(rule_id)
    prefix = _comment_prefix_for_language(language)
    if not data:
        return f"{prefix} Aegis: {rule_id} - 请查阅安全修复指南"
    lines = [f"Aegis 修复建议 ({rule_id}):", f"{data.get('description', '')}"]
    for i, s in enumerate(data.get("remediation") or [], 1):
        lines.append(f"  {i}. {s}")
    refs = data.get("references") or []
    if refs:
        lines.append("参考:")
        for r in refs[:3]:
            lines.append(f"  {r}")
    return _build_comment_block(lines, language)


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


def scan_document(
    source: str,
    file_path: str,
    extra_rule_dirs: list[Path] | None = None,
    rules_allowed_root: Path | None = None,
) -> list[dict]:
    """
    调用 rule_engine 对源代码执行安全扫描。

    Args:
        source: 文件源代码
        file_path: 文件路径
        extra_rule_dirs: 额外 DSL 规则目录（LSP 从 initializationOptions.rules_dirs 传入）
        rules_allowed_root: 规则目录允许根（通常为工作区根）

    Returns:
        finding 列表。
    """
    language = detect_language(file_path)
    if language is None:
        return []

    from ..analysis.rule_engine import (
        analyze_go,
        analyze_java,
        analyze_javascript,
        analyze_php,
        analyze_python,
    )

    try:
        if language == "python":
            return cast(
                list[dict[str, Any]],
                analyze_python(
                    source,
                    file_path,
                    extra_rule_dirs=extra_rule_dirs,
                    rules_allowed_root=rules_allowed_root,
                ),
            )
        elif language in ("javascript", "typescript"):
            return cast(
                list[dict[str, Any]],
                analyze_javascript(
                    source,
                    file_path,
                    language=language,
                    extra_rule_dirs=extra_rule_dirs,
                    rules_allowed_root=rules_allowed_root,
                ),
            )
        elif language == "php":
            return cast(list[dict[str, Any]], analyze_php(source, file_path))
        elif language == "java":
            return cast(
                list[dict[str, Any]],
                analyze_java(
                    source,
                    file_path,
                    extra_rule_dirs=extra_rule_dirs,
                    rules_allowed_root=rules_allowed_root,
                ),
            )
        elif language == "go":
            return cast(
                list[dict[str, Any]],
                analyze_go(
                    source,
                    file_path,
                    extra_rule_dirs=extra_rule_dirs,
                    rules_allowed_root=rules_allowed_root,
                ),
            )
    except Exception as e:  # Intentional: re-raises as ScanError
        logger.exception("Scan failed for %s", file_path)
        raise ScanError(str(e)) from e

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
        init_opts = _coerce_payload(params.initialization_options)
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
        _schedule_validation(server, uri)

    # P1-2：扩展命令「扫描当前文件」触发的自定义通知
    @server.feature("aegis/requestScan")
    def on_request_scan(params: dict[str, Any] | None) -> None:
        payload = _coerce_payload(params)
        uri = payload.get("uri", "")
        if not uri:
            return
        try:
            doc = server.workspace.get_text_document(uri)
            _validate_document(server, uri, doc.source)
        except (RuntimeError, KeyError) as e:
            logger.warning("Manual scan failed for %s: %s", uri, e)

    # P1-2 / P5-4：扩展命令「扫描工作区」触发的自定义通知（遍历已打开的文档，发送进度）
    @server.feature("aegis/requestScanWorkspace")
    def on_request_scan_workspace(_params: dict[str, Any] | None) -> None:
        try:
            docs = getattr(server.workspace, "_documents", {})
            items = list(docs.items())
            total = len(items)
            if total == 0:
                server.protocol.notify(
                    "aegis/scanProgress",
                    {"current": 0, "total": 0, "uri": ""},
                )
            for idx, (uri, doc) in enumerate(items):
                try:
                    server.protocol.notify(
                        "aegis/scanProgress",
                        {"current": idx + 1, "total": total, "uri": uri},
                    )
                    _validate_document(server, uri, doc.source)
                except (RuntimeError, KeyError) as e:
                    logger.warning("Workspace scan failed for %s: %s", uri, e)
        except (RuntimeError, KeyError) as e:
            logger.warning("Workspace scan failed: %s", e)

    @server.feature(
        lsp.TEXT_DOCUMENT_CODE_ACTION,
        lsp.CodeActionOptions(code_action_kinds=[lsp.CodeActionKind.QuickFix]),
    )
    def code_action(params: lsp.CodeActionParams) -> list[lsp.CodeAction]:
        """
        M1：对 Aegis AI 的 Diagnostic 提供 Code Action。
        仅处理 context.diagnostics 中 source 为 "Aegis AI" 的项。
        """
        actions: list[lsp.CodeAction] = []
        uri = params.text_document.uri
        doc_lines: list[str] = []
        doc_source_for_actions = ""
        try:
            doc_for_actions = server.workspace.get_text_document(uri)
            doc_source_for_actions = doc_for_actions.source
            doc_lines = doc_source_for_actions.splitlines()
        except (RuntimeError, KeyError):
            doc_for_actions = None

        comment_block = _find_aegis_comment_block(doc_lines, params.range.start.line)
        if comment_block:
            start_line, end_line = comment_block
            if end_line < len(doc_lines):
                delete_end = lsp.Position(line=end_line, character=0)
            else:
                last_line = max(0, len(doc_lines) - 1)
                delete_end = lsp.Position(
                    line=last_line,
                    character=len(doc_lines[last_line]) if doc_lines else 0,
                )
            actions.append(
                lsp.CodeAction(
                    title="Aegis: Remove Inserted Remediation Comments",
                    kind=lsp.CodeActionKind.QuickFix,
                    edit=lsp.WorkspaceEdit(
                        changes={
                            uri: [
                                lsp.TextEdit(
                                    range=lsp.Range(
                                        start=lsp.Position(line=start_line, character=0),
                                        end=delete_end,
                                    ),
                                    new_text="",
                                )
                            ]
                        }
                    ),
                )
            )

        aegis_diagnostics = [
            d
            for d in (params.context.diagnostics or [])
            if (getattr(d, "source", None) or "").strip().lower() == "aegis ai"
        ]
        if not aegis_diagnostics:
            return actions

        # 懒加载 AI 分析器（仅在需要 AI 修复建议时创建）
        ai_analyzer: Any | None = getattr(server, "_ai_analyzer", None)
        if AI_ANALYZER_AVAILABLE and ai_analyzer is None:
            try:
                ai_analyzer = AIAnalyzer(enabled=bool(_workspace_ctx._init_options.get("ai_enabled", True)))
                cast(Any, server)._ai_analyzer = ai_analyzer
            except (ImportError, RuntimeError):
                ai_analyzer = None

        for diag in aegis_diagnostics:
            preferred_actions: list[lsp.CodeAction] = []
            replacement_actions: list[lsp.CodeAction] = []
            guidance_actions: list[lsp.CodeAction] = []
            suppression_actions: list[lsp.CodeAction] = []
            rule_id = getattr(diag, "code", None) or ""
            if isinstance(rule_id, lsp.CodeDescription):
                rule_id = ""
            rule_id = str(rule_id).strip() or "UNKNOWN"
            remediation = _get_remediation_for_rule(rule_id)
            insert_line = diag.range.start.line
            insert_pos = lsp.Position(line=insert_line, character=0)

            # ── O1：Inline Suppression — 忽略此行的此规则 ──
            # 检测文件语言以选择正确的注释风格
            file_path_for_comment = uri_to_filepath(uri)
            lang_for_comment = detect_language(file_path_for_comment)
            comment_text = _remediation_to_comment_text(rule_id, lang_for_comment)
            ignore_prefix = _comment_prefix_for_language(lang_for_comment)
            ignore_comment = f"{ignore_prefix} aegis-ignore: {rule_id}"

            # 获取当前行的缩进
            try:
                doc_for_indent = server.workspace.get_text_document(uri)
                doc_lines = doc_for_indent.source.splitlines()
                indent = _get_line_indent(doc_lines, insert_line)
            except (RuntimeError, KeyError):
                indent = ""

            ignore_edit = lsp.WorkspaceEdit(
                changes={
                    uri: [
                        lsp.TextEdit(
                            range=lsp.Range(start=insert_pos, end=insert_pos),
                            new_text=indent + ignore_comment + "\n",
                        ),
                    ]
                }
            )
            suppression_actions.append(
                lsp.CodeAction(
                    title=f"Aegis: Ignore this finding ({rule_id}, suppression only)",
                    kind=lsp.CodeActionKind.QuickFix,
                    diagnostics=[diag],
                    edit=ignore_edit,
                )
            )

            # ── O1：Inline Suppression — 忽略此行的所有规则 ──
            ignore_all_comment = f"{ignore_prefix} aegis-ignore"

            ignore_all_edit = lsp.WorkspaceEdit(
                changes={
                    uri: [
                        lsp.TextEdit(
                            range=lsp.Range(start=insert_pos, end=insert_pos),
                            new_text=indent + ignore_all_comment + "\n",
                        ),
                    ]
                }
            )
            suppression_actions.append(
                lsp.CodeAction(
                    title="Aegis: Ignore all on this line (suppression only)",
                    kind=lsp.CodeActionKind.QuickFix,
                    diagnostics=[diag],
                    edit=ignore_all_edit,
                )
            )

            # ── O1：Add to Baseline — 将 finding 写入 .aegis-baseline.json ──
            suppression_actions.append(
                lsp.CodeAction(
                    title=f"Aegis: Add to baseline ({rule_id}, suppression only)",
                    kind=lsp.CodeActionKind.QuickFix,
                    diagnostics=[diag],
                    command=lsp.Command(
                        title="Add to baseline",
                        command="aegis.addToBaseline",
                        arguments=[
                            {
                                "uri": uri,
                                "rule_id": rule_id,
                                "line": diag.range.start.line + 1,
                                "message": diag.message[:200],
                            }
                        ],
                    ),
                )
            )

            # M1 4.3：插入修复建议注释
            new_text = _indent_block(comment_text, indent) + "\n"
            edit = lsp.WorkspaceEdit(
                changes={
                    uri: [
                        lsp.TextEdit(range=lsp.Range(start=insert_pos, end=insert_pos), new_text=new_text),
                    ]
                }
            )
            guidance_actions.append(
                lsp.CodeAction(
                    title=f"Aegis: 插入修复建议注释（{rule_id}，不会修复代码）",
                    kind=lsp.CodeActionKind.QuickFix,
                    diagnostics=[diag],
                    edit=edit,
                )
            )

            # M1 4.4：若有 suggested_code，提供「应用示例代码」Quick Fix
            example_code = ""
            try:
                if doc_source_for_actions:
                    smart_example = generate_smart_remediation(
                        {
                            "type": rule_id,
                            "line": diag.range.start.line + 1,
                            "start_line": diag.range.start.line + 1,
                            "end_line": diag.range.end.line + 1,
                        },
                        doc_source_for_actions,
                        file_path_for_comment,
                    ).suggested_code
                    if smart_example:
                        example_code = smart_example
            except (RuntimeError, ValueError, KeyError) as e:
                logger.debug("Smart example code generation failed for %s: %s", rule_id, e)
            if not example_code:
                suggested = (remediation or {}).get("suggested_code")
                if suggested and isinstance(suggested, str):
                    example_code = suggested

            if example_code and _is_actionable_example_code(example_code):
                code_text = _indent_block(example_code.strip(), indent) + "\n"
                replace_range = _replacement_range_for_diagnostic(diag, doc_lines)
                code_edit = lsp.WorkspaceEdit(
                    changes={
                        uri: [
                            lsp.TextEdit(
                                range=replace_range,
                                new_text=code_text,
                            ),
                        ]
                    }
                )
                replacement_actions.append(
                    lsp.CodeAction(
                        title=f"Aegis: 应用示例修复代码（{rule_id}，会替换代码并触发复扫）",
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

                finding_like: dict[str, Any] = {
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
                        cache_key = (uri, rule_id, diag_start_line)
                        ai_cache = getattr(server, "_ai_cache", None)
                        if ai_cache is None:
                            cast(Any, server)._ai_cache = {}
                            ai_cache = getattr(server, "_ai_cache", {})
                        # Evict oldest entries when cache exceeds 256 items
                        if ai_cache and len(ai_cache) > 256:
                            keys_to_remove = list(ai_cache.keys())[:64]
                            for k in keys_to_remove:
                                ai_cache.pop(k, None)
                        result = ai_cache.get(cache_key) if ai_cache else None
                        if result is None:
                            doc_source: str | None = None
                            try:
                                doc = server.workspace.get_text_document(uri)
                                doc_source = doc.source
                            except (RuntimeError, KeyError) as e:
                                logger.debug("Failed to get document source for AI analysis: %s", e)
                            result = ai_analyzer.analyze_finding(
                                finding_like,
                                language=lang,
                                source_code=doc_source,
                            )
                            if ai_cache is not None and result:
                                ai_cache[cache_key] = result

                        if result:
                            # ── 高置信度（>= 0.75）且有修复代码：直接替换漏洞行 ──
                            if result.fixed_code and result.confidence >= 0.75 and not result.requires_review:
                                # 替换整个漏洞 range（保留缩进：从 result.fixed_code 原样写入）
                                replace_range = lsp.Range(
                                    start=_replacement_range_for_diagnostic(diag, doc_lines).start,
                                    end=_replacement_range_for_diagnostic(diag, doc_lines).end,
                                )
                                fixed_text = result.fixed_code
                                fixed_text = _indent_block(fixed_text.strip(), indent) + "\n"
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
                                preview = (fixed_text.strip().replace("\n", " "))[:40]
                                if len(fixed_text.strip()) > 40:
                                    preview += "…"
                                title = f"Aegis: 应用 AI 精准修复（{rule_id}，会替换代码并触发复扫）"
                                if preview:
                                    title += f" | {preview}"
                                preferred_actions.append(
                                    lsp.CodeAction(
                                        title=title,
                                        kind=lsp.CodeActionKind.QuickFix,
                                        diagnostics=[diag],
                                        edit=replace_edit,
                                        is_preferred=True,
                                    )
                                )

                            # ── 低置信度或无 fixed_code：插入 diff 格式注释 ──
                            else:
                                comment_lines = [f"Aegis AI 修复建议 ({rule_id}) 置信度 {result.confidence:.0%}"]
                                if result.requires_review:
                                    comment_lines.append("⚠ 需人工复核")

                                if result.fix_suggestion:
                                    comment_lines.append(f"思路: {result.fix_suggestion}")

                                if result.fixed_code:
                                    comment_lines.append("建议修改为:")
                                    for ln in result.fixed_code.splitlines():
                                        comment_lines.append(ln)

                                ai_comment = _build_comment_block(comment_lines, lang_for_comment, indent)
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
                                preview = (
                                    (result.fixed_code or result.fix_suggestion or "").strip().replace("\n", " ")[:40]
                                )
                                if preview and len((result.fixed_code or result.fix_suggestion or "").strip()) > 40:
                                    preview += "…"
                                title = f"Aegis: 插入 AI 修复建议（{rule_id}，不会修复代码）"
                                if preview:
                                    title += f" | {preview}"
                                guidance_actions.append(
                                    lsp.CodeAction(
                                        title=title,
                                        kind=lsp.CodeActionKind.QuickFix,
                                        diagnostics=[diag],
                                        edit=ai_edit,
                                    )
                                )
                except (RuntimeError, KeyError, ValueError):
                    # AI 分析失败时静默忽略，不影响其他 CodeAction
                    logger.exception("AI remediation generation failed for %s", rule_id)
            actions.extend(preferred_actions)
            actions.extend(replacement_actions)
            actions.extend(guidance_actions)
            actions.extend(suppression_actions)
        return actions

    # ── O1: aegis.addToBaseline 命令处理（Code Action command 触发）──
    @server.command("aegis.addToBaseline")
    def on_add_to_baseline(args: list[Any]) -> None:
        """将 finding 加入 .aegis-baseline.json（工作区根目录）。"""
        if not args:
            return
        params = _coerce_payload(args[0])
        finding_uri = params.get("uri", "")
        rule_id = params.get("rule_id", "UNKNOWN")
        line = int(params.get("line", 0))
        if not finding_uri or not line:
            return

        file_path = uri_to_filepath(finding_uri)
        # 推断工作区根目录
        project_root = None
        root_str = getattr(_workspace_ctx, "_project_path", None)
        if root_str:
            project_root = Path(root_str)
        else:
            project_root = Path(file_path).parent

        baseline_path = project_root / ".aegis-baseline.json"
        baseline = Baseline.load(baseline_path)

        finding_like = {
            "type": rule_id,
            "file": file_path,
            "line": line,
        }
        baseline.add_findings({file_path: [finding_like]}, project_root)
        baseline.save(baseline_path, project_root)
        logger.info("Added finding to baseline: %s:%s@L%d", rule_id, file_path, line)
        try:
            server.window_show_message(
                lsp.ShowMessageParams(
                    type=lsp.MessageType.Info,
                    message=f"Aegis: 已加入 baseline -> {baseline_path.name} ({rule_id})",
                )
            )
            server.window_log_message(
                lsp.LogMessageParams(
                    type=lsp.MessageType.Info,
                    message=f"[Aegis] Baseline updated: {baseline_path}",
                )
            )
        except RuntimeError as e:
            logger.debug("Failed to notify baseline update: %s", e)

        # 重新扫描当前文件以刷新 diagnostics（baseline 中的 finding 将被过滤）
        try:
            doc = server.workspace.get_text_document(finding_uri)
            _validate_document(server, finding_uri, doc.source)
        except (RuntimeError, KeyError):
            pass

    # ── O2: aegis/generateFix — 为 Diff Preview 生成 AI 修复代码 ──
    @server.feature("aegis/generateFix")
    def on_generate_fix(params: dict[str, Any] | None) -> dict[str, Any] | None:
        """生成 AI 修复代码并返回给客户端预览。"""
        payload = _coerce_payload(params)
        if not payload:
            return None
        fix_uri = payload.get("uri", "")
        rule_id = str(payload.get("rule_id", "UNKNOWN")).strip()
        start_line = int(payload.get("start_line", 0))
        end_line = int(payload.get("end_line", start_line))
        message = payload.get("message", "")

        def _error_response(error_code: str, error_message: str) -> dict[str, Any]:
            return {
                "uri": fix_uri,
                "rule_id": rule_id,
                "error_code": error_code,
                "error_message": error_message,
                "start_line": start_line,
                "end_line": end_line,
                "requires_review": True,
            }

        if not fix_uri or not start_line:
            return None

        file_path = uri_to_filepath(fix_uri)
        lang = detect_language(file_path)

        # 获取文档源码
        try:
            doc = server.workspace.get_text_document(fix_uri)
            source = doc.source
        except (RuntimeError, KeyError):
            return None

        # 尝试从 AI 缓存获取
        ai_analyzer_inst = getattr(server, "_ai_analyzer", None)
        if AI_ANALYZER_AVAILABLE and ai_analyzer_inst is None:
            try:
                ai_analyzer_inst = AIAnalyzer(enabled=bool(_workspace_ctx._init_options.get("ai_enabled", True)))
                cast(Any, server)._ai_analyzer = ai_analyzer_inst
            except (ImportError, RuntimeError):
                ai_analyzer_inst = None

        if ai_analyzer_inst is None or not getattr(ai_analyzer_inst, "enabled", False):
            return _error_response(
                "provider_not_configured",
                "AI provider is not configured. Set Aegis › AI: Provider and the matching API key.",
            )

        cache_key = (fix_uri, rule_id, start_line)
        ai_cache = getattr(server, "_ai_cache", {})
        result = ai_cache.get(cache_key) if ai_cache else None

        if result is None:
            finding_like = {
                "type": rule_id,
                "severity": "High",
                "file": file_path,
                "line": start_line,
                "start_line": start_line,
                "end_line": end_line,
                "details": message,
                "language": lang,
            }
            try:
                result = ai_analyzer_inst.analyze_finding(
                    finding_like,
                    language=lang,
                    source_code=source,
                )
                if result and ai_cache is not None:
                    ai_cache[cache_key] = result
            except (RuntimeError, KeyError, ValueError) as e:
                logger.warning("generateFix AI analyze failed: %s", e)
                return _error_response("provider_unavailable", f"AI provider request failed: {e}")

        if not result:
            return _error_response("provider_unavailable", "AI provider did not return a result.")

        if getattr(result, "error_code", None):
            return _error_response(
                str(result.error_code),
                str(result.error_message or "AI fix request failed."),
            )

        if not result.fixed_code:
            return _error_response(
                "no_applicable_fix",
                "AI reviewed this finding but did not return a safe replacement.",
            )

        return {
            "uri": fix_uri,
            "rule_id": rule_id,
            "fixed_code": result.fixed_code,
            "confidence": result.confidence,
            "fix_suggestion": result.fix_suggestion or "",
            "start_line": result.fix_start_line or start_line,
            "end_line": result.fix_end_line or end_line,
            "requires_review": result.requires_review,
        }

    # ── O3: aegis/getTaintPath — 返回指定 finding 的完整 taint path ──
    @server.feature("aegis/getTaintPath")
    def on_get_taint_path(params: dict[str, Any] | None) -> dict[str, Any] | None:
        """返回指定 finding 的完整 taint path 用于 Webview 渲染。"""
        payload = _coerce_payload(params)
        if not payload:
            return None
        tp_uri = payload.get("uri", "")
        tp_line = int(payload.get("line", 0))
        tp_rule_id = str(payload.get("ruleId", "")).strip()
        if not tp_uri or not tp_line:
            return None

        cached = _findings_cache.get(tp_uri, [])
        for f in cached:
            f_line = int(f.get("line", 0))
            f_type = str(f.get("type", f.get("rule_id", ""))).strip()
            if f_line == tp_line and f_type == tp_rule_id:
                taint_analysis = f.get("taint_analysis") or {}
                full_path = taint_analysis.get("full_path")
                if full_path:
                    return {
                        "vulnType": f_type,
                        "severity": f.get("severity", "Medium"),
                        "taintPath": full_path,
                    }
                # Fallback: taint_details from to_dict()
                taint_details = f.get("taint_details")
                if taint_details:
                    return {
                        "vulnType": f_type,
                        "severity": f.get("severity", "Medium"),
                        "taintPath": taint_details,
                    }
                return None
        return None

    return server


def _cancel_pending_validation(uri: str) -> None:
    """M2：取消该 URI 的待执行防抖验证（限流：同一文档仅保留最新一次）。"""
    with _pending_lock:
        timer = _pending_validation.pop(uri, None)
    if timer is not None:
        try:
            timer.cancel()
        except RuntimeError as e:
            logger.debug("Failed to cancel pending timer for %s: %s", uri, e)


def _schedule_validation(server: LanguageServer, uri: str, delay: float = DEBOUNCE_SECONDS) -> None:
    """为指定文档安排一次防抖验证。"""
    _cancel_pending_validation(uri)
    timer = threading.Timer(
        delay,
        _debounced_validate,
        args=(server, uri),
    )
    timer.daemon = True
    with _pending_lock:
        _pending_validation[uri] = timer
    timer.start()


def _debounced_validate(server: LanguageServer, uri: str) -> None:
    """M2：防抖到期后从 workspace 取当前文档内容并执行验证。"""
    with _pending_lock:
        _pending_validation.pop(uri, None)
    try:
        doc = server.workspace.get_text_document(uri)
        source = doc.source
    except (RuntimeError, KeyError):
        server.text_document_publish_diagnostics(lsp.PublishDiagnosticsParams(uri=uri, diagnostics=[]))
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
        server.text_document_publish_diagnostics(lsp.PublishDiagnosticsParams(uri=uri, diagnostics=[]))
        return

    project_root = getattr(_workspace_ctx, "_project_path", None)
    if _is_path_excluded(file_path, project_root, _workspace_ctx.exclude_patterns):
        logger.info("Skipping excluded file for LSP scan: %s", file_path)
        server.text_document_publish_diagnostics(lsp.PublishDiagnosticsParams(uri=uri, diagnostics=[]))
        return

    # P1-3：文件过大则跳过并清空诊断
    try:
        fpath = Path(file_path)
        if fpath.exists() and fpath.stat().st_size > MAX_FILE_SIZE_BYTES:
            logger.info(
                "Skipping oversized file (%d bytes): %s",
                fpath.stat().st_size,
                file_path,
            )
            server.text_document_publish_diagnostics(lsp.PublishDiagnosticsParams(uri=uri, diagnostics=[]))
            return
    except OSError:
        pass

    # ── 通知前端：扫描开始 ───────────────────────────────────────────────────
    try:
        server.protocol.notify("aegis/scanStart", {"uri": uri})
    except RuntimeError as e:
        logger.debug("Failed to send scanStart notification: %s", e)

    # 记录扫描开始时的文档版本（若有）
    version_before: int | None = None
    try:
        doc = server.workspace.get_text_document(uri)
        version_before = doc.version
    except RuntimeError as e:
        logger.debug("Failed to get document version: %s", e)

    # 可选：从 initializationOptions.rules_dirs 解析额外规则目录
    extra_rule_dirs: list[Path] | None = None
    rules_allowed_root: Path | None = None
    try:
        root_str = getattr(_workspace_ctx, "_project_path", None)
        rules_allowed_root = Path(root_str) if root_str else Path(file_path).parent
        raw_dirs = _workspace_ctx._init_options.get("rules_dirs") or []
        if raw_dirs:
            extra_rule_dirs = []
            for d in raw_dirs:
                p = Path(d) if not isinstance(d, Path) else Path(str(d))
                if not p.is_absolute() and rules_allowed_root:
                    p = rules_allowed_root / p
                p = p.resolve()
                if p.is_dir():
                    try:
                        if rules_allowed_root:
                            p.relative_to(rules_allowed_root)
                        extra_rule_dirs.append(p)
                    except ValueError:
                        logger.debug("Skip rules_dir outside workspace: %s", p)
    except RuntimeError as e:
        logger.debug("Resolving rules_dirs: %s", e)

    # O5: 增量分析 — 检测是否只有部分函数变化，尝试复用缓存
    _incremental_used = False
    changed_funcs, full_rescan = _incremental_analyzer.get_changed_functions(file_path, source, language)
    if not full_rescan and not changed_funcs:
        # 完全未变化 — 使用缓存结果
        cached_findings = _incremental_analyzer.get_cached_findings(file_path)
        if cached_findings is not None:
            findings = cached_findings
            _incremental_used = True
            logger.debug("Incremental: using cached findings for %s", file_path)

    if not _incremental_used:
        # P1-3：单次扫描超时，避免巨型或复杂文件拖死
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    scan_document,
                    source,
                    file_path,
                    extra_rule_dirs,
                    rules_allowed_root,
                )
                findings = future.result(timeout=SCAN_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError:
            logger.warning(
                "Scan timed out after %.0fs for %s",
                SCAN_TIMEOUT_SECONDS,
                file_path,
            )
            findings = []
        except ScanError as e:
            logger.warning("Scan error for %s: %s", file_path, e)
            try:
                server.protocol.notify(
                    NOTIFICATION_SCAN_ERROR,
                    {"uri": uri, "message": str(e)},
                )
            except RuntimeError as send_err:
                logger.debug("Failed to send scanError notification: %s", send_err)
            server.text_document_publish_diagnostics(lsp.PublishDiagnosticsParams(uri=uri, diagnostics=[]))
            return

        # O5: 更新增量缓存
        _incremental_analyzer.update_cache(file_path, source, language, findings)

        # O5: 更新依赖追踪 & 检查是否需要重扫导入方
        project_root_str = getattr(_workspace_ctx, "_project_path", None) or str(Path(file_path).parent)
        _dependency_tracker.update_imports(file_path, source, language, project_root_str)
        if _dependency_tracker.update_export_hash(file_path, source):
            affected = _dependency_tracker.get_affected_files(file_path) - {file_path}
            for affected_fp in affected:
                logger.info("O5: export change in %s triggers rescan of %s", file_path, affected_fp)
                _incremental_analyzer.invalidate(affected_fp)

    # 合并跨文件分析结果
    cross_file_findings = _workspace_ctx.get_cross_file_findings(file_path)
    if cross_file_findings:
        findings = findings + cross_file_findings
        logger.info(
            "Merged %d cross-file findings for %s",
            len(cross_file_findings),
            file_path,
        )

    # 过滤已禁用的规则
    disabled = set(_workspace_ctx.disabled_rules)
    if disabled:
        findings = [f for f in findings if f.get("type", f.get("rule_id", "")) not in disabled]

    # O1: 过滤 aegis-ignore 行级抑制
    from ..scanner.baseline import filter_suppressed_findings

    findings = filter_suppressed_findings(findings, source)

    # O1: 过滤 .aegis-baseline.json 中的已抑制 findings
    project_root = None
    root_str = getattr(_workspace_ctx, "_project_path", None)
    if root_str:
        project_root = Path(root_str)
    else:
        project_root = Path(file_path).parent
    baseline_path = project_root / ".aegis-baseline.json"
    if baseline_path.exists():
        try:
            baseline = Baseline.load(baseline_path)
            findings = [f for f in findings if not baseline.contains(f, project_root)]
        except (OSError, ValueError) as e:
            logger.debug("Failed to load baseline: %s", e)

    # 过滤低于最低严重度的发现
    _severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    min_sev = _severity_order.get(_workspace_ctx.severity_minimum, 1)
    if min_sev > 1:
        findings = [f for f in findings if _severity_order.get(f.get("severity", "Medium"), 2) >= min_sev]

    # 发布前再次读取版本；若文档已被用户修改，丢弃本次结果并清空诊断
    try:
        doc = server.workspace.get_text_document(uri)
        if version_before is not None and doc.version != version_before:
            logger.info(
                "Document %s version changed (%s -> %s), skipping publish",
                uri,
                version_before,
                doc.version,
            )
            _schedule_validation(server, uri, delay=0.05)
            return
    except RuntimeError as e:
        logger.debug("Failed to check document version: %s", e)

    diagnostics = [finding_to_diagnostic(f, uri, source_code=source, file_path=file_path) for f in findings]
    issue_count = len(diagnostics)

    # O3: 缓存 findings 用于后续 aegis/getTaintPath 查询
    _findings_cache[uri] = findings

    logger.info(
        "Published %d diagnostics for %s (%s)",
        issue_count,
        file_path,
        language,
    )
    server.text_document_publish_diagnostics(lsp.PublishDiagnosticsParams(uri=uri, diagnostics=diagnostics))

    # ── 通知前端：扫描结束（含问题数量，驱动 Status Bar 更新）─────────────
    try:
        server.protocol.notify("aegis/scanEnd", {"uri": uri, "issueCount": issue_count})
    except RuntimeError as e:
        logger.debug("Failed to send scanEnd notification: %s", e)

    # ── B3：后台预缓存 Critical/High 的 AI 修复结果，Code Action 时即显 ──
    def _precache_ai() -> None:
        try:
            ai_analyzer = getattr(server, "_ai_analyzer", None)
            if not AI_ANALYZER_AVAILABLE or ai_analyzer is None:
                return
            if not getattr(ai_analyzer, "enabled", False):
                return
            cache = getattr(server, "_ai_cache", None)
            if cache is None:
                cast(Any, server)._ai_cache = {}
                cache = getattr(server, "_ai_cache", {})
            for f in findings:
                if f.get("severity") not in ("Critical", "High"):
                    continue
                rule_id = f.get("type") or f.get("rule_id") or ""
                line_no = int(f.get("line") or f.get("start_line") or 0)
                if not rule_id or not line_no:
                    continue
                key = (uri, str(rule_id).strip(), line_no)
                if key in cache:
                    continue
                finding_like = {
                    "type": rule_id,
                    "severity": f.get("severity", "High"),
                    "file": file_path,
                    "line": line_no,
                    "start_line": line_no,
                    "end_line": int(f.get("end_line") or line_no),
                    "details": f.get("details", ""),
                    "language": language,
                }
                try:
                    result = ai_analyzer.analyze_finding(
                        finding_like,
                        language=language,
                        source_code=source,
                    )
                    if result:
                        cache[key] = result
                except (RuntimeError, KeyError, ValueError) as e:
                    logger.warning("AI precache failed for %s: %s", key, e)
        except Exception as e:  # Intentional: top-level thread safety catch
            logger.warning("AI precache thread failed: %s", e)

    t = threading.Thread(target=_precache_ai, daemon=True)
    t.start()
