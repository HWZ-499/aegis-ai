"""
analysis_context.py - 分析上下文对象（阶段二增强版）

统一为所有规则提供：
- 当前文件路径 / 语言 / 框架等元信息
- 符号表、数据流图等可扩展分析状态
- 数据流追踪器（用于污点分析）
- Sanitizer 感知查询
- 一个集中存放扫描结果的 findings 列表
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .dataflow_tracker import DataFlowTracker


def make_related_location(
    file_path: str,
    start_line: int,
    end_line: Optional[int] = None,
    message: str = "",
    start_character: int = 0,
    end_character: int = 999,
) -> Dict[str, Any]:
    """
    构建 TDD 7.1 规定的 related_locations 中单条 Location 字典。

    LSP 转换层会将其映射为 DiagnosticRelatedInformation。
    """
    return {
        "file_path": file_path,
        "start_line": start_line,
        "end_line": end_line if end_line is not None else start_line,
        "start_character": start_character,
        "end_character": end_character,
        "message": message,
    }


def tree_sitter_node_to_range(node: Any) -> Dict[str, int]:
    """
    从 Tree-sitter 节点提取 TDD 7.1 规定的精确定位字段。

    用于 Finding 的 start_line / start_character / end_line / end_character，
    IDE 可据此做字符级高亮。Tree-sitter 使用 0-based (row, column)。

    Returns:
        含 start_line(1-based), start_character(0-based), end_line(1-based), end_character(0-based) 的字典；
        若节点无 start_point/end_point 则返回空字典。
    """
    if node is None:
        return {}
    start = getattr(node, "start_point", None)
    end = getattr(node, "end_point", None)
    if start is None or end is None:
        return {}
    return {
        "start_line": start[0] + 1,
        "start_character": start[1],
        "end_line": end[0] + 1,
        "end_character": end[1],
    }


@dataclass
class AnalysisContext:
    """
    分析上下文（阶段二增强版）。

    说明：
    - 这是"规则引擎"和"具体规则"之间的共享状态容器。
    - 所有规则都通过它来：
      - 读取基本信息（file_path, language, framework 等）
      - 读取/写入分析结构（symbol_table, dataflow_graph 等）
      - 使用数据流追踪器进行污点分析
      - 查询变量是否经过 Sanitizer 净化
      - 追加新的漏洞发现（findings）
    """

    file_path: Path
    language: str

    # 技术栈 / 框架等高层信息（例如 "django" / "express" / "spring-boot"）
    framework: Optional[str] = None

    # 预留：符号表、数据流图等将来做污点分析时会用到
    symbol_table: Dict[str, Any] = field(default_factory=dict)
    dataflow_graph: Any = None

    # 数据流追踪器（用于污点分析 + Sanitizer 感知）
    dataflow_tracker: Optional["DataFlowTracker"] = None

    # 污点图（2.1 统一污点系统：优先于 dataflow_tracker，规则通过本图查询）
    taint_graph: Any = None

    # 当前文件中已发现的问题列表
    findings: List[Dict[str, Any]] = field(default_factory=list)

    # 其他可扩展的上下文信息
    extras: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """初始化后处理：自动创建数据流追踪器。"""
        if self.dataflow_tracker is None:
            from .dataflow_tracker import DataFlowTracker
            self.dataflow_tracker = DataFlowTracker(language=self.language)

    # ──────────────────────────────────────────────
    # Finding 管理
    # ──────────────────────────────────────────────

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """
        向上下文中追加一条扫描结果。

        要求至少包含: type, severity, line 等字段。
        """
        if not isinstance(finding, dict):
            raise TypeError("finding 必须是 dict")

        finding.setdefault("file", str(self.file_path))
        finding.setdefault("language", self.language)
        self.findings.append(finding)

    # ──────────────────────────────────────────────
    # 污点查询便捷方法
    # ──────────────────────────────────────────────

    def is_var_tainted(self, var_name: str) -> bool:
        """检查变量是否被污染（且未经净化）。优先查 taint_graph，否则 dataflow_tracker。"""
        if self.taint_graph is not None:
            return self.taint_graph.is_var_tainted(var_name, str(self.file_path))
        if self.dataflow_tracker:
            return self.dataflow_tracker.is_tainted(var_name)
        return False

    def is_var_sanitized(self, var_name: str) -> bool:
        """检查变量是否经过 Sanitizer 净化。优先查 taint_graph。"""
        if self.taint_graph is not None:
            return self.taint_graph.is_var_sanitized(var_name)
        if self.dataflow_tracker:
            return self.dataflow_tracker.is_sanitized(var_name)
        return False

    def get_sanitizer_name(self, var_name: str) -> Optional[str]:
        """获取变量经过的净化器名称（如 ``"parseInt"``）。优先查 taint_graph。"""
        if self.taint_graph is not None:
            return self.taint_graph.get_sanitizer_name(var_name)
        if self.dataflow_tracker:
            return self.dataflow_tracker.get_sanitizer_name(var_name)
        return None

    def has_tracked_var(self, var_name: str) -> bool:
        """变量是否已被追踪。优先查 taint_graph，否则 dataflow_tracker。"""
        if self.taint_graph is not None:
            return self.taint_graph.has_tracked_var(var_name, str(self.file_path))
        if self.dataflow_tracker:
            return self.dataflow_tracker.has_tracked_var(var_name)
        return False

    def get_taint_source(self, var_name: str) -> Optional[Any]:
        """
        获取变量的污点来源信息（规则层兼容）。
        返回具有 .source_expr / .source_type / .line 的对象，无则 None。
        """
        if self.taint_graph is not None:
            info = self.taint_graph.get_taint_source_info(var_name, str(self.file_path))
            return SimpleNamespace(**info) if info else None
        if self.dataflow_tracker:
            return self.dataflow_tracker.get_taint_source(var_name)
        return None

    # ──────────────────────────────────────────────
    # 追踪便捷方法
    # ──────────────────────────────────────────────

    def track_assignment(self, var_name: str, value_expr: str, line: int) -> None:
        """追踪变量赋值。"""
        if self.dataflow_tracker:
            self.dataflow_tracker.track_assignment(var_name, value_expr, line)
