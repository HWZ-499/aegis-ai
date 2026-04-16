"""
taint_graph.py - 污点图数据结构

实现污点分析的核心数据结构：
- TaintNode：污点图中的节点（变量、表达式、函数调用）
- TaintEdge：污点图中的边（数据流传播关系）
- TaintGraph：完整的污点图，支持路径查询
- TaintPath：从 Source 到 Sink 的污点路径
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class NodeType(Enum):
    """节点类型"""

    SOURCE = auto()  # 污点源（用户输入）
    SINK = auto()  # 汇点（敏感操作）
    VARIABLE = auto()  # 变量
    PARAMETER = auto()  # 函数参数
    RETURN_VALUE = auto()  # 返回值
    PROPERTY = auto()  # 对象属性
    CALL_ARG = auto()  # 函数调用参数
    SANITIZER = auto()  # 净化器


class EdgeType(Enum):
    """边类型"""

    ASSIGNMENT = auto()  # 赋值：x = source
    PROPAGATION = auto()  # 传播：y = f(x) where x is tainted
    PARAMETER_PASS = auto()  # 参数传递：func(taintedVar)
    RETURN = auto()  # 返回：return taintedVar
    PROPERTY_ACCESS = auto()  # 属性访问：obj.prop = tainted
    ARRAY_ACCESS = auto()  # 数组访问：arr[i] = tainted
    CONCAT = auto()  # 字符串拼接：str + tainted
    SANITIZE = auto()  # 净化：escaped = escape(tainted)


@dataclass
class TaintNode:
    """
    污点图中的节点。

    表示一个可能被污染的数据点（变量、表达式、函数调用等）。
    """

    # 唯一标识符（自动生成）
    id: str = ""

    # 基本信息
    name: str = ""  # 节点名称（变量名、表达式等）
    node_type: NodeType = NodeType.VARIABLE

    # 位置信息
    file_path: str = ""  # 文件路径
    line: int = 0  # 行号
    column: int = 0  # 列号

    # 污点信息
    is_tainted: bool = False  # 是否被污染
    taint_level: int = 0  # 污点级别（0-4）
    source_pattern: str = ""  # 匹配的 Source 模式
    sink_pattern: str = ""  # 匹配的 Sink 模式

    # AST 信息
    ast_type: str = ""  # AST 节点类型
    code_snippet: str = ""  # 代码片段

    # 额外信息
    extras: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """自动生成唯一 ID"""
        if not self.id:
            content = f"{self.file_path}:{self.line}:{self.column}:{self.name}"
            self.id = hashlib.md5(content.encode()).hexdigest()[:12]

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, TaintNode):
            return self.id == other.id
        return False

    def is_source(self) -> bool:
        """是否是污点源"""
        return self.node_type == NodeType.SOURCE

    def is_sink(self) -> bool:
        """是否是汇点"""
        return self.node_type == NodeType.SINK

    def is_sanitizer(self) -> bool:
        """是否是净化器"""
        return self.node_type == NodeType.SANITIZER


@dataclass
class TaintEdge:
    """
    污点图中的边。

    表示两个节点之间的数据流关系。
    """

    # 唯一标识符
    id: str = ""

    # 连接的节点
    from_node: str = ""  # 源节点 ID
    to_node: str = ""  # 目标节点 ID

    # 边类型
    edge_type: EdgeType = EdgeType.ASSIGNMENT

    # 位置信息
    line: int = 0  # 发生数据流的行号

    # 额外信息
    description: str = ""  # 描述
    extras: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """自动生成唯一 ID"""
        if not self.id:
            content = f"{self.from_node}->{self.to_node}:{self.edge_type.name}"
            self.id = hashlib.md5(content.encode()).hexdigest()[:12]

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, TaintEdge):
            return self.id == other.id
        return False


@dataclass
class TaintPath:
    """
    从 Source 到 Sink 的污点路径。

    记录完整的数据流传播链路。
    """

    # 路径信息
    source_node: TaintNode | None = None  # 起始节点（Source）
    sink_node: TaintNode | None = None  # 结束节点（Sink）
    path_nodes: list[TaintNode] = field(default_factory=list)  # 中间节点
    path_edges: list[TaintEdge] = field(default_factory=list)  # 边序列

    # 净化信息
    is_sanitized: bool = False  # 是否被净化
    sanitizer_node: TaintNode | None = None  # 净化器节点

    # 风险评估
    risk_level: str = "High"  # 风险级别
    confidence: float = 1.0  # 置信度 (0-1)

    def __len__(self):
        """路径长度（节点数）"""
        return len(self.path_nodes) + 2  # +2 for source and sink

    def get_full_path(self) -> list[TaintNode]:
        """获取完整路径（包含 source 和 sink）"""
        if self.source_node is None:
            return self.path_nodes
        result = [self.source_node] + self.path_nodes
        if self.sink_node:
            result.append(self.sink_node)
        return result

    def to_string(self) -> str:
        """转换为可读字符串"""
        parts = []
        for node in self.get_full_path():
            location = f"{node.file_path}:{node.line}" if node.file_path else f"L{node.line}"
            parts.append(f"{node.name} ({location})")
        return " -> ".join(parts)

    def _node_to_dict(self, node: TaintNode) -> dict[str, Any]:
        """将单个节点转为字典。"""
        return {
            "nodeType": node.node_type.name,
            "name": node.name,
            "filePath": node.file_path,
            "line": node.line,
            "column": node.column,
            "codeSnippet": node.code_snippet,
        }

    def _edge_to_dict(self, edge: TaintEdge) -> dict[str, Any]:
        """将单条边转为字典。"""
        return {
            "edgeType": edge.edge_type.name,
            "line": edge.line,
            "description": edge.description,
        }

    def to_dict(self) -> dict[str, Any]:
        """转换为字典格式"""
        return {
            "source": {
                "name": self.source_node.name if self.source_node else "",
                "file": self.source_node.file_path if self.source_node else "",
                "line": self.source_node.line if self.source_node else 0,
                "pattern": self.source_node.source_pattern if self.source_node else "",
            },
            "sink": {
                "name": self.sink_node.name if self.sink_node else "",
                "file": self.sink_node.file_path if self.sink_node else "",
                "line": self.sink_node.line if self.sink_node else 0,
                "pattern": self.sink_node.sink_pattern if self.sink_node else "",
            },
            "path_length": len(self),
            "is_sanitized": self.is_sanitized,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "path_string": self.to_string(),
        }

    def to_full_dict(self) -> dict[str, Any]:
        """转换为包含所有节点和边的完整字典格式（用于 Webview 可视化）。"""
        nodes = [self._node_to_dict(n) for n in self.get_full_path()]
        edges = [self._edge_to_dict(e) for e in self.path_edges]
        return {
            "nodes": nodes,
            "edges": edges,
            "pathLength": len(self),
            "isSanitized": self.is_sanitized,
            "riskLevel": self.risk_level,
            "confidence": self.confidence,
        }


class TaintGraph:
    """
    污点图。

    存储所有污点节点和边，支持路径查询。

    使用示例：
        graph = TaintGraph()

        # 添加节点
        source = graph.add_node("userInput", NodeType.SOURCE, "app.js", 10)
        var = graph.add_node("data", NodeType.VARIABLE, "app.js", 15)
        sink = graph.add_node("eval(data)", NodeType.SINK, "app.js", 20)

        # 添加边
        graph.add_edge(source.id, var.id, EdgeType.ASSIGNMENT)
        graph.add_edge(var.id, sink.id, EdgeType.PARAMETER_PASS)

        # 查找路径
        paths = graph.find_paths_to_sinks()
    """

    def __init__(self):
        """初始化空的污点图"""
        self._nodes: dict[str, TaintNode] = {}  # id -> node
        self._edges: dict[str, TaintEdge] = {}  # id -> edge

        # 邻接表（用于路径查找）
        self._outgoing: dict[str, set[str]] = {}  # node_id -> set of edge_ids
        self._incoming: dict[str, set[str]] = {}  # node_id -> set of edge_ids

        # 按类型索引
        self._sources: set[str] = set()  # source node ids
        self._sinks: set[str] = set()  # sink node ids
        self._sanitizers: set[str] = set()  # sanitizer node ids

        # 按文件索引
        self._by_file: dict[str, set[str]] = {}  # file_path -> node_ids

        # 规则层查询：被净化器处理过的变量名（2.1 统一污点系统）
        self._sanitized_names: set[str] = set()
        self._sanitizer_by_var: dict[str, str] = {}  # var_name -> sanitizer_name

    def reset(self) -> None:
        """清空图与净化记录，便于同一分析器复用。"""
        self._nodes.clear()
        self._edges.clear()
        self._outgoing.clear()
        self._incoming.clear()
        self._sources.clear()
        self._sinks.clear()
        self._sanitizers.clear()
        self._by_file.clear()
        self._sanitized_names.clear()
        self._sanitizer_by_var.clear()

    def add_node(
        self, name: str, node_type: NodeType, file_path: str = "", line: int = 0, column: int = 0, **extras
    ) -> TaintNode:
        """
        添加节点到图中。

        Args:
            name: 节点名称
            node_type: 节点类型
            file_path: 文件路径
            line: 行号
            column: 列号
            **extras: 额外信息

        Returns:
            创建的节点
        """
        node = TaintNode(
            name=name,
            node_type=node_type,
            file_path=file_path,
            line=line,
            column=column,
            extras=extras,
        )

        # 检查是否已存在相同节点
        if node.id in self._nodes:
            return self._nodes[node.id]

        # 添加到图中
        self._nodes[node.id] = node
        self._outgoing[node.id] = set()
        self._incoming[node.id] = set()

        # 按类型索引
        if node_type == NodeType.SOURCE:
            self._sources.add(node.id)
            node.is_tainted = True
            node.taint_level = 4  # Critical
        elif node_type == NodeType.SINK:
            self._sinks.add(node.id)
        elif node_type == NodeType.SANITIZER:
            self._sanitizers.add(node.id)

        # 按文件索引
        if file_path:
            if file_path not in self._by_file:
                self._by_file[file_path] = set()
            self._by_file[file_path].add(node.id)

        return node

    def add_edge(
        self, from_node_id: str, to_node_id: str, edge_type: EdgeType, line: int = 0, description: str = "", **extras
    ) -> TaintEdge | None:
        """
        添加边到图中。

        Args:
            from_node_id: 源节点 ID
            to_node_id: 目标节点 ID
            edge_type: 边类型
            line: 行号
            description: 描述
            **extras: 额外信息

        Returns:
            创建的边，如果节点不存在则返回 None
        """
        # 验证节点存在
        if from_node_id not in self._nodes or to_node_id not in self._nodes:
            return None

        edge = TaintEdge(
            from_node=from_node_id,
            to_node=to_node_id,
            edge_type=edge_type,
            line=line,
            description=description,
            extras=extras,
        )

        # 检查是否已存在相同边
        if edge.id in self._edges:
            return self._edges[edge.id]

        # 添加到图中
        self._edges[edge.id] = edge
        self._outgoing[from_node_id].add(edge.id)
        self._incoming[to_node_id].add(edge.id)

        # 传播污点
        from_node = self._nodes[from_node_id]
        to_node = self._nodes[to_node_id]

        if from_node.is_tainted and edge_type != EdgeType.SANITIZE:
            to_node.is_tainted = True
            to_node.taint_level = max(to_node.taint_level, from_node.taint_level - 1)

        return edge

    def get_node(self, node_id: str) -> TaintNode | None:
        """获取节点"""
        return self._nodes.get(node_id)

    def get_node_by_name(self, name: str, file_path: str = "") -> TaintNode | None:
        """根据名称获取节点"""
        for node in self._nodes.values():
            if node.name == name:
                if not file_path or node.file_path == file_path:
                    return node
        return None

    # ──────────────────────────────────────────────
    # 规则层查询 API（2.1 统一污点系统，与 DataFlowTracker 对齐）
    # ──────────────────────────────────────────────

    def has_tracked_var(self, var_name: str, file_path: str = "") -> bool:
        """变量是否已被追踪（曾出现在数据流中）。"""
        return self.get_node_by_name(var_name, file_path) is not None

    def is_var_tainted(self, var_name: str, file_path: str = "") -> bool:
        """变量是否被污染且未被净化。"""
        if var_name in self._sanitized_names:
            return False
        node = self.get_node_by_name(var_name, file_path)
        return node is not None and node.is_tainted

    def is_var_sanitized(self, var_name: str) -> bool:
        """变量是否经过净化器处理。"""
        return var_name in self._sanitized_names

    def get_sanitizer_name(self, var_name: str) -> str | None:
        """获取变量经过的净化器名称。"""
        return self._sanitizer_by_var.get(var_name)

    def mark_sanitized(self, var_name: str, sanitizer_name: str = "") -> None:
        """标记变量已被净化。"""
        self._sanitized_names.add(var_name)
        if sanitizer_name:
            self._sanitizer_by_var[var_name] = sanitizer_name

    def get_taint_source_info(self, var_name: str, file_path: str = "") -> dict[str, Any] | None:
        """
        获取变量的污点来源信息（规则层兼容 DataFlowTracker.get_taint_source）。
        返回 dict: source_type, source_expr, line；若无来源则返回 None。
        """
        node = self.get_node_by_name(var_name, file_path)
        if not node or not node.is_tainted:
            return None
        if node.id in self._sources:
            return {
                "source_type": node.extras.get("source_pattern", "user_input"),
                "source_expr": node.name,
                "line": node.line,
            }
        # 沿入边回溯到第一个 SOURCE
        from collections import deque

        visited = {node.id}
        queue = deque([node.id])
        while queue:
            nid = queue.popleft()
            if nid in self._sources:
                src = self._nodes[nid]
                return {
                    "source_type": src.extras.get("source_pattern", "user_input"),
                    "source_expr": src.name,
                    "line": src.line,
                }
            for eid in self._incoming.get(nid, set()):
                edge = self._edges.get(eid)
                if edge and edge.from_node not in visited:
                    visited.add(edge.from_node)
                    queue.append(edge.from_node)
        return None

    def get_edge(self, edge_id: str) -> TaintEdge | None:
        """获取边"""
        return self._edges.get(edge_id)

    def get_sources(self) -> list[TaintNode]:
        """获取所有 Source 节点"""
        return [self._nodes[nid] for nid in self._sources]

    def get_sinks(self) -> list[TaintNode]:
        """获取所有 Sink 节点"""
        return [self._nodes[nid] for nid in self._sinks]

    def get_sanitizers(self) -> list[TaintNode]:
        """获取所有 Sanitizer 节点"""
        return [self._nodes[nid] for nid in self._sanitizers]

    def get_tainted_nodes(self) -> list[TaintNode]:
        """获取所有被污染的节点"""
        return [n for n in self._nodes.values() if n.is_tainted]

    def get_outgoing_edges(self, node_id: str) -> list[TaintEdge]:
        """获取节点的出边"""
        if node_id not in self._outgoing:
            return []
        return [self._edges[eid] for eid in self._outgoing[node_id]]

    def get_incoming_edges(self, node_id: str) -> list[TaintEdge]:
        """获取节点的入边"""
        if node_id not in self._incoming:
            return []
        return [self._edges[eid] for eid in self._incoming[node_id]]

    def find_paths_to_sinks(self, max_depth: int = 20) -> list[TaintPath]:
        """
        查找从所有 Source 到所有 Sink 的路径。

        使用 BFS 算法查找所有可达路径。

        Args:
            max_depth: 最大搜索深度

        Returns:
            所有找到的污点路径
        """
        paths = []

        for source_id in self._sources:
            source_node = self._nodes[source_id]

            # BFS 查找到所有 Sink 的路径
            for path in self._bfs_paths(source_id, self._sinks, max_depth):
                if len(path) >= 2:
                    sink_node = self._nodes[path[-1]]

                    # 构建中间节点列表
                    intermediate_nodes = [self._nodes[nid] for nid in path[1:-1]]

                    # 构建边列表
                    edges = []
                    for i in range(len(path) - 1):
                        from_id, to_id = path[i], path[i + 1]
                        for eid in self._outgoing.get(from_id, []):
                            edge = self._edges[eid]
                            if edge.to_node == to_id:
                                edges.append(edge)
                                break

                    # 检查是否经过净化器
                    is_sanitized = False
                    sanitizer_node = None
                    for node in intermediate_nodes:
                        if node.id in self._sanitizers:
                            is_sanitized = True
                            sanitizer_node = node
                            break

                    taint_path = TaintPath(
                        source_node=source_node,
                        sink_node=sink_node,
                        path_nodes=intermediate_nodes,
                        path_edges=edges,
                        is_sanitized=is_sanitized,
                        sanitizer_node=sanitizer_node,
                        risk_level="Low" if is_sanitized else "High",
                        confidence=0.3 if is_sanitized else 0.9,
                    )
                    paths.append(taint_path)

        return paths

    def _bfs_paths(self, start_id: str, target_ids: set[str], max_depth: int = 20) -> list[list[str]]:
        """
        BFS 查找从起点到目标集合的所有路径。

        Args:
            start_id: 起始节点 ID
            target_ids: 目标节点 ID 集合
            max_depth: 最大深度

        Returns:
            所有找到的路径（节点 ID 列表）
        """
        paths = []

        # BFS 队列：(当前节点, 路径, 访问过的节点)
        queue: list[tuple[str, list[str], set[str]]] = [(start_id, [start_id], {start_id})]

        while queue:
            current_id, path, visited = queue.pop(0)

            # 深度限制
            if len(path) > max_depth:
                continue

            # 检查是否到达目标
            if current_id in target_ids and len(path) > 1:
                paths.append(path)
                continue  # 找到路径后继续搜索其他路径

            # 扩展邻居
            for edge_id in self._outgoing.get(current_id, []):
                edge = self._edges[edge_id]
                next_id = edge.to_node

                if next_id not in visited:
                    new_visited = visited | {next_id}
                    queue.append((next_id, path + [next_id], new_visited))

        return paths

    def find_path_between(self, from_node_id: str, to_node_id: str, max_depth: int = 20) -> TaintPath | None:
        """
        查找两个节点之间的路径。

        Args:
            from_node_id: 起始节点 ID
            to_node_id: 目标节点 ID
            max_depth: 最大深度

        Returns:
            找到的路径，如果不存在则返回 None
        """
        paths = self._bfs_paths(from_node_id, {to_node_id}, max_depth)

        if not paths:
            return None

        # 返回最短路径
        shortest = min(paths, key=len)

        from_node = self._nodes[from_node_id]
        to_node = self._nodes[to_node_id]
        intermediate = [self._nodes[nid] for nid in shortest[1:-1]]

        return TaintPath(
            source_node=from_node,
            sink_node=to_node,
            path_nodes=intermediate,
        )

    def get_stats(self) -> dict[str, int]:
        """获取图的统计信息"""
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "sources": len(self._sources),
            "sinks": len(self._sinks),
            "sanitizers": len(self._sanitizers),
            "tainted_nodes": len([n for n in self._nodes.values() if n.is_tainted]),
            "files": len(self._by_file),
        }

    def to_dict(self) -> dict[str, Any]:
        """转换为字典格式（用于序列化）"""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "type": n.node_type.name,
                    "file": n.file_path,
                    "line": n.line,
                    "is_tainted": n.is_tainted,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "id": e.id,
                    "from": e.from_node,
                    "to": e.to_node,
                    "type": e.edge_type.name,
                }
                for e in self._edges.values()
            ],
            "stats": self.get_stats(),
        }


__all__ = [
    "NodeType",
    "EdgeType",
    "TaintNode",
    "TaintEdge",
    "TaintPath",
    "TaintGraph",
]
