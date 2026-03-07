"""
taint - 完整污点分析模块

提供 Source → Sink 路径追踪的污点分析能力。

核心概念：
- Source（污点源）：用户可控的输入点，如 req.body, req.query
- Sink（汇点）：敏感操作点，如 eval(), exec(), db.find()
- Sanitizer（净化器）：清理污点的函数，如 escapeHtml(), parseInt()
- TaintPath（污点路径）：从 Source 到 Sink 的完整传播路径

使用方式：
    from analysis.taint import TaintAnalyzer

    analyzer = TaintAnalyzer(language="javascript")
    analyzer.analyze_code(code, file_path)
    paths = analyzer.find_taint_paths()
"""

from .cross_file_analyzer import (
    CrossFileAnalyzer,
    CrossFileTaintPath,
    ExportType,
    FunctionCall,
    ModuleExport,
    ModuleImport,
)
from .source_sink_registry import (
    SanitizerPattern,
    SinkPattern,
    SourcePattern,
    SourceSinkRegistry,
    get_default_registry,
)
from .taint_analyzer import TaintAnalyzer
from .taint_graph import (
    EdgeType,
    NodeType,
    TaintEdge,
    TaintGraph,
    TaintNode,
    TaintPath,
)

__all__ = [
    # 数据结构
    "TaintNode",
    "TaintEdge",
    "TaintGraph",
    "TaintPath",
    "NodeType",
    "EdgeType",
    # 注册表
    "SourcePattern",
    "SinkPattern",
    "SanitizerPattern",
    "SourceSinkRegistry",
    "get_default_registry",
    # 单文件分析器
    "TaintAnalyzer",
    # 跨文件分析器
    "CrossFileAnalyzer",
    "ModuleExport",
    "ModuleImport",
    "FunctionCall",
    "CrossFileTaintPath",
    "ExportType",
]
