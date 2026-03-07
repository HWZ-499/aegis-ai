"""
analysis.base

提供规则引擎的基础设施：
- AnalysisContext: 分析上下文
- SecurityRule: 规则抽象基类（AST 访问模型）
- DataFlowTracker: 简单数据流追踪器
- is_user_input_node / is_user_input_expr: 结构化用户输入检测
"""

from .analysis_context import (
    AnalysisContext,
    make_related_location,
    tree_sitter_node_to_range,
)
from .dataflow_tracker import DataFlowTracker, TaintLevel, TaintSource, VariableInfo
from .file_context import is_likely_seed_or_migration
from .security_rule import SecurityRule
from .user_input_detector import is_user_input_expr, is_user_input_node

__all__ = [
    "AnalysisContext",
    "make_related_location",
    "tree_sitter_node_to_range",
    "SecurityRule",
    "DataFlowTracker",
    "TaintLevel",
    "TaintSource",
    "VariableInfo",
    "is_user_input_node",
    "is_user_input_expr",
    "is_likely_seed_or_migration",
]
