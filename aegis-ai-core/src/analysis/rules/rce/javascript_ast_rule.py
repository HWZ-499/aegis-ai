"""
rce.javascript_ast_rule

JavaScript/TypeScript RCE（远程代码执行 / 命令执行）AST 规则。

检测目标（复用 multi_language_ast 中的核心逻辑）：
- eval() / Function()
- child_process.exec / spawn / execFile

说明：
- 使用 Tree-sitter Node（不是 Python ast.AST）；
- 复用现有的 _identify_caller_type 逻辑，过滤 RegExp / 第三方库 / 函数定义。
"""

from __future__ import annotations

from typing import Any

from ...base import (
    AnalysisContext,
    SecurityRule,
    make_related_location,
    tree_sitter_node_to_range,
)
from ...base.user_input_detector import is_user_input_node

# Tree-sitter Node 类型（运行时检查）
try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any


class JavaScriptRCEAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 JavaScript/TypeScript RCE 检测规则。
    """

    def __init__(self) -> None:
        super().__init__(
            rule_id="RCE_COMMAND_EXEC_JS_AST",
            severity="Critical",
            languages=["javascript", "typescript"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        访问 Tree-sitter AST 节点。
        """
        if not TREE_SITTER_AVAILABLE:
            return

        # 只关心函数调用节点
        if not isinstance(node, Node) or node.type != "call_expression":
            return

        # 获取调用者（callee）
        callee = None
        for child in node.children:
            if child.type in ("identifier", "member_expression"):
                callee = child
                break

        if not callee:
            return

        # 识别调用者类型（复用现有逻辑）
        caller_type = self._identify_caller_type(callee, node)

        # 过滤：跳过 RegExp / 第三方库 / 函数定义
        if caller_type in ("RegExp", "ThirdParty", "FunctionDefinition"):
            return

        # 提取函数名 / 方法名 / 对象名
        function_name = None
        method_name = None
        object_name = None

        if callee.type == "identifier":
            function_name = self._get_node_text(callee)
        elif callee.type == "member_expression":
            for child in callee.children:
                if child.type == "identifier":
                    object_name = self._get_node_text(child)
                elif child.type == "property_identifier":
                    method_name = self._get_node_text(child)

        # 1. eval() 和 Function()（污点感知检测）
        if function_name in ("eval", "Function"):
            self._check_eval_or_function(node, context, function_name)
            return

        # 2. child_process.exec() 等命令执行
        if object_name == "child_process" and method_name in ("exec", "spawn", "execFile"):
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            finding: dict[str, Any] = {
                "type": "RCE_COMMAND_EXEC",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": f"JavaScript AST: 发现命令执行调用 child_process.{method_name}()，存在命令注入风险。",
            }
            finding.update(tree_sitter_node_to_range(node))
            context.add_finding(finding)
            return

        # 3. vm.runInNewContext() - Node.js VM 模块（代码执行）
        if object_name == "vm" and method_name in ("runInNewContext", "runInContext", "runInThisContext"):
            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
            finding: dict[str, Any] = {
                "type": "RCE_COMMAND_EXEC",
                "rule_id": self.rule_id,
                "severity": self.severity,
                "line": line_no,
                "details": f"JavaScript AST: 发现 vm.{method_name}() 调用，可能导致代码执行。",
            }
            finding.update(tree_sitter_node_to_range(node))
            context.add_finding(finding)
            return

        # 4. unserialize() - node-serialize 库（针对 NodeGoat）
        # 检测模式：unserialize(req.cookies.*) 或 unserialize(req.body.*)
        if function_name == "unserialize":
            # 检查参数是否来自用户输入
            for child in node.children:
                if child.type == "arguments":
                    for arg in child.children:
                        if self._looks_like_user_input_for_unserialize(arg):
                            line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                            finding: dict[str, Any] = {
                                "type": "RCE_COMMAND_EXEC",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line_no,
                                "details": "JavaScript AST: 发现 unserialize() 调用，参数来自用户输入（req.cookies.* 或 req.body.*），存在反序列化代码执行风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            # TDD 7.1/7.2：用户输入参数位置作为 related_locations
                            if hasattr(arg, "start_point"):
                                finding["related_locations"] = [
                                    make_related_location(
                                        str(context.file_path),
                                        arg.start_point[0] + 1,
                                        end_line=arg.end_point[0] + 1 if hasattr(arg, "end_point") else None,
                                        message="用户输入来源",
                                    )
                                ]
                            context.add_finding(finding)
                            return

    # ------------------------------------------------------------------
    # eval / Function 污点感知检查
    # ------------------------------------------------------------------
    def _check_eval_or_function(self, node: Any, context: AnalysisContext, func_name: str) -> None:
        """
        污点感知版 eval()/Function() 检测。

        判断优先级（高 → 低）：
        1. 无参数 → 跳过
        2. 第一个参数是字符串字面量（string 节点）→ 跳过
        3. 第一个参数来自用户输入（结构化匹配 req.*）→ Critical
        4. 第一个参数含变量引用但来源不明 → Medium（降级）
        """
        first_arg = self._get_first_arg(node)
        if first_arg is None:
            return

        # 字符串字面量参数 → 静态代码，安全
        if first_arg.type in ("string", "template_string", "number"):
            return

        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0

        # 用户输入直接流入
        if self._looks_like_user_input_for_unserialize(first_arg):
            finding: dict[str, Any] = {
                "type": "RCE_COMMAND_EXEC",
                "rule_id": self.rule_id,
                "severity": "Critical",
                "line": line_no,
                "details": f"JavaScript AST: {func_name}() 参数来自用户输入，存在代码注入风险。",
            }
            finding.update(tree_sitter_node_to_range(node))
            context.add_finding(finding)
            return

        # 也检查 context.taint_graph（如果有污点图）
        if context.taint_graph is not None:
            arg_text = self._get_node_text(first_arg) or ""
            if arg_text and context.is_var_tainted(arg_text):
                finding = {
                    "type": "RCE_COMMAND_EXEC",
                    "rule_id": self.rule_id,
                    "severity": "Critical",
                    "line": line_no,
                    "details": f"JavaScript AST: {func_name}() 参数被污点图标记为用户输入，存在代码注入风险。",
                }
                finding.update(tree_sitter_node_to_range(node))
                context.add_finding(finding)
                return

        # 参数含变量但来源不明 → 降级为 Medium
        if first_arg.type in (
            "identifier",
            "member_expression",
            "call_expression",
            "binary_expression",
            "template_string",
        ):
            finding = {
                "type": "RCE_COMMAND_EXEC",
                "rule_id": self.rule_id,
                "severity": "Medium",
                "line": line_no,
                "details": f"JavaScript AST: {func_name}() 参数含变量，建议确认参数来源是否可控。",
            }
            finding.update(tree_sitter_node_to_range(node))
            context.add_finding(finding)

    @staticmethod
    def _get_first_arg(node: Any) -> Any:
        """提取函数调用的第一个实参节点。"""
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type not in ("(", ")", ","):
                        return arg
        return None

    # ------------------------------------------------------------------
    # 辅助方法（复用 multi_language_ast 的逻辑）
    # ------------------------------------------------------------------
    @staticmethod
    def _get_node_text(node: Node) -> str | None:
        """提取节点的文本内容。"""
        if hasattr(node, "text"):
            return node.text.decode("utf-8")
        return None

    @staticmethod
    def _identify_caller_type(callee_node: Node, call_node: Node) -> str:
        """
        识别调用者类型（复用 multi_language_ast._identify_caller_type 的逻辑）。

        Returns:
            "RegExp" / "ThirdParty" / "FunctionDefinition" / "ChildProcess" / "Unknown"
        """
        # 检查是否是成员表达式 obj.method()
        if callee_node.type == "member_expression":
            obj_node = None
            method_name = None

            for child in callee_node.children:
                if child.type == "identifier":
                    obj_node = child
                elif child.type == "property_identifier":
                    method_name = JavaScriptRCEAstRule._get_node_text(child)

            if obj_node:
                obj_name = JavaScriptRCEAstRule._get_node_text(obj_node) or ""

                # 识别 RegExp 对象
                if obj_name.lower() in ("regex", "regexp") or obj_name == "RegExp":
                    return "RegExp"

                # 检查是否是正则表达式字面量 /regex/.exec()
                parent = getattr(callee_node, "parent", None)
                if parent:
                    for sibling in getattr(parent, "children", []):
                        if sibling.type == "regex":
                            return "RegExp"

                # 识别第三方库对象
                third_party_libs = [
                    "THREE",
                    "jQuery",
                    "$",
                    "React",
                    "Vue",
                    "Angular",
                    "Backbone",
                    "Underscore",
                    "Lodash",
                    "_",
                ]
                if obj_name in third_party_libs:
                    return "ThirdParty"

                # 识别 child_process
                if obj_name in ("child_process", "process"):
                    return "ChildProcess"

        # 检查是否是正则表达式字面量调用 /regex/.exec()
        for child in call_node.children:
            if child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "regex":
                        return "RegExp"
                    elif subchild.type == "identifier":
                        subchild_name = JavaScriptRCEAstRule._get_node_text(subchild) or ""
                        if subchild_name.lower() in ("regex", "regexp"):
                            return "RegExp"

        # 检查是否是函数定义中的关键词
        parent = getattr(call_node, "parent", None)
        if parent and parent.type == "function_declaration":
            return "FunctionDefinition"

        return "Unknown"

    @staticmethod
    def _looks_like_user_input_for_unserialize(node: Node) -> bool:
        """
        判断节点是否来自用户输入（结构化检测，针对 unserialize 场景）。

        使用 ``is_user_input_node`` 进行精确 AST 匹配。
        """
        return is_user_input_node(node, language="javascript")


__all__ = ["JavaScriptRCEAstRule"]
