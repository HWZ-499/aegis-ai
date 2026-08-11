"""PHP SQL Injection AST rule — Tree-sitter based."""

from __future__ import annotations

import re
from typing import Any

from ...base import AnalysisContext, SecurityRule, tree_sitter_node_to_range
from ...base.user_input_detector import _subtree_contains_php_user_input

try:
    from tree_sitter import Node

    _TS = True
except ImportError:
    _TS = False
    Node = Any  # type: ignore[misc,assignment]


class PhpSQLInjectionAstRule(SecurityRule):
    """Detect SQL injection in PHP via Tree-sitter AST."""

    _HIGH_RISK_SOURCE_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b", re.IGNORECASE)
    _LOW_RISK_SERVER_SOURCE_RE = re.compile(r"\$_SERVER\b", re.IGNORECASE)

    QUERY_METHODS = frozenset(
        {
            "query",
            "exec",
            "execute",
            "prepare",
            "multi_query",
            "pg_query",
            "pg_query_params",
            "sqlite_query",
            "querySingle",
        }
    )
    QUERY_FUNCTIONS = frozenset(
        {
            "mysql_query",
            "mysqli_query",
            "pg_query",
            "sqlite_query",
        }
    )

    def __init__(self) -> None:
        super().__init__(rule_id="SQL_INJECTION_PHP_AST", severity="High", languages=["php"])
        self._reported: set[int] = set()
        self._safe_prepared_stmt_vars: set[str] = set()

    def before_file(self, context: AnalysisContext) -> None:
        self._reported = set()
        self._safe_prepared_stmt_vars = set()

    def visit(self, node: Any, context: AnalysisContext) -> None:
        if not _TS or not isinstance(node, Node):
            return

        # assignment_expression: $stmt = $pdo->prepare("SELECT ... ?")
        if node.type == "assignment_expression":
            self._track_safe_prepare_assignment(node)
            return

        # member_call_expression: $conn->query($sql)
        if node.type == "member_call_expression":
            method_name = self._get_method_name(node)
            receiver_var = self._get_receiver_var(node)
            if method_name and method_name in self.QUERY_METHODS:
                # prepare() is safe only for static SQL. It does not protect
                # dynamic table/column/query fragments already in the SQL text.
                if method_name == "prepare" and self._is_static_prepare_call(node):
                    return
                # Skip safe prepared statement execute flow:
                # $stmt = $pdo->prepare("... ?"); $stmt->execute([$id]);
                if method_name == "execute" and receiver_var and receiver_var in self._safe_prepared_stmt_vars:
                    return
                self._check_args(node, context, f"$obj->{method_name}")

        # function_call_expression: mysql_query($sql)
        elif node.type == "function_call_expression":
            func_name = self._get_func_name(node)
            if func_name and func_name in self.QUERY_FUNCTIONS:
                self._check_args(node, context, func_name)

    def _check_args(self, node: Any, context: AnalysisContext, call_desc: str) -> None:
        line = node.start_point[0] + 1
        if line in self._reported:
            return
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "argument":
                        # Skip simple string literals (no interpolation)
                        inner = self._unwrap_arg(arg)
                        if inner is None:
                            continue
                        if inner.type == "string" and not self._string_has_variable(inner):
                            continue
                        if inner.type in ("string", "encapsed_string", "binary_expression"):
                            weak_var = self._find_weakly_sanitized_sql_var(inner, context)
                            if weak_var:
                                if self._is_var_numeric_guarded(weak_var, line, context):
                                    continue
                                self._reported.add(line)
                                finding = {
                                    "type": "SQL_INJECTION",
                                    "rule_id": self.rule_id,
                                    "severity": self.severity,
                                    "line": line,
                                    "details": (
                                        f"PHP: {call_desc}() 的 SQL 使用弱转义变量 ${weak_var}。"
                                        "mysqli_real_escape_string/addslashes 不能替代参数化查询。"
                                    ),
                                }
                                finding.update(tree_sitter_node_to_range(node))
                                context.add_finding(finding)
                                return
                        if _subtree_contains_php_user_input(arg, context):
                            if not self._contains_high_risk_php_sql_source(arg, context):
                                continue
                            if self._is_sql_arg_numeric_guarded(inner, line, context):
                                continue
                            self._reported.add(line)
                            finding = {
                                "type": "SQL_INJECTION",
                                "rule_id": self.rule_id,
                                "severity": self.severity,
                                "line": line,
                                "details": f"PHP: {call_desc}() 的参数包含用户输入，存在 SQL 注入风险。建议使用 prepare/bind_param 参数化查询。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return
                        # Check tainted variables
                        if inner.type == "variable_name":
                            var = self._get_node_text(inner).lstrip("$")
                            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                                if not self._contains_high_risk_php_sql_source(inner, context):
                                    continue
                                self._reported.add(line)
                                finding = {
                                    "type": "SQL_INJECTION",
                                    "rule_id": self.rule_id,
                                    "severity": self.severity,
                                    "line": line,
                                    "details": f"PHP: {call_desc}() 的参数变量 ${var} 被污染，存在 SQL 注入风险。",
                                }
                                finding.update(tree_sitter_node_to_range(node))
                                context.add_finding(finding)
                                return
                            assigned_expr = self._find_latest_assignment_expr(var, line, context)
                            weak_var = self._find_weakly_sanitized_sql_var_in_text(assigned_expr, context)
                            if weak_var:
                                if self._is_var_numeric_guarded(weak_var, line, context):
                                    continue
                                self._reported.add(line)
                                finding = {
                                    "type": "SQL_INJECTION",
                                    "rule_id": self.rule_id,
                                    "severity": self.severity,
                                    "line": line,
                                    "details": (
                                        f"PHP: {call_desc}() 使用变量 ${var} 执行 SQL，且其中 ${weak_var} 仅经过弱转义。"
                                        "请改用 prepare/bind 参数化查询。"
                                    ),
                                }
                                finding.update(tree_sitter_node_to_range(node))
                                context.add_finding(finding)
                                return
                        # Concatenated or interpolated strings with tainted vars
                        if inner.type in ("binary_expression", "encapsed_string"):
                            if self._expr_contains_tainted_var(inner, context):
                                if not self._contains_high_risk_php_sql_source(inner, context):
                                    continue
                                if self._is_sql_arg_numeric_guarded(inner, line, context):
                                    continue
                                self._reported.add(line)
                                finding = {
                                    "type": "SQL_INJECTION",
                                    "rule_id": self.rule_id,
                                    "severity": self.severity,
                                    "line": line,
                                    "details": f"PHP: {call_desc}() 的参数包含拼接/插值的污染变量，存在 SQL 注入风险。",
                                }
                                finding.update(tree_sitter_node_to_range(node))
                                context.add_finding(finding)
                                return

    def _track_safe_prepare_assignment(self, node: Any) -> None:
        """
        记录安全 prepared statement 变量（静态 SQL + 占位符）。
        """
        children = list(getattr(node, "children", []))
        if len(children) < 3:
            return

        left = children[0]
        right = children[-1]
        if getattr(left, "type", "") != "variable_name":
            return
        if getattr(right, "type", "") != "member_call_expression":
            return

        method_name = self._get_method_name(right)
        if method_name != "prepare":
            return
        if not self._is_static_prepare_call(right):
            return

        var_name = self._get_node_text(left).lstrip("$")
        if var_name:
            self._safe_prepared_stmt_vars.add(var_name)

    def _is_static_prepare_call(self, node: Any) -> bool:
        """
        prepare(...) 首参为静态 SQL 字符串（无变量插值）且包含占位符。
        """
        for child in getattr(node, "children", []):
            if child.type != "arguments":
                continue
            for arg in child.children:
                if arg.type != "argument":
                    continue
                inner = self._unwrap_arg(arg)
                if inner is None:
                    return False
                text = self._get_node_text(inner)
                if inner.type in ("string", "encapsed_string"):
                    if self._string_has_variable(inner):
                        return False
                    return "?" in text or "%s" in text or ":" in text
                return False
        return False

    def _expr_contains_tainted_var(self, node: Any, context: AnalysisContext) -> bool:
        if node.type == "variable_name":
            var = self._get_node_text(node).lstrip("$")
            if context.is_var_tainted(var) or context.is_var_tainted("$" + var):
                return True
        if hasattr(node, "children"):
            for child in node.children:
                if self._expr_contains_tainted_var(child, context):
                    return True
        return False

    def _find_weakly_sanitized_sql_var(self, node: Any, context: AnalysisContext) -> str | None:
        """
        检测仅经过数据库转义后插入 SQL 的用户输入变量。

        包括未加引号数字上下文和带引号字符串上下文。数据库转义依赖
        连接字符集等外部条件，不能作为参数化查询的替代。

        该逻辑用于补齐：
        1) 用户输入 -> mysqli_real_escape_string/addslashes
        2) 变量拼入 SQL（如 `id = $id` 或 `user = '$user'`）
        """
        sql_text = self._get_node_text(node)
        if not sql_text:
            return None

        return self._find_weakly_sanitized_sql_var_in_text(
            sql_text,
            context,
            var_candidates=self._collect_variable_names(node),
        )

    def _find_weakly_sanitized_sql_var_in_text(
        self,
        sql_text: str | None,
        context: AnalysisContext,
        var_candidates: set[str] | None = None,
    ) -> str | None:
        if not sql_text:
            return None
        if not self._looks_like_sql(sql_text):
            return None

        candidates = var_candidates if var_candidates is not None else set(re.findall(r"\$([A-Za-z_]\w*)", sql_text))
        quoted_weak_vars: list[str] = []
        for var_name in sorted(candidates):
            if context.is_var_tainted(var_name) or context.is_var_tainted("$" + var_name):
                continue

            sanitizer = (
                context.get_sanitizer_name(var_name) or context.get_sanitizer_name("$" + var_name) or ""
            ).lower()
            if "mysqli_real_escape_string" not in sanitizer and "addslashes" not in sanitizer:
                continue
            if not self._var_has_high_risk_source(var_name, context):
                continue
            if self._is_sql_unquoted_var_usage(sql_text, var_name):
                return var_name
            if self._is_var_wrapped_by_quotes(sql_text, var_name):
                quoted_weak_vars.append(var_name)

        # Keep the quoted-string migration bounded to the legacy gap observed
        # in authentication queries: multiple independently controlled fields
        # are weakly escaped and interpolated into the same SQL statement.
        if len(quoted_weak_vars) >= 2 and re.search(r"\bSELECT\b", sql_text, re.IGNORECASE):
            return quoted_weak_vars[0]
        return None

    def _var_has_high_risk_source(self, var_name: str, context: AnalysisContext) -> bool:
        source = context.get_taint_source(var_name) or context.get_taint_source("$" + var_name)
        if source is None:
            return False
        source_type = (getattr(source, "source_type", "") or "").strip().lower()
        source_expr = (getattr(source, "source_expr", "") or "").strip()
        return any(token in source_type for token in ("get", "post", "request", "cookie", "files")) or bool(
            self._HIGH_RISK_SOURCE_RE.search(source_expr)
        )

    def _is_sql_arg_numeric_guarded(self, node: Any, sink_line: int, context: AnalysisContext) -> bool:
        """
        Return True when every high-risk variable flowing into this SQL argument
        has been narrowed to numeric-only input before the sink.

        This is intentionally SQLi-specific. A digit-only guard proves the value
        cannot inject SQL syntax, but it is not a general-purpose sanitizer for
        other vulnerability classes.
        """
        sql_text = self._get_sql_text_for_arg(node, sink_line, context)
        if not sql_text or not self._looks_like_sql(sql_text):
            return False

        candidate_vars = self._collect_sql_value_vars(node, sql_text, sink_line, context)
        if not candidate_vars:
            return False

        high_risk_vars = {var_name for var_name in candidate_vars if self._is_high_risk_tainted_var(var_name, context)}
        if not high_risk_vars:
            return False

        return all(self._is_var_numeric_guarded(var_name, sink_line, context) for var_name in high_risk_vars)

    def _get_sql_text_for_arg(self, node: Any, sink_line: int, context: AnalysisContext) -> str | None:
        if getattr(node, "type", "") == "variable_name":
            var_name = self._get_node_text(node).lstrip("$")
            assignment = self._find_latest_assignment(var_name, sink_line, context)
            if assignment is not None:
                return assignment[1]
        return self._get_node_text(node)

    def _collect_sql_value_vars(
        self,
        node: Any,
        sql_text: str,
        sink_line: int,
        context: AnalysisContext,
    ) -> set[str]:
        if getattr(node, "type", "") == "variable_name":
            var_name = self._get_node_text(node).lstrip("$")
            assignment = self._find_latest_assignment(var_name, sink_line, context)
            if assignment is not None:
                return set(re.findall(r"\$([A-Za-z_]\w*)", assignment[1]))
        collected = self._collect_variable_names(node)
        if collected:
            return collected
        return set(re.findall(r"\$([A-Za-z_]\w*)", sql_text))

    def _is_high_risk_tainted_var(self, var_name: str, context: AnalysisContext) -> bool:
        if not (context.is_var_tainted(var_name) or context.is_var_tainted("$" + var_name)):
            return False

        source = context.get_taint_source(var_name) or context.get_taint_source("$" + var_name)
        if source is None:
            return True

        source_type = (getattr(source, "source_type", "") or "").strip().lower()
        source_expr = (getattr(source, "source_expr", "") or "").strip()
        if any(token in source_type for token in ("get", "post", "request", "cookie", "files")):
            return True
        if self._HIGH_RISK_SOURCE_RE.search(source_expr):
            return True
        if "server" in source_type or self._LOW_RISK_SERVER_SOURCE_RE.search(source_expr):
            return False
        return True

    def _is_var_numeric_guarded(self, var_name: str, sink_line: int, context: AnalysisContext) -> bool:
        assignment = self._find_latest_assignment(var_name, sink_line, context)
        assignment_line = assignment[0] if assignment is not None else sink_line
        assignment_expr = assignment[1] if assignment is not None else None

        if assignment_expr and self._is_numeric_cast_expr(assignment_expr):
            return True

        guarded_exprs = {f"${var_name}"}
        if assignment_expr:
            guarded_exprs.add(assignment_expr)

        source = context.get_taint_source(var_name) or context.get_taint_source("$" + var_name)
        source_expr = (getattr(source, "source_expr", "") or "").strip() if source is not None else ""
        if source_expr and source_expr != f"${var_name}":
            guarded_exprs.add(source_expr)

        return self._has_numeric_guard_for_exprs(guarded_exprs, assignment_line, sink_line, context, assignment_expr)

    @staticmethod
    def _is_numeric_cast_expr(expr: str) -> bool:
        return re.search(r"^\s*(?:\(?\s*(?:int|integer|float|double)\s*\)?|intval|floatval|abs)\s*\(", expr) is not None

    def _has_numeric_guard_for_exprs(
        self,
        exprs: set[str],
        assignment_line: int,
        sink_line: int,
        context: AnalysisContext,
        assignment_expr: str | None = None,
    ) -> bool:
        source = context.extras.get("source")
        if not isinstance(source, str) or not source:
            return False
        lines = source.splitlines()
        normalized_exprs = {self._normalize_php_expr(expr) for expr in exprs if expr}
        if not normalized_exprs:
            return False

        sink_idx = max(sink_line - 1, 0)
        assignment_idx = max(assignment_line - 1, 0)
        for guard_idx in range(0, min(sink_idx + 1, len(lines))):
            condition = self._extract_if_condition(lines[guard_idx])
            if not condition:
                continue

            guarded = self._numeric_guard_exprs(condition)
            matching_guard_exprs = {
                self._normalize_php_expr(expr) for expr in guarded if self._normalize_php_expr(expr) in normalized_exprs
            }
            if not matching_guard_exprs:
                continue

            if self._is_negative_guard_condition(condition):
                if self._else_block_contains_lines(lines, guard_idx, {assignment_idx, sink_idx}):
                    return True
                if self._guard_failure_block_exits(lines, guard_idx) and guard_idx < assignment_idx <= sink_idx:
                    return True
            else:
                if not self._block_contains_lines(lines, guard_idx, {sink_idx}):
                    continue
                if assignment_idx <= guard_idx:
                    return True
                if assignment_expr and self._normalize_php_expr(assignment_expr) in matching_guard_exprs:
                    return True

        return False

    @staticmethod
    def _extract_if_condition(line: str) -> str | None:
        match = re.search(r"\bif\s*\((.*)\)", line)
        if match is None:
            return None
        return match.group(1)

    def _numeric_guard_exprs(self, condition: str) -> list[str]:
        result: list[str] = []
        for match in re.finditer(
            r"preg_match\s*\(\s*(['\"])(?P<pattern>.*?)(?<!\\)\1\s*,\s*(?P<expr>[^,)]+)",
            condition,
            re.IGNORECASE,
        ):
            if self._is_digit_only_regex(match.group("pattern")):
                result.append(match.group("expr").strip())

        for match in re.finditer(
            r"\b(?:ctype_digit|is_numeric)\s*\(\s*(?P<expr>[^)]+)\)",
            condition,
            re.IGNORECASE,
        ):
            result.append(match.group("expr").strip())

        for match in re.finditer(
            r"\bfilter_var\s*\(\s*(?P<expr>[^,]+)\s*,\s*FILTER_VALIDATE_(?:INT|FLOAT)\b",
            condition,
            re.IGNORECASE,
        ):
            result.append(match.group("expr").strip())

        return result

    @staticmethod
    def _is_digit_only_regex(pattern: str) -> bool:
        stripped = pattern.strip()
        if stripped.startswith("/") and stripped.count("/") >= 2:
            last = stripped.rfind("/")
            stripped = stripped[1:last]
        normalized = stripped.replace("\\\\d", r"\d").replace("\\d", r"\d")
        normalized = re.sub(r"\s+", "", normalized)
        return normalized in {r"^\d+$", "^[0-9]+$", "^[[:digit:]]+$"}

    @staticmethod
    def _is_negative_guard_condition(condition: str) -> bool:
        if re.search(r"!\s*(?:preg_match|ctype_digit|is_numeric|filter_var)\s*\(", condition, re.IGNORECASE):
            return True
        return (
            re.search(
                r"(?:preg_match|ctype_digit|is_numeric|filter_var)\s*\([^)]*\)\s*(?:={2,3}|!==?)\s*(?:false|0)",
                condition,
                re.IGNORECASE,
            )
            is not None
        )

    @staticmethod
    def _normalize_php_expr(expr: str) -> str:
        return re.sub(r"\s+", "", expr).replace('"', "'")

    def _else_block_contains_lines(self, lines: list[str], guard_idx: int, target_indices: set[int]) -> bool:
        guard_end = self._find_block_end(lines, guard_idx)
        if guard_end is None:
            return False
        else_idx = self._find_else_open_line(lines, guard_end)
        if else_idx is None:
            return False
        return self._block_contains_lines(lines, else_idx, target_indices)

    def _guard_failure_block_exits(self, lines: list[str], guard_idx: int) -> bool:
        guard_end = self._find_block_end(lines, guard_idx)
        if guard_end is None:
            return False
        block_text = "\n".join(lines[guard_idx : guard_end + 1])
        return re.search(r"\b(?:return|exit|die|throw)\b", block_text, re.IGNORECASE) is not None

    def _block_contains_lines(self, lines: list[str], open_idx: int, target_indices: set[int]) -> bool:
        block_end = self._find_block_end(lines, open_idx)
        if block_end is None:
            return False
        return all(open_idx <= target_idx <= block_end for target_idx in target_indices)

    @staticmethod
    def _find_block_end(lines: list[str], open_idx: int) -> int | None:
        depth = 0
        saw_open = False
        for idx in range(open_idx, len(lines)):
            for ch in lines[idx]:
                if ch == "{":
                    depth += 1
                    saw_open = True
                elif ch == "}" and saw_open:
                    depth -= 1
                    if depth == 0:
                        return idx
        return None

    @staticmethod
    def _find_else_open_line(lines: list[str], guard_end_idx: int) -> int | None:
        for idx in range(guard_end_idx, min(guard_end_idx + 4, len(lines))):
            line = lines[idx].strip()
            if not line:
                continue
            if "else" not in line:
                if idx == guard_end_idx:
                    continue
                return None
            if "{" in line:
                return idx
            for next_idx in range(idx + 1, min(idx + 3, len(lines))):
                if lines[next_idx].strip().startswith("{"):
                    return next_idx
            return None
        return None

    @staticmethod
    def _looks_like_sql(text: str) -> bool:
        return re.search(r"\b(select|update|delete|insert|replace|where|from|into)\b", text, re.IGNORECASE) is not None

    def _contains_high_risk_php_sql_source(self, node: Any, context: AnalysisContext) -> bool:
        """
        SQLi 规则使用更严格的用户输入门控：
        - 命中 $_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES 视为高风险
        - 仅 $_SERVER 派生来源视为低风险，不直接触发 SQLi
        """
        text = self._get_node_text(node)
        if self._HIGH_RISK_SOURCE_RE.search(text):
            return True

        var_names = self._collect_variable_names(node)
        if not var_names:
            return False

        tainted_present = False
        saw_source = False
        saw_only_server = True
        for var_name in var_names:
            if context.is_var_tainted(var_name) or context.is_var_tainted("$" + var_name):
                tainted_present = True
            source = context.get_taint_source(var_name) or context.get_taint_source("$" + var_name)
            if source is None:
                saw_only_server = False
                continue
            source_type = (getattr(source, "source_type", "") or "").strip().lower()
            if source_type:
                saw_source = True
                if any(token in source_type for token in ("get", "post", "request", "cookie", "files")):
                    return True
                if "server" in source_type:
                    continue
                saw_only_server = False

            source_expr = (getattr(source, "source_expr", "") or "").strip()
            if not source_expr:
                saw_only_server = False
                continue

            saw_source = True
            if self._HIGH_RISK_SOURCE_RE.search(source_expr):
                return True
            if not self._LOW_RISK_SERVER_SOURCE_RE.search(source_expr):
                saw_only_server = False

        if saw_source and saw_only_server:
            return False
        if tainted_present:
            return True
        return False

    @classmethod
    def _find_latest_assignment_expr(cls, var_name: str, sink_line: int, context: AnalysisContext) -> str | None:
        assignment = cls._find_latest_assignment(var_name, sink_line, context)
        return assignment[1] if assignment is not None else None

    @staticmethod
    def _find_latest_assignment(var_name: str, sink_line: int, context: AnalysisContext) -> tuple[int, str] | None:
        source = context.extras.get("source")
        if not isinstance(source, str) or not source:
            return None

        lines = source.splitlines()
        upper_bound = min(max(sink_line - 1, 0), len(lines))
        assign_re = re.compile(rf"\${re.escape(var_name)}\s*=\s*(.+?)\s*;?\s*$")

        for idx in range(upper_bound - 1, -1, -1):
            line = lines[idx]
            matched = assign_re.search(line)
            if matched is not None:
                return idx + 1, matched.group(1).strip()
        return None

    def _collect_variable_names(self, node: Any) -> set[str]:
        result: set[str] = set()
        if getattr(node, "type", "") == "variable_name":
            var_name = self._get_node_text(node).lstrip("$")
            if var_name:
                result.add(var_name)
        for child in getattr(node, "children", []):
            result.update(self._collect_variable_names(child))
        return result

    @staticmethod
    def _is_var_wrapped_by_quotes(sql_text: str, var_name: str) -> bool:
        var_expr = rf"(?:\{{\s*)?\${re.escape(var_name)}(?:\s*\}})?"
        return re.search(rf"['\"]\s*{var_expr}\s*['\"]", sql_text) is not None

    @staticmethod
    def _is_sql_unquoted_var_usage(sql_text: str, var_name: str) -> bool:
        var_expr = rf"(?:\{{\s*)?\${re.escape(var_name)}(?:\s*\}})?"
        if re.search(rf"(?:=|<>|!=|<|>|<=|>=)\s*{var_expr}\b", sql_text, re.IGNORECASE):
            return True
        if re.search(rf"\b(?:IN|LIKE|LIMIT|OFFSET)\b\s*\(?\s*{var_expr}\b", sql_text, re.IGNORECASE):
            return True
        return False

    @staticmethod
    def _unwrap_arg(arg_node: Any) -> Any:
        if arg_node.type == "argument":
            for c in arg_node.children:
                if c.type not in (",", "(", ")"):
                    return c
        return arg_node

    @staticmethod
    def _string_has_variable(node: Any) -> bool:
        if hasattr(node, "children"):
            for c in node.children:
                if c.type == "variable_name":
                    return True
        return False

    @staticmethod
    def _get_method_name(node: Any) -> str | None:
        for child in node.children:
            if child.type == "name":
                return child.text.decode("utf-8") if hasattr(child, "text") else None
        return None

    @staticmethod
    def _get_receiver_var(node: Any) -> str | None:
        for child in node.children:
            if child.type == "variable_name":
                text = child.text.decode("utf-8") if hasattr(child, "text") else ""
                return text.lstrip("$") or None
        return None

    @staticmethod
    def _get_func_name(node: Any) -> str | None:
        for child in node.children:
            if child.type == "name":
                return child.text.decode("utf-8") if hasattr(child, "text") else None
        return None

    @staticmethod
    def _get_node_text(node: Any) -> str:
        if hasattr(node, "text"):
            raw = node.text
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return ""


__all__ = ["PhpSQLInjectionAstRule"]
