"""
nosql_injection.javascript_ast_rule

JavaScript/TypeScript NoSQL 注入 AST 规则（优化版 + 数据流分析）。

检测目标：
- MongoDB/Mongoose 查询中使用 $where / $ne / $regex 等操作符，且值来自用户输入。
- findOne(), find(), update() 等方法调用，参数包含用户输入。
- 通过数据流分析检测间接污点传播（如 const x = req.body; db.find(x)）

优化逻辑：
1. 获取方法名（callee.property.name）
2. 命中 MongoDB 危险关键字（扩展到所有常见操作符）
3. 检查调用者（Context 检查）- 只有当调用者看起来像数据库时才报警
4. 参数检查：
   - A: 参数直接是 req.body (Critical)
   - B: 参数是对象字面量 {user: ...} (High)
   - C: 参数是变量 - 使用数据流分析检测是否被污染 (High/Medium)
   - D: DAO 模式特殊处理

说明：
- 使用 Tree-sitter Node；
- 主要针对 Mongoose ODM 和 MongoDB 原生查询。
- 集成数据流追踪器进行污点分析
"""

from __future__ import annotations

from typing import Any

from ...base import (
    AnalysisContext,
    SecurityRule,
    is_likely_seed_or_migration,
    make_related_location,
    tree_sitter_node_to_range,
)
from ...base.user_input_detector import is_user_input_node

# Tree-sitter Node 类型
try:
    from tree_sitter import Node

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any


class JavaScriptNoSQLInjectionAstRule(SecurityRule):
    """
    基于 Tree-sitter AST 的 JavaScript/TypeScript NoSQL 注入检测规则（优化版 + 数据流分析）。

    新增功能：
    - 集成数据流追踪器进行污点分析
    - 扩展 MongoDB 操作符检测
    - 自动收集变量赋值信息
    """

    # 扩展的 MongoDB 危险操作符列表
    DANGEROUS_OPERATORS = [
        "$where",  # 最危险：允许执行任意 JS
        "$ne",  # 不等于：常用于绕过认证
        "$gt",
        "$gte",
        "$lt",
        "$lte",  # 比较操作符
        "$regex",  # 正则匹配：可能导致 ReDoS
        "$in",
        "$nin",  # 包含/不包含
        "$or",
        "$and",
        "$not",
        "$nor",  # 逻辑操作符
        "$exists",  # 字段存在检查
        "$type",  # 类型检查
        "$expr",  # 表达式
        "$jsonSchema",  # JSON Schema
        "$mod",  # 取模
        "$text",  # 全文搜索
        "$all",  # 数组匹配
        "$elemMatch",  # 元素匹配
        "$size",  # 数组大小
        "$slice",  # 数组切片
    ]

    # MongoDB 数据库方法
    MONGO_SINKS = [
        "find",
        "findOne",
        "findById",
        "findOneAndUpdate",
        "findOneAndDelete",
        "findOneAndReplace",
        "update",
        "updateOne",
        "updateMany",
        "replaceOne",
        "delete",
        "deleteOne",
        "deleteMany",
        "remove",
        "count",
        "countDocuments",
        "estimatedDocumentCount",
        "aggregate",
        "distinct",
        "mapReduce",
        "insert",
        "insertOne",
        "insertMany",  # 插入操作也可能有注入风险（含旧式 insert API）
    ]

    # 调用者名称或片段属于 crypto/哈希/流 API 时，.update() 视为非 NoSQL（降低误报）
    CRYPTO_LIKE_UPDATE_SUBSTRINGS = (
        "sha256",
        "sha1",
        "sha512",
        "md5",
        "hmac",
        "createhash",
        "createhmac",
        "cipher",
        "decipher",
        "buffer",
        "stream",
        "transform",
        "method",  # method.create().update(message) 常见于哈希/流封装
        "this",  # this.update(...) 常见于哈希/流类内部（如 HmacSha256.prototype）
    )

    def __init__(self) -> None:
        super().__init__(
            rule_id="NOSQL_INJECTION_JS_AST",
            severity="High",
            languages=["javascript", "typescript"],
        )

    def visit(self, node: Any, context: AnalysisContext) -> None:
        """
        访问 Tree-sitter AST 节点。

        检测目标：
        - VariableDeclaration: 收集变量赋值信息（用于数据流分析）
        - AssignmentExpression: 收集变量赋值信息
        - CallExpression: findOne(), find(), update(), count() 等方法调用
        - Object: 查询对象中的危险操作符（$where, $ne 等）
        """
        if not TREE_SITTER_AVAILABLE:
            return

        if not isinstance(node, Node):
            return

        # 【数据流收集】收集变量声明（const x = ..., let y = ...）
        if node.type in ("variable_declaration", "lexical_declaration"):
            self._collect_variable_declaration(node, context)

        # 【数据流收集】收集赋值表达式（x = ...）
        elif node.type == "assignment_expression":
            self._collect_assignment(node, context)

        # 【检测】检测函数调用（findOne, find, update, count 等）
        elif node.type == "call_expression":
            self._check_database_method_call(node, context)

        # 【检测】检测对象字面量（查询对象）
        elif node.type == "object":
            self._check_query_object(node, context)

    # ------------------------------------------------------------------
    # 数据流收集方法
    # ------------------------------------------------------------------
    def _collect_variable_declaration(self, node: Node, context: AnalysisContext) -> None:
        """
        收集变量声明，用于数据流分析。

        处理：
        - const userId = req.body.userId;
        - let query = req.query;
        """
        for child in node.children:
            if child.type == "variable_declarator":
                var_name = None
                value_expr = None

                for subchild in child.children:
                    if subchild.type == "identifier":
                        var_name = self._get_node_text(subchild)
                    elif subchild.type not in ("=",):
                        value_expr = self._get_node_text(subchild)

                if var_name and value_expr:
                    line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                    context.track_assignment(var_name, value_expr, line)

    def _collect_assignment(self, node: Node, context: AnalysisContext) -> None:
        """
        收集赋值表达式，用于数据流分析。

        处理：
        - userId = req.body.userId;
        """
        left_node = None
        right_node = None

        for child in node.children:
            if child.type == "identifier":
                left_node = child
            elif child.type not in ("=",):
                right_node = child

        if left_node and right_node:
            var_name = self._get_node_text(left_node)
            value_expr = self._get_node_text(right_node)

            if var_name and value_expr:
                line = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                context.track_assignment(var_name, value_expr, line)

    # ------------------------------------------------------------------
    # 检测方法
    # ------------------------------------------------------------------
    def _check_database_method_call(self, node: Node, context: AnalysisContext) -> None:
        """
        检测数据库方法调用（优化后的逻辑）。

        逻辑流程：
        1. 获取方法名（callee.property.name）
        2. 命中 MongoDB 危险关键字
        3. 检查调用者（Context 检查）- 只有当调用者看起来像数据库时才报警
        4. 参数检查：
           - A: 参数直接是 req.body (Critical)
           - B: 参数是对象字面量 {user: ...} (High)
           - C: 参数是变量 (Medium - 需要数据流分析，但现在先报出来)
        """
        if not node.children:
            return

        # 1. 获取方法名（callee.property.name）
        method_name = None
        caller_name = None

        for child in node.children:
            if child.type == "member_expression":
                # 提取方法名和调用者
                method_parts = []
                obj_parts = []

                def extract_member_parts(n: Node) -> None:
                    """递归提取 member_expression 的各个部分；支持 new ClassName().update、this.update 形式。"""
                    for subchild in n.children:
                        if subchild.type == "identifier":
                            obj_parts.append(self._get_node_text(subchild) or "")
                        elif subchild.type == "this":
                            # tree-sitter 中 this 是关键字节点，类型为 "this" 而非 identifier
                            obj_parts.append("this")
                        elif subchild.type == "property_identifier":
                            method_parts.append(self._get_node_text(subchild) or "")
                        elif subchild.type == "member_expression":
                            extract_member_parts(subchild)
                        elif subchild.type == "parenthesized_expression":
                            # (new Sha256(...)).update -> 递归到括号内表达式，提取类名
                            for sub in subchild.children:
                                if sub.type in ("new_expression", "call_expression", "member_expression"):
                                    extract_member_parts(sub)
                                    break
                        elif subchild.type == "new_expression":
                            # new Sha256(...).update -> 提取类名 Sha256，便于排除 crypto 误报
                            for sub in subchild.children:
                                if sub.type == "identifier":
                                    t = self._get_node_text(sub)
                                    if t:
                                        obj_parts.append(t)
                                    break
                                if sub.type == "call_expression":
                                    for c in sub.children:
                                        if c.type == "identifier":
                                            t = self._get_node_text(c)
                                            if t:
                                                obj_parts.append(t)
                                            break
                                    break
                        elif subchild.type == "call_expression":
                            # method.create().update -> 提取 method
                            for c in subchild.children:
                                if c.type == "identifier":
                                    t = self._get_node_text(c)
                                    if t:
                                        obj_parts.append(t)
                                    break
                                if c.type == "member_expression":
                                    extract_member_parts(c)
                                    break
                                break

                extract_member_parts(child)

                # 最后一个 property_identifier 是方法名
                if method_parts:
                    method_name = method_parts[-1]
                # 组合调用者名称
                if obj_parts:
                    if len(method_parts) > 1:
                        caller_name = ".".join(obj_parts + method_parts[:-1])
                    else:
                        caller_name = obj_parts[0]

            elif child.type == "identifier":
                # 直接函数调用（如 findOne()）
                method_name = self._get_node_text(child)

        # 2. 命中 MongoDB 危险关键字（使用扩展列表）
        if not method_name or method_name not in self.MONGO_SINKS:
            return

        # 3. 检查调用者（Context 检查）- 只有当调用者看起来像数据库时才报警
        # 精确词列表：仅保留独立用作 DB 集合/对象名时几乎不产生歧义的词。
        # - 移除了 "user"（太通用：userService / currentUser 均会被子串命中）
        # - 保留 "users"（复数形式通常专指 MongoDB collection；词边界切分能区分）
        # - 移除了 "model"（viewModel / formModel 极易误报）
        # - 移除了 "session" / "review"（业务逻辑对象常用词）
        likely_db_objects = [
            "db",
            "collection",
            "users",
            "usercol",
            "userscol",
            "dao",
            "mongo",
            "mongoose",
            "repository",
            "repo",
        ]

        # 【修复】检测 DAO.update() 模式（如 allocationsDAO.update, contributionsDAO.update）
        is_dao_pattern = False
        if caller_name and caller_name.lower().endswith("dao"):
            is_dao_pattern = True

        # 如果调用者不像数据库，且函数名太普通（如 'find'），则跳过
        # 防止把 array.find() 当成漏洞
        # 但是：如果参数明确包含 req.body/req.query，即使调用者未知也要报
        if method_name == "find":
            if not caller_name or (not self._is_db_related(caller_name, likely_db_objects) and not is_dao_pattern):
                if not self._args_contain_obvious_user_input(node, context):
                    return

        # 如果调用者存在但不像是数据库对象，跳过
        if caller_name:
            caller_lower = caller_name.lower()
            # 排除明显不是数据库的对象
            if caller_lower in ("array", "string", "number", "object", "math", "date"):
                return
            # 如果调用者不像数据库对象，跳过（除非方法名很明确是数据库操作，或者是 DAO 模式，或者参数包含明确用户输入）
            if (
                method_name not in ("findOne", "updateOne", "deleteOne", "remove", "update")
                and not self._is_db_related(caller_name, likely_db_objects)
                and not is_dao_pattern
                and not self._args_contain_obvious_user_input(node, context)
            ):
                return

        # 【修复】对于 update 方法，如果是 DAO 模式，即使调用者不完全匹配，也继续检测
        if method_name == "update" and is_dao_pattern:
            pass  # 继续检测

        # 【降低误报】.remove() 仅在对疑似 MongoDB/DB 调用者时报；Storage/DOM 的 remove 不报
        if method_name == "remove":
            if not caller_name or (not self._is_db_related(caller_name, likely_db_objects) and not is_dao_pattern):
                return

        # 【降低误报】.update() 在 crypto/哈希/流 API 中常见（如 Sha256.update、method.create().update），非 NoSQL
        if method_name == "update" and self._is_crypto_like_update(caller_name):
            return

            # 4. 关键：参数检查（不要死板地找 req.body）
        for child in node.children:
            if child.type == "arguments":
                if not child.children:
                    continue

                # 收集所有非分隔符参数
                all_args: list[Any] = [arg for arg in child.children if arg.type not in (",", "(", ")")]

                if not all_args:
                    continue

                first_arg = all_args[0]
                line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0

                # 情况 A: 参数直接是 req.body (Critical)
                if self._looks_like_user_input(first_arg, context):
                    finding: dict[str, Any] = {
                        "type": "NOSQL_INJECTION",
                        "rule_id": self.rule_id,
                        "severity": "Critical",  # Critical 级别
                        "line": line_no,
                        "details": f"检测到 {caller_name or ''}.{method_name}() 调用，参数直接来自用户输入（req.body.* 或 req.query.*），存在严重的 NoSQL 注入风险。",
                    }
                    finding.update(tree_sitter_node_to_range(node))
                    context.add_finding(finding)
                    return

                # 情况 B: 参数是对象字面量 {user: ...} (High)
                elif first_arg.type == "object":
                    # 【降低误报】简单 _id/id 查询（如 findOne({ _id: id })）常见于合法 ById 查找，跳过
                    if self._is_simple_id_query(first_arg):
                        return
                    if self._has_dangerous_key_or_value(first_arg, context):
                        finding: dict[str, Any] = {
                            "type": "NOSQL_INJECTION",
                            "rule_id": self.rule_id,
                            "severity": "High",  # High 级别
                            "line": line_no,
                            "details": f"检测到 {caller_name or ''}.{method_name}() 调用，参数是对象字面量且包含危险键或用户输入，存在 NoSQL 注入风险。",
                        }
                        finding.update(tree_sitter_node_to_range(node))
                        context.add_finding(finding)
                        return
                    elif self._contains_identifier_in_object(first_arg, context, caller_is_db=self._is_db_related(caller_name, likely_db_objects) if caller_name else False):
                        # 对象中包含污染标识符（污点感知）
                        finding: dict[str, Any] = {
                            "type": "NOSQL_INJECTION",
                            "rule_id": self.rule_id,
                            "severity": "High",  # High 级别（因为对象字面量）
                            "line": line_no,
                            "details": f"检测到 {caller_name or ''}.{method_name}() 调用，参数是对象字面量且包含标识符（可能是用户输入），存在潜在的 NoSQL 注入风险。建议使用参数化查询。",
                        }
                        finding.update(tree_sitter_node_to_range(node))
                        context.add_finding(finding)
                        return

                # 情况 C: 参数是变量 - 使用数据流分析检测是否被污染
                elif first_arg.type == "identifier":
                    var_name = self._get_node_text(first_arg) or ""
                    # 排除明显的常量
                    if var_name.lower() not in ("true", "false", "null", "undefined", "this", "self"):
                        # DAO 文件感知（提前计算，用于决定是否跳过 sanitizer 检查）
                        fp_lower_pre = str(context.file_path).lower().replace("\\", "/")
                        is_dao_file_pre = (
                            "-dao" in fp_lower_pre
                            or "dao.js" in fp_lower_pre
                            or "dao.ts" in fp_lower_pre
                            or "_dao" in fp_lower_pre
                            or "repository" in fp_lower_pre
                        )
                        # 【Sanitizer 感知】如果变量已经被净化，跳过
                        # 例外：DAO 文件中 insert/insertOne/insertMany 不受此限制
                        # 因为 guard_clause_validation 可能因作用域混淆而误标记 insert 方法中的变量
                        if context.is_var_sanitized(var_name):
                            if not (is_dao_file_pre and method_name in ("insert", "insertOne", "insertMany")):
                                return

                        # 【降低误报】种子/迁移文件中 insert/insertMany/insertOne 不报（多为初始化数据）
                        if method_name in ("insert", "insertMany", "insertOne") and is_likely_seed_or_migration(
                            context.file_path
                        ):
                            return

                        # 【数据流分析】检查变量是否被污染（优先查 taint_graph）
                        is_tainted = context.is_var_tainted(var_name)
                        taint_source = context.get_taint_source(var_name)

                        # 复用前面计算的 is_dao_file 结果
                        is_dao_file = is_dao_file_pre

                        # 确定严重级别
                        if is_tainted:
                            # 变量被污染 -> High 级别
                            severity = "High"
                            source_info = f"（污点来源: {taint_source.source_expr}）" if taint_source else ""
                            details = f"检测到 {caller_name or ''}.{method_name}() 调用，参数变量 '{var_name}' 被污染{source_info}，存在 NoSQL 注入风险。建议使用参数化查询。"
                        elif is_dao_pattern and method_name == "update":
                            # DAO.update() 模式 -> High 级别
                            severity = "High"
                            details = f"检测到 {caller_name or ''}.{method_name}() 调用，参数是变量 '{var_name}'，在 DAO 层存在 NoSQL 注入风险。建议使用参数化查询。"
                        elif is_dao_file and method_name in ("insert", "insertOne", "insertMany"):
                            # DAO 文件中 insert 变量参数：DAO 层接收的外部数据直接插入 -> High 级别
                            severity = "High"
                            details = f"检测到 {caller_name or ''}.{method_name}() 调用，参数是变量 '{var_name}'，在 DAO 层 insert 操作中存在 NoSQL 注入风险（DAO 函数参数视为外部输入）。建议净化后再插入。"
                        else:
                            # 其他情况 -> Medium 级别
                            severity = "Medium"
                            details = f"检测到 {caller_name or ''}.{method_name}() 调用，参数是变量 '{var_name}'，可能存在 NoSQL 注入风险（建议检查变量来源）。建议使用参数化查询。"

                        finding: dict[str, Any] = {
                            "type": "NOSQL_INJECTION",
                            "rule_id": self.rule_id,
                            "severity": severity,
                            "line": line_no,
                            "details": details,
                        }
                        finding.update(tree_sitter_node_to_range(node))
                        # TDD 7.1/7.2：污点来源作为 related_locations，LSP 映射为 relatedInformation
                        if taint_source and getattr(taint_source, "line", None) is not None:
                            src_line = getattr(taint_source, "line", 0)
                            src_expr = getattr(taint_source, "source_expr", "")
                            finding["related_locations"] = [
                                make_related_location(
                                    str(context.file_path),
                                    src_line,
                                    message=f"SOURCE: {src_expr}",
                                )
                            ]
                        context.add_finding(finding)
                        return

                # 情况 D: update/updateOne/findOneAndUpdate 多参数检查
                # 检查第二个参数中的 $set/$push/$addToSet 等操作符嵌套的污染变量
                if method_name in ("update", "updateOne", "updateMany", "findOneAndUpdate") and len(all_args) >= 2:
                    update_doc = all_args[1]
                    if update_doc.type == "object":
                        if self._has_tainted_update_operator(update_doc, context):
                            finding: dict[str, Any] = {
                                "type": "NOSQL_INJECTION",
                                "rule_id": self.rule_id,
                                "severity": "High",
                                "line": line_no,
                                "details": f"检测到 {caller_name or ''}.{method_name}() 调用，更新文档（第二个参数）中 $set/$push 等操作符的值来自用户输入或污染变量，存在 NoSQL 注入风险。",
                            }
                            finding.update(tree_sitter_node_to_range(node))
                            context.add_finding(finding)
                            return

    def _is_crypto_like_update(self, caller_name: str | None) -> bool:
        """
        判断 .update() 的调用者是否像 crypto/哈希/流 API（非 NoSQL），用于降低误报。

        例如：Sha256.update、method.create().update、createHash().update、Buffer 等。
        """
        if not caller_name:
            return False
        caller_lower = caller_name.lower()
        return any(s in caller_lower for s in self.CRYPTO_LIKE_UPDATE_SUBSTRINGS)

    def _args_contain_obvious_user_input(self, call_node: Node, context: AnalysisContext) -> bool:
        """
        Quick scan of call arguments for obvious user input (req.body.*/req.query.*).

        Used to override caller whitelist: if the argument clearly contains user
        input, the call is suspicious regardless of the caller name.
        """
        for child in call_node.children:
            if child.type != "arguments":
                continue
            for arg in child.children:
                if arg.type in (",", "(", ")"):
                    continue
                if self._looks_like_user_input(arg, context):
                    return True
                # Check inside object literals: { email: req.query.email }
                if arg.type == "object":
                    if self._has_dangerous_key_or_value(arg, context):
                        return True
        return False

    def _is_db_related(self, caller_name: str, likely_db_objects: list) -> bool:
        """
        检查调用者是否像数据库对象（词边界匹配，避免子串误报）。

        使用词边界逻辑：将调用者名称按驼峰/下划线/点分割为词元，
        再对每个词元做精确匹配，杜绝 "userService" 因含 "user" 被误判。

        Args:
            caller_name: 调用者名称（如 "db.users", "usersCol"）
            likely_db_objects: 允许的精确词列表

        Returns:
            True 如果调用者像数据库对象，False 否则
        """
        if not caller_name:
            return False

        import re

        # 按 . / _ / 驼峰边界切分，例如 "usersCollection" -> ["users", "Collection"]
        tokens = re.split(r"[._]|(?<=[a-z])(?=[A-Z])", caller_name)
        tokens_lower = {t.lower() for t in tokens if t}

        db_set = {obj.lower() for obj in likely_db_objects}

        # 词元精确命中
        if tokens_lower & db_set:
            return True

        # "collection" / "col" 作为完整词元才算（避免 "color"/"protocol" 误报）
        if "collection" in tokens_lower or "col" in tokens_lower:
            return True

        return False

    def _is_simple_id_query(self, node: Node) -> bool:
        """
        判断是否为“仅按 _id/id 查询”的对象字面量，用于降低 DAO 层 findByUserId 等误报。

        例如 findOne({ _id: id })、find({ id: userId }) 等单键 id 查询多为合法 ById 查找。
        """
        if node.type != "object":
            return False
        pairs = [c for c in node.children if c.type == "pair"]
        if len(pairs) != 1:
            return False
        pair = pairs[0]
        key_text: str | None = None
        value_node: Node | None = None
        for sub in pair.children:
            if sub.type in ("property_identifier", "string"):
                key_text = self._get_node_text(sub)
            elif sub.type not in (":",):
                value_node = sub
        if not key_text or key_text not in ("_id", "id"):
            return False
        return value_node is not None and value_node.type == "identifier"

    def _has_dangerous_key_or_value(self, node: Node, context: AnalysisContext) -> bool:
        """
        检查对象字面量中是否包含危险的键或值。

        危险的键：$where, $ne, $regex 等 MongoDB 操作符（使用扩展列表）
        危险的值：req.body.*, req.query.* 等用户输入，或被污染的变量
        """
        if node.type != "object":
            return False

        for child in node.children:
            if child.type == "pair":
                # 检查键名
                for subchild in child.children:
                    if subchild.type in ("property_identifier", "string"):
                        key_text = self._get_node_text(subchild)
                        if key_text and key_text in self.DANGEROUS_OPERATORS:
                            return True
                    # 检查值是否是用户输入（结构化检测）
                    elif subchild.type == "member_expression":
                        if self._looks_like_user_input(subchild, context):
                            return True
                    # 检查值是否是被污染的变量
                    elif subchild.type == "identifier":
                        var_name = self._get_node_text(subchild)
                        if var_name and context.is_var_tainted(var_name):
                            return True
                        if self._looks_like_user_input(subchild, context):
                            return True
        return False

    def _has_tainted_update_operator(self, update_doc: Node, context: AnalysisContext) -> bool:
        """
        检查 MongoDB 更新文档（第二个参数）中 $set/$push/$addToSet 等操作符的值
        是否包含用户输入或污染变量。

        支持嵌套结构：
        - ``{$set: {field: taintedVar}}``
        - ``{$push: {array: req.body.item}}``

        Args:
            update_doc: 更新文档对象字面量 AST 节点。
            context: 分析上下文。

        Returns:
            True 当操作符值中检测到污点。
        """
        UPDATE_OPERATORS = frozenset({"$set", "$push", "$addToSet", "$pull", "$inc", "$mul", "$rename", "$unset"})
        if update_doc.type != "object":
            return False

        for child in update_doc.children:
            if child.type != "pair":
                continue
            key_text: str | None = None
            value_node: Node | None = None
            for subchild in child.children:
                if subchild.type in ("property_identifier", "string"):
                    key_text = self._get_node_text(subchild)
                elif subchild.type not in (":",):
                    value_node = subchild

            if not key_text or key_text not in UPDATE_OPERATORS:
                continue
            if value_node is None:
                continue

            # 操作符值是对象（如 {field: taintedVar}），递归检查值
            if value_node.type == "object":
                for pair in value_node.children:
                    if pair.type != "pair":
                        continue
                    for sub in pair.children:
                        if sub.type in (":", "property_identifier", "string"):
                            continue
                        # 直接用户输入（req.body.x）
                        if self._looks_like_user_input(sub, context):
                            return True
                        # 污染变量
                        if sub.type == "identifier":
                            vname = self._get_node_text(sub) or ""
                            if vname.lower() in ("true", "false", "null", "undefined"):
                                continue
                            if context.is_var_tainted(vname):
                                return True
                            # DAO 文件感知：DAO 层函数形参视为外部输入
                            fp_lower = str(context.file_path).lower().replace("\\", "/")
                            is_dao_file = (
                                "-dao" in fp_lower
                                or "dao.js" in fp_lower
                                or "dao.ts" in fp_lower
                                or "_dao" in fp_lower
                                or "repository" in fp_lower
                            )
                            if is_dao_file and context is not None:
                                # 未被追踪的变量在 DAO 文件中视为函数参数（外部输入）
                                if not context.has_tracked_var(vname):
                                    return True
            # 操作符值直接是变量或用户输入
            elif value_node.type == "identifier":
                vname = self._get_node_text(value_node) or ""
                if context.is_var_tainted(vname):
                    return True
                if self._looks_like_user_input(value_node, context):
                    return True
            elif self._looks_like_user_input(value_node, context):
                return True

        return False

    def _contains_identifier_in_object(self, node: Node, context: AnalysisContext | None = None, *, caller_is_db: bool = False) -> bool:
        """
        检查对象字面量中是否包含**来自外部/污染的**标识符。

        旧版仅排除 6 个关键字，导致 ``{ limit: PAGE_SIZE }`` 等大量合法常量被误报。
        新版引入污点感知：

        - 若 context 可用，仅当标识符在 TaintGraph 中被标记为 tainted 时才报；
        - 若标识符已被追踪（has_tracked_var）且未被污染，则跳过（视为安全局部变量）；
        - 若 context 不可用，退化为：仅报告变量名**看起来像**用户输入的标识符。

        Args:
            node: 对象字面量 AST 节点。
            context: 分析上下文（可选）。

        Returns:
            True 仅当对象中存在被污染/疑似用户输入的标识符。
        """
        if node.type != "object":
            return False

        # 全大写变量视为常量（如 PAGE_SIZE / MAX_LIMIT）
        import re

        _CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
        _BUILTIN_LITERALS = frozenset(("true", "false", "null", "undefined", "this", "self", "none"))

        for child in node.children:
            if child.type != "pair":
                continue
            for subchild in child.children:
                if subchild.type != "identifier":
                    continue
                value_text = self._get_node_text(subchild) or ""
                vl = value_text.lower()

                # 跳过 JS 关键字/字面量
                if vl in _BUILTIN_LITERALS:
                    continue
                # 跳过全大写常量（如 PAGE_SIZE / LIMIT）
                if _CONST_RE.match(value_text):
                    continue

                if context is not None:
                    # 已追踪且未污染 → 已知安全变量，跳过
                    if context.has_tracked_var(value_text) and not context.is_var_tainted(value_text):
                        continue
                    # 已追踪且污染 → 确认有风险
                    if context.is_var_tainted(value_text):
                        return True
                    # 未追踪：可能是函数参数等未收集的变量
                    user_kws = ("req", "body", "query", "param", "input", "payload", "user_id", "userid")
                    if any(kw in vl for kw in user_kws):
                        return True
                    # DAO 文件上下文感知：DAO 层函数参数几乎总是来自业务层用户输入
                    # 如 user-dao.js / memos-dao.js 中的 findOne({ userName: userName })
                    fp_lower = str(context.file_path).lower().replace("\\", "/")
                    is_dao_file = (
                        "-dao" in fp_lower
                        or "dao.js" in fp_lower
                        or "dao.ts" in fp_lower
                        or "_dao" in fp_lower
                        or "repository" in fp_lower
                    )
                    if is_dao_file:
                        return True
                    # 调用者已确认是 DB 对象（如 usersCol）→ 未追踪变量视为可疑外部输入
                    if caller_is_db:
                        return True
                    # 未追踪且名称无特征 → 不报（宁漏勿误）
                    continue

                # context 不可用时退化：仅靠名称关键词判断
                user_kws = ("req", "body", "query", "param", "input", "payload")
                if any(kw in vl for kw in user_kws):
                    return True

        return False

    def _check_query_object(self, node: Node, context: AnalysisContext) -> None:
        """检测查询对象中的 NoSQL 注入模式（使用扩展操作符列表）。"""
        for child in node.children:
            if child.type == "pair":
                # 提取键名
                key_node = None
                value_node = None

                for subchild in child.children:
                    if subchild.type in ("property_identifier", "string"):
                        key_text = self._get_node_text(subchild)
                        if key_text and key_text in self.DANGEROUS_OPERATORS:
                            key_node = subchild
                    elif subchild.type in ("string", "template_string", "identifier", "member_expression"):
                        value_node = subchild

                if key_node and value_node:
                    # 检查值是否是用户输入或被污染的变量
                    is_dangerous = False
                    if self._looks_like_user_input(value_node, context):
                        is_dangerous = True
                    elif value_node.type == "identifier":
                        var_name = self._get_node_text(value_node)
                        if var_name and context.is_var_tainted(var_name):
                            is_dangerous = True

                    if is_dangerous:
                        line_no = node.start_point[0] + 1 if hasattr(node, "start_point") else 0
                        operator = self._get_node_text(key_node)
                        finding: dict[str, Any] = {
                            "type": "NOSQL_INJECTION",
                            "rule_id": self.rule_id,
                            "severity": self.severity,
                            "line": line_no,
                            "details": f"检测到 NoSQL 查询中使用危险操作符 '{operator}' 且值来自用户输入或被污染变量，存在 NoSQL 注入风险。",
                        }
                        finding.update(tree_sitter_node_to_range(node))
                        context.add_finding(finding)
                        return

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------
    def _contains_user_input_in_object(self, node: Node) -> bool:
        """
        检查对象字面量中是否包含用户输入。

        检测模式：
        - { user: req.body.user }
        - { email: req.query.email }

        Tree-sitter AST 结构：
        object
          pair
            property_identifier (user)
            member_expression (req.body.user)
              identifier (req)
              property_identifier (body)
              property_identifier (user)
        """
        if node.type != "object":
            return False

        for child in node.children:
            if child.type == "pair":
                # pair 节点有两个子节点：key 和 value
                # 我们需要检查 value（第二个子节点）
                if len(child.children) >= 2:
                    value_node = child.children[1]  # value 是第二个子节点

                    # 检查 value 是否是用户输入（结构化检测）
                    if value_node.type == "member_expression":
                        if self._looks_like_user_input(value_node):
                            return True
                    elif value_node.type == "identifier":
                        if self._looks_like_user_input(value_node):
                            return True
        return False

    @staticmethod
    def _looks_like_user_input(node: Node, context: AnalysisContext | None = None) -> bool:
        """
        判断节点是否来自用户输入（结构化检测）。

        使用 ``is_user_input_node`` 进行 AST 结构精确匹配，
        不再使用关键词子串模糊搜索，避免 ``userProfile`` / ``formatQuery`` 等误报。

        Args:
            node: Tree-sitter AST 节点。
            context: 分析上下文（用于 DataFlowTracker 污点查询）。

        Returns:
            True 如果节点来自用户输入。
        """
        return is_user_input_node(node, context, language="javascript")

    @staticmethod
    def _get_node_text(node: Node) -> str | None:
        """提取节点的文本内容。"""
        if hasattr(node, "text"):
            return node.text.decode("utf-8")
        return None


__all__ = ["JavaScriptNoSQLInjectionAstRule"]
