# ast_analyzer.py - 基于语法树的静态分析引擎（扩展版）
"""
.. deprecated:: 1.2.0
    此模块为旧版 Python-only AST 引擎，已被 ``rule_engine.py`` 取代。
    新代码请使用 ``from src.analysis.rule_engine import analyze_python``。
    计划在 v1.5 中移除。

扩展的 AST 规则引擎，能检测 10+ 种常见安全漏洞：
1. 代码注入（eval, exec）
2. 命令注入（os.system, subprocess）
3. SQL 注入（字符串拼接）
4. XSS 风险（未转义输出）
5. 硬编码凭证（密码、密钥）
6. 路径遍历（文件操作）
7. 反序列化风险（pickle, json）
8. 不安全的库（telnetlib）
9. 弱加密算法（MD5, SHA1）
10. 敏感信息泄露（调试信息）
"""

import ast


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []
        # 用于跟踪变量赋值，检测用户输入
        self.user_input_vars = set()
        self.assigned_vars = {}

    def _is_user_input(self, node):
        """判断节点是否可能是用户输入"""
        if isinstance(node, ast.Name):
            var_name = node.id.lower()
            # 常见的用户输入变量名
            if any(keyword in var_name for keyword in ["input", "user", "request", "param", "arg", "query", "form"]):
                return True
            # 检查是否在已知的用户输入变量集合中
            if node.id in self.user_input_vars:
                return True
        return False

    def _is_sql_string(self, node):
        """判断节点是否包含 SQL 语句"""
        if isinstance(node, ast.Str):
            sql_keywords = ["select", "insert", "update", "delete", "drop", "create", "alter"]
            return any(keyword in node.s.lower() for keyword in sql_keywords)
        elif isinstance(node, ast.JoinedStr):  # f-string
            return True
        return False

    def _is_output_function(self, node):
        """判断是否是输出函数"""
        if isinstance(node.func, ast.Name):
            return node.func.id in ["print", "write", "send", "render"]
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr in ["write", "send", "render", "response"]
        return False

    def _is_file_operation(self, node):
        """判断是否是文件操作"""
        if isinstance(node.func, ast.Name):
            return node.func.id in ["open", "file"]
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr in ["open", "read", "write"]
        return False

    def _is_deserialization(self, node):
        """判断是否是反序列化操作"""
        if isinstance(node.func, ast.Attribute):
            module = getattr(node.func.value, "id", "")
            func = node.func.attr
            if module == "pickle" and func in ["loads", "load"]:
                return True
            if module == "json" and func == "loads":
                # json.loads 需要检查参数是否可控
                return True
            if module == "yaml" and func in ["load", "safe_load"]:
                return True
        return False

    def visit_Call(self, node):
        """
        检测函数调用节点（扩展版）
        """
        # 1. 检测危险函数直接调用 (如 eval(), exec())
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ["eval", "exec", "compile"]:
                # eval/exec 是 Critical，compile 是 High
                severity = "Critical" if func_name in ["eval", "exec"] else "High"
                self.issues.append(
                    {
                        "line": node.lineno,
                        "type": "RCE_COMMAND_EXEC",
                        "severity": severity,
                        "details": f"发现高危函数调用: {func_name}()，可能导致代码注入。",
                    }
                )
            elif func_name == "input":
                # input() 通常表示用户输入，标记相关变量
                if node.args:
                    # 如果 input() 的结果被赋值，标记该变量
                    pass  # 在 visit_Assign 中处理

        # 2. 检测 subprocess.call / os.system (命令注入)
        elif isinstance(node.func, ast.Attribute):
            try:
                module_name = getattr(node.func.value, "id", "")
                func_name = node.func.attr

                if module_name == "os" and func_name == "system":
                    self.issues.append(
                        {
                            "line": node.lineno,
                            "type": "RCE_COMMAND_EXEC",
                            "severity": "Critical",  # 提升为 Critical：system() 直接执行系统命令，风险极高
                            "details": "发现 os.system() 调用，存在命令注入风险。",
                        }
                    )
                elif module_name == "subprocess" and func_name in [
                    "call",
                    "run",
                    "Popen",
                    "check_call",
                    "check_output",
                ]:
                    self.issues.append(
                        {
                            "line": node.lineno,
                            "type": "RCE_COMMAND_EXEC",
                            "severity": "Critical",  # 提升为 Critical：subprocess 函数直接执行命令，风险极高
                            "details": f"发现 subprocess.{func_name} 调用，建议检查参数是否可控。",
                        }
                    )

                # 3. 检测 XSS 风险（未转义的用户输入直接输出）
                if self._is_output_function(node) and node.args:
                    if self._is_user_input(node.args[0]):
                        self.issues.append(
                            {
                                "line": node.lineno,
                                "type": "XSS_RISK",
                                "severity": "High",  # 提升为 High，因为用户输入直接输出风险高
                                "details": "用户输入直接输出，可能存在 XSS 风险，建议进行 HTML 转义。",
                            }
                        )

                # 4. 检测路径遍历风险（文件操作使用用户输入）
                if self._is_file_operation(node) and node.args:
                    if self._is_user_input(node.args[0]):
                        self.issues.append(
                            {
                                "line": node.lineno,
                                "type": "PATH_TRAVERSAL",
                                "severity": "High",
                                "details": "文件操作使用用户输入，可能存在路径遍历风险，建议进行路径验证。",
                            }
                        )

                # 5. 检测反序列化风险
                if self._is_deserialization(node) and node.args:
                    if self._is_user_input(node.args[0]):
                        self.issues.append(
                            {
                                "line": node.lineno,
                                "type": "DESERIALIZATION",
                                "severity": "High",
                                "details": "反序列化用户输入，存在代码执行风险，建议使用安全的序列化格式或验证输入。",
                            }
                        )

                # 6. 检测弱加密算法
                if module_name == "hashlib":
                    weak_algorithms = ["md5", "sha1"]
                    if func_name in weak_algorithms:
                        self.issues.append(
                            {
                                "line": node.lineno,
                                "type": "Weak Cryptography",
                                "severity": "Medium",
                                "details": f"使用弱加密算法 {func_name}，建议使用 SHA256 或更强的算法。",
                            }
                        )
            except:
                pass  # 忽略解析失败的复杂结构

        # 继续遍历子节点
        self.generic_visit(node)

    def visit_BinOp(self, node):
        """
        检测 SQL 注入风险（字符串拼接）
        """
        if isinstance(node.op, ast.Add):
            # 检测 SQL 字符串拼接
            if self._is_sql_string(node.left) or self._is_sql_string(node.right):
                # 检查是否包含用户输入
                if self._is_user_input(node.left) or self._is_user_input(node.right):
                    self.issues.append(
                        {
                            "line": node.lineno,
                            "type": "SQL_INJECTION",
                            "severity": "High",
                            "details": "检测到 SQL 字符串拼接，且包含用户输入，存在 SQL 注入风险，建议使用参数化查询。",
                        }
                    )
        self.generic_visit(node)

    def visit_Assign(self, node):
        """
        检测硬编码凭证
        """
        if isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id.lower()

            # 检测硬编码密码、密钥
            if any(
                keyword in var_name
                for keyword in ["password", "passwd", "pwd", "secret", "key", "token", "api_key", "apikey"]
            ):
                if isinstance(node.value, (ast.Str, ast.Constant)):
                    value_str = node.value.s if isinstance(node.value, ast.Str) else str(node.value.value)
                    # 排除明显的占位符
                    if value_str and value_str not in ["", "your_key", "your_password", "placeholder"]:
                        self.issues.append(
                            {
                                "line": node.lineno,
                                "type": "HARDCODED_CREDENTIALS",
                                "severity": "High",  # 硬编码凭证改为 High（不是 Critical，因为需要访问代码才能获取）
                                "details": f"发现硬编码凭证: {var_name}，建议使用环境变量或密钥管理服务。",
                            }
                        )

            # 记录变量赋值（用于追踪用户输入）
            if isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Name) and node.value.func.id == "input":
                    self.user_input_vars.add(node.targets[0].id)
                    self.assigned_vars[node.targets[0].id] = "user_input"

        self.generic_visit(node)

    def visit_Import(self, node):
        """
        检测危险库导入
        """
        for alias in node.names:
            insecure_libs = {
                "telnetlib": "Telnet 协议传输不加密，建议使用 SSH",
                "md5": "MD5 算法已不安全，建议使用 SHA256",
                "sha": "SHA1 算法已不安全，建议使用 SHA256",
            }
            if alias.name in insecure_libs:
                self.issues.append(
                    {
                        "line": node.lineno,
                        "type": "Insecure Library",
                        "severity": "Medium",
                        "details": f"发现导入不安全的库 {alias.name}，{insecure_libs[alias.name]}。",
                    }
                )
        self.generic_visit(node)

    def visit_If(self, node):
        """
        检测调试代码（生产环境不应有）
        """
        # 检测 if __debug__ 或 if DEBUG
        if isinstance(node.test, ast.Name):
            if node.test.id in ["__debug__", "DEBUG", "debug"]:
                self.issues.append(
                    {
                        "line": node.lineno,
                        "type": "Debug Code",
                        "severity": "Low",
                        "details": "发现调试代码，生产环境建议移除。",
                    }
                )
        self.generic_visit(node)


def analyze_code_ast(code_content):
    """
    对外暴露的主函数
    """
    try:
        # 将代码解析为语法树
        tree = ast.parse(code_content)
        # 初始化访问器并开始遍历
        visitor = SecurityVisitor()
        visitor.visit(tree)
        return visitor.issues
    except SyntaxError:
        return []  # 如果不是Python代码或语法错误，直接返回空，交给AI去处理
    except Exception as e:
        print(f"AST Parse Error: {e}")
        return []
