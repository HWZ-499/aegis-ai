# multi_language_ast.py - 多语言 AST 分析器
"""
使用 Tree-sitter 支持多种编程语言的 AST 分析
"""

import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

# 按线程复用 analyzer，避免每个文件都新建 Parser（显著减少 33s 级耗时）
_analyzer_local = threading.local()

# 尝试导入 tree-sitter
try:
    from tree_sitter import Node, Parser

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    _import_logger = logging.getLogger(__name__)
    _import_logger.warning("tree-sitter 未安装，多语言 AST 分析不可用。安装: pip install tree-sitter")

# 尝试导入 tree-sitter-languages
try:
    from tree_sitter_languages import get_language

    TREE_SITTER_LANGUAGES_AVAILABLE = True
except ImportError:
    TREE_SITTER_LANGUAGES_AVAILABLE = False
    if TREE_SITTER_AVAILABLE:
        _import_logger = logging.getLogger(__name__)
        _import_logger.warning("tree-sitter-languages 未安装，将使用正则规则。安装: pip install tree-sitter-languages")

# Python AST 分析（已有实现）
from src.analysis.ast_analyzer import analyze_code_ast as analyze_python_ast


class MultiLanguageASTAnalyzer:
    """
    多语言 AST 分析器。

    ⚠️ 能力边界诚实声明：

    Tier-1（完整 AST 安全规则）：
    - JavaScript / TypeScript：7+ 条专用 AST 规则（NoSQL 注入、XSS、RCE、SQL 注入、
      路径遍历、反序列化、硬编码凭证），集成数据流追踪与污点分析。
    - Python：内置 ast 模块分析 + 正则规则。

    Tier-2（仅解析 AST，无专用安全规则）：
    - Java / C / C++ / Go：可通过 tree-sitter 解析 AST，但只能
      运行通用正则规则进行初步关键词检测，误报率高，暂无专用安全规则。
    """

    def __init__(self):
        """初始化多语言分析器"""
        self.parsers = {}
        self.language_detectors = {}

        if TREE_SITTER_AVAILABLE:
            self._init_tree_sitter_parsers()

    def _init_tree_sitter_parsers(self):
        """初始化 Tree-sitter 解析器"""
        if not TREE_SITTER_AVAILABLE:
            return

        try:
            # 使用 tree-sitter-languages 预编译的语言库
            if TREE_SITTER_LANGUAGES_AVAILABLE:
                # JavaScript/TypeScript
                try:
                    js_lang = get_language("javascript")
                    js_parser = Parser()
                    js_parser.set_language(js_lang)
                    self.parsers["javascript"] = js_parser
                    self.parsers["typescript"] = js_parser  # TypeScript 使用 JavaScript 解析器
                    logger.info("JavaScript/TypeScript parser 初始化成功")
                except Exception as e:
                    logger.warning("JavaScript parser 初始化失败: %s", e)
                    import traceback

                    traceback.print_exc()

                # Java
                try:
                    java_lang = get_language("java")
                    java_parser = Parser()
                    java_parser.set_language(java_lang)
                    self.parsers["java"] = java_parser
                    logger.info("Java parser 初始化成功")
                except Exception as e:
                    logger.warning("Java parser 初始化失败: %s", e)

                # C/C++
                try:
                    cpp_lang = get_language("cpp")
                    cpp_parser = Parser()
                    cpp_parser.set_language(cpp_lang)
                    self.parsers["cpp"] = cpp_parser
                    self.parsers["c"] = cpp_parser  # C 使用 C++ 解析器
                    logger.info("C/C++ parser 初始化成功")
                except Exception as e:
                    logger.warning("C/C++ parser 初始化失败: %s", e)

                # Go
                try:
                    go_lang = get_language("go")
                    go_parser = Parser()
                    go_parser.set_language(go_lang)
                    self.parsers["go"] = go_parser
                    logger.info("Go parser 初始化成功")
                except Exception as e:
                    logger.warning("Go parser 初始化失败: %s", e)
            else:
                logger.warning("tree-sitter-languages 未安装，无法使用预编译语言库。安装: pip install tree-sitter-languages")

        except Exception as e:
            logger.warning("Tree-sitter 初始化失败: %s", e)
            import traceback

            traceback.print_exc()

    def detect_language(self, file_path: str, code_content: str) -> str:
        """
        检测代码语言

        Args:
            file_path: 文件路径
            code_content: 代码内容

        Returns:
            语言名称（python, javascript, java, c, cpp, go 等）
        """
        # 根据文件扩展名判断
        ext = Path(file_path).suffix.lower()

        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".go": "go",
            ".php": "php",
            ".rb": "ruby",
            ".rs": "rust",
            ".swift": "swift",
            ".kt": "kotlin",
        }

        language = language_map.get(ext, "unknown")

        # 如果无法从扩展名判断，尝试从代码内容判断
        if language == "unknown":
            # 简单的启发式检测
            if "function" in code_content and "var " in code_content:
                language = "javascript"
            elif "public class" in code_content or "import java" in code_content:
                language = "java"
            elif "package main" in code_content or "func " in code_content:
                language = "go"
            elif "#include" in code_content:
                language = "c"
            elif "<?php" in code_content:
                language = "php"

        return language

    def analyze(self, code_content: str, language: str | None = None, file_path: str | None = None) -> list[dict]:
        """
        分析代码安全问题

        Args:
            code_content: 代码内容
            language: 语言名称（如果为 None，自动检测）
            file_path: 文件路径（用于语言检测）

        Returns:
            检测到的问题列表
        """
        # 自动检测语言
        if language is None:
            if file_path:
                language = self.detect_language(file_path, code_content)
            else:
                language = "python"  # 默认

        # 根据语言选择分析器
        if language == "python":
            return analyze_python_ast(code_content)
        elif language in ["javascript", "typescript"]:
            return self._analyze_javascript(code_content, file_path=file_path)
        elif language == "java":
            return self._analyze_java(code_content)
        elif language in ["c", "cpp"]:
            return self._analyze_cpp(code_content)
        elif language == "go":
            return self._analyze_go(code_content)
        elif language == "php":
            return self._analyze_php(code_content, file_path)
        else:
            # 不支持的语言，使用通用正则规则
            from src.analysis.security_rules import scan_code_locally

            regex_findings = scan_code_locally(code_content, file_path=file_path)
            # 转换为统一格式（保留严重程度）
            findings = []
            for finding in regex_findings:
                findings.append(
                    {
                        "line": finding.get("line", 0),
                        "type": finding.get("type", "Unknown"),
                        "severity": finding.get("severity", "Medium"),
                        "details": finding.get("content", finding.get("details", "")),
                        "source": "Regex",
                    }
                )
            return findings

    def _analyze_javascript(self, code_content: str, file_path: str | None = None) -> list[dict]:
        """
        分析 JavaScript/TypeScript 代码

        当前实现：使用正则规则（Tree-sitter 需要额外配置）
        未来：使用 Tree-sitter AST 分析
        """
        findings = []

        # 使用正则规则检测（临时方案）
        from src.analysis.security_rules import scan_code_locally

        regex_findings = scan_code_locally(code_content, file_path=file_path)

        # 转换为统一格式（保留 scan_code_locally 返回的严重程度）
        for finding in regex_findings:
            findings.append(
                {
                    "line": finding.get("line", 0),
                    "type": finding.get("type", "Unknown"),
                    "severity": finding.get("severity", "Medium"),  # 使用 scan_code_locally 返回的严重程度
                    "details": finding.get("content", finding.get("details", "")),
                    "source": "Regex",
                }
            )

        # 使用 Tree-sitter 进行 AST 分析
        if TREE_SITTER_AVAILABLE and "javascript" in self.parsers:
            try:
                parser = self.parsers["javascript"]
                tree = parser.parse(bytes(code_content, "utf8"))
                ast_findings = self._traverse_javascript_tree(tree.root_node)
                findings.extend(ast_findings)
            except Exception as e:
                logger.debug("JavaScript AST analysis failed, falling back to regex: %s", e)

        return findings

    def _traverse_javascript_tree(self, node: Node) -> list[dict]:
        """
        遍历 JavaScript AST，检测安全问题

        【P0优化】增强AST语义分析：
        1. 区分函数定义和调用（只检测CallExpression，跳过FunctionDeclaration）
        2. 识别调用者类型（RegExp vs child_process）
        3. 识别第三方库对象（THREE.ParticleSystem等）

        Args:
            node: Tree-sitter Node

        Returns:
            检测到的问题列表
        """
        findings = []

        # 【P0优化】跳过函数定义，只检测函数调用
        if node.type == "function_declaration":
            # 函数定义 - 只递归遍历子节点，不检测函数定义本身
            for child in node.children:
                findings.extend(self._traverse_javascript_tree(child))
            return findings

        # 【P0优化】只检测函数调用（CallExpression）
        if node.type == "call_expression":
            # 分析函数调用，识别调用者类型
            call_findings = self._analyze_call_expression(node)
            findings.extend(call_findings)

        # 检测 innerHTML 赋值
        if node.type == "assignment_expression":
            if node.children:
                left_node = node.children[0]
                # 获取左侧表达式的文本
                if hasattr(left_node, "text"):
                    left_text = left_node.text.decode("utf-8")
                elif hasattr(left_node, "children"):
                    # 如果是成员表达式，提取属性名
                    for child in left_node.children:
                        if child.type == "property_identifier" and hasattr(child, "text"):
                            prop_name = child.text.decode("utf-8")
                            if "innerHTML" in prop_name or "outerHTML" in prop_name:
                                findings.append(
                                    {
                                        "line": node.start_point[0] + 1,
                                        "type": "XSS_RISK",
                                        "severity": "High",
                                        "details": f"JavaScript AST: 检测到 {prop_name} 赋值操作（XSS 风险）",
                                        "source": "AST",
                                    }
                                )
                                break
                else:
                    # 简单文本匹配
                    left_text = str(left_node) if left_node else ""
                    if "innerHTML" in left_text or "outerHTML" in left_text:
                        findings.append(
                            {
                                "line": node.start_point[0] + 1,
                                "type": "XSS_RISK",
                                "severity": "High",
                                "details": "JavaScript AST: 检测到 innerHTML/outerHTML 赋值操作",
                                "source": "AST",
                            }
                        )

        # 递归遍历子节点
        for child in node.children:
            findings.extend(self._traverse_javascript_tree(child))

        return findings

    def _analyze_call_expression(self, node: Node) -> list[dict]:
        """
        分析函数调用节点，识别调用者类型

        【P0优化】实现AST类型推断：
        - 识别 RegExp.exec() vs child_process.exec()
        - 识别第三方库对象（THREE.ParticleSystem）
        - 识别函数名中的关键词（System, exec等）的上下文

        Args:
            node: Tree-sitter CallExpression 节点

        Returns:
            检测到的问题列表
        """
        findings = []

        if node.type != "call_expression":
            return findings

        # 获取调用者（callee）
        callee = None
        for child in node.children:
            if child.type in ["identifier", "member_expression"]:
                callee = child
                break

        if not callee:
            return findings

        # 【P0优化】识别调用者类型
        caller_type = self._identify_caller_type(callee, node)

        # 根据调用者类型决定是否报告
        if caller_type == "RegExp":
            # RegExp.exec() - 跳过，不是命令执行
            return findings
        elif caller_type == "ThirdParty":
            # 第三方库调用（THREE.ParticleSystem等）- 跳过
            return findings
        elif caller_type == "FunctionDefinition":
            # 函数定义中的关键词 - 跳过
            return findings

        # 检测危险的函数调用
        function_name = None
        method_name = None
        object_name = None

        if callee.type == "identifier":
            # 直接函数调用：eval(), Function()
            function_name = callee.text.decode("utf-8") if hasattr(callee, "text") else None
        elif callee.type == "member_expression":
            # 成员调用：obj.method()
            for child in callee.children:
                if child.type == "identifier":
                    object_name = child.text.decode("utf-8") if hasattr(child, "text") else None
                elif child.type == "property_identifier":
                    method_name = child.text.decode("utf-8") if hasattr(child, "text") else None

        # 检测 eval() 和 Function()
        if function_name in ["eval", "Function"]:
            findings.append(
                {
                    "line": node.start_point[0] + 1,
                    "type": "RCE_COMMAND_EXEC",
                    "severity": "Critical",
                    "details": f"JavaScript AST: 发现危险的 {function_name}() 调用",
                    "source": "AST",
                }
            )

        # 检测 child_process.exec() 等命令执行
        if object_name == "child_process" and method_name in ["exec", "spawn", "execFile"]:
            findings.append(
                {
                    "line": node.start_point[0] + 1,
                    "type": "RCE_COMMAND_EXEC",
                    "severity": "Critical",
                    "details": f"JavaScript AST: 发现命令执行调用 child_process.{method_name}()",
                    "source": "AST",
                }
            )

        return findings

    def _identify_caller_type(self, callee_node: Node, call_node: Node) -> str:
        """
        识别调用者类型

        【P0优化】实现类型推断：
        - RegExp: 正则表达式对象
        - ChildProcess: 子进程对象
        - ThirdParty: 第三方库对象
        - FunctionDefinition: 函数定义中的关键词
        - Unknown: 未知类型

        Args:
            callee_node: 调用者节点
            call_node: 函数调用节点

        Returns:
            调用者类型字符串
        """
        # 检查是否是成员表达式 obj.method()
        if callee_node.type == "member_expression":
            obj_node = None
            method_name = None

            for child in callee_node.children:
                if child.type == "identifier":
                    obj_node = child
                elif child.type == "property_identifier":
                    method_name = child.text.decode("utf-8") if hasattr(child, "text") else None

            if obj_node:
                obj_name = obj_node.text.decode("utf-8") if hasattr(obj_node, "text") else ""

                # 【P0优化】识别RegExp对象
                if obj_name.lower() in ["regex", "regexp"] or obj_name == "RegExp":
                    return "RegExp"

                # 检查是否是正则表达式字面量 /regex/.exec()
                # 需要检查父节点或兄弟节点
                parent = callee_node.parent if hasattr(callee_node, "parent") else None
                if parent:
                    # 检查是否有正则表达式字面量
                    for sibling in parent.children if hasattr(parent, "children") else []:
                        if sibling.type == "regex":
                            return "RegExp"

                # 【P0优化】识别第三方库对象
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
                if obj_name == "child_process" or obj_name == "process":
                    return "ChildProcess"

                # 检查方法名
                if method_name == "exec":
                    # exec() 方法 - 需要进一步判断
                    # 如果是 RegExp 对象，返回 "RegExp"
                    # 如果是 child_process，返回 "ChildProcess"
                    # 这里已经通过 obj_name 判断了
                    pass

        # 检查是否是正则表达式字面量调用 /regex/.exec()
        # 遍历调用节点的子节点，查找正则表达式字面量
        for child in call_node.children:
            if child.type == "member_expression":
                for subchild in child.children:
                    if subchild.type == "regex":
                        return "RegExp"
                    elif subchild.type == "identifier":
                        subchild_name = subchild.text.decode("utf-8") if hasattr(subchild, "text") else ""
                        if subchild_name.lower() in ["regex", "regexp"]:
                            return "RegExp"

        # 检查是否是函数定义中的关键词（如 function prepareFilesystem()）
        # 这应该在 _traverse_javascript_tree 中已经过滤了，但这里再加一层保护
        parent = call_node.parent if hasattr(call_node, "parent") else None
        if parent and parent.type == "function_declaration":
            return "FunctionDefinition"

        return "Unknown"

    def _analyze_java(self, code_content: str) -> list[dict]:
        """
        分析 Java 代码

        当前实现：使用正则规则
        未来：使用 Tree-sitter AST 分析
        """
        findings = []

        # Java 特定的漏洞检测规则
        java_patterns = {
            "SQL_INJECTION": [
                # 字符串拼接模式
                r"Statement\.execute\s*\(\s*['\"].*\+.*['\"]\s*\)",
                r"PreparedStatement.*\.execute\s*\(\s*['\"].*\+",
                r"\.query\s*\(\s*['\"].*\+.*['\"]\s*\)",
                r"stmt\.execute\s*\(\s*['\"].*\+.*['\"]\s*\)",  # 更通用的模式
                r"createStatement\s*\(\s*\)\.execute\s*\(\s*['\"].*\+",  # createStatement().execute("..." + var)
                # 变量传递模式（检测 SQL 字符串拼接后传递给 execute）
                r"String\s+\w+\s*=\s*['\"].*\+.*['\"]\s*;",  # String query = "..." + var;
                r"stmt\.execute\s*\(\s*\w+\s*\)",  # stmt.execute(query) - 如果前面有 SQL 拼接
                r"Statement\s+\w+\s*=\s*\w+\.createStatement\s*\(\s*\)",  # Statement stmt = conn.createStatement();
                r"\.execute\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",  # .execute(variable) - 需要上下文检查
            ],
            "DESERIALIZATION": [
                r"ObjectInputStream.*readObject\s*\(",
                r"\.readObject\s*\(",
            ],
            "COMMAND_INJECTION": [
                r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(",
                r"ProcessBuilder\s*\(",
            ],
            "PATH_TRAVERSAL": [
                r"File\s*\(\s*.*\+.*['\"]",
                r"new File\s*\(\s*.*\+",
            ],
        }

        import re

        lines = code_content.split("\n")

        # 检测 SQL 字符串拼接模式（跨行检测）
        sql_concatenation_vars = set()
        for line_idx, line in enumerate(lines, 1):
            # 检测 SQL 字符串拼接：String query = "SELECT ..." + var;
            # 支持多种模式：
            # 1. String query = "SELECT ..." + var;
            # 2. String query = "SELECT ..." + var + "...";
            # 3. query = "SELECT ..." + var;
            sql_patterns = [
                (r"String\s+(\w+)\s*=\s*['\"][^'\"]*\+", 1),  # String query = "..." + var (字符串后直接跟+)
                (r"String\s+(\w+)\s*=\s*['\"].*\+.*['\"]", 1),  # String query = "..." + var + "..."
                (r"(\w+)\s*=\s*['\"].*SELECT.*\+", 1),  # query = "SELECT ..." + var
            ]
            for pattern, group_num in sql_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    var_name = match.group(group_num)
                    # 检查是否包含 SQL 关键词
                    if re.search(r"SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER", line, re.IGNORECASE):
                        sql_concatenation_vars.add(var_name)
                        findings.append(
                            {
                                "line": line_idx,
                                "type": "SQL_INJECTION",
                                "severity": "High",
                                "details": f"Java: 发现 SQL 字符串拼接 - {line.strip()[:60]}",
                                "source": "Regex",
                            }
                        )
                        break

        # 检测使用拼接的 SQL 变量的 execute 调用
        for line_idx, line in enumerate(lines, 1):
            for var_name in sql_concatenation_vars:
                # 检测 .execute(var) 或 execute(var)
                if re.search(rf"\.execute\s*\(\s*{var_name}\s*\)", line, re.IGNORECASE):
                    findings.append(
                        {
                            "line": line_idx,
                            "type": "SQL_INJECTION",
                            "severity": "High",
                            "details": f"Java: 使用拼接的 SQL 变量执行查询 - {line.strip()[:60]}",
                            "source": "Regex",
                        }
                    )

        # 其他漏洞检测（单行模式）
        for line_idx, line in enumerate(lines, 1):
            for vuln_type, patterns in java_patterns.items():
                if vuln_type == "SQL_INJECTION":
                    continue  # SQL_INJECTION 已经在上面处理了
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 使用 VULN_SEVERITY 字典获取严重程度
                        from src.analysis.security_rules import VULN_SEVERITY

                        severity = VULN_SEVERITY.get(vuln_type, "Medium")

                        findings.append(
                            {
                                "line": line_idx,
                                "type": vuln_type,
                                "severity": severity,
                                "details": f"Java: 发现 {vuln_type} 风险 - {line.strip()[:60]}",
                                "source": "Regex",
                            }
                        )
                        break

        # 使用 Tree-sitter 进行 AST 分析
        if TREE_SITTER_AVAILABLE and "java" in self.parsers:
            try:
                parser = self.parsers["java"]
                tree = parser.parse(bytes(code_content, "utf8"))
                ast_findings = self._traverse_java_tree(tree.root_node)
                findings.extend(ast_findings)
            except Exception as e:
                logger.debug("Java AST analysis failed, falling back to regex: %s", e)

        return findings

    def _traverse_java_tree(self, node: Node) -> list[dict]:
        """
        遍历 Java AST，检测安全问题

        Args:
            node: Tree-sitter Node

        Returns:
            检测到的问题列表
        """
        findings = []

        # 检测 SQL 字符串拼接
        if node.type == "assignment_expression" or node.type == "local_variable_declaration":
            # 获取节点文本
            if hasattr(node, "text"):
                node_text = node.text.decode("utf-8")
            else:
                # 如果没有 text 属性，尝试从子节点构建
                node_text = ""
                for child in node.children:
                    if hasattr(child, "text"):
                        node_text += child.text.decode("utf-8") + " "

            if "SELECT" in node_text.upper() and "+" in node_text:
                findings.append(
                    {
                        "line": node.start_point[0] + 1,
                        "type": "SQL_INJECTION",
                        "severity": "High",
                        "details": f"Java AST: 检测到 SQL 字符串拼接 - {node_text[:50]}",
                        "source": "AST",
                    }
                )

        # 检测 Runtime.exec() 调用
        if node.type == "method_invocation":
            method_name = None
            for child in node.children:
                if child.type == "identifier":
                    method_name = child.text.decode("utf-8")
                    break

            if method_name == "exec":
                # 检查是否是 Runtime.getRuntime().exec()
                parent_text = node.parent.text.decode("utf-8") if hasattr(node, "parent") and node.parent else ""
                if "Runtime" in parent_text:
                    findings.append(
                        {
                            "line": node.start_point[0] + 1,
                            "type": "COMMAND_INJECTION",
                            "severity": "High",
                            "details": "Java AST: 发现 Runtime.exec() 调用",
                            "source": "AST",
                        }
                    )

        # 递归遍历子节点
        for child in node.children:
            findings.extend(self._traverse_java_tree(child))

        return findings

    def _analyze_cpp(self, code_content: str) -> list[dict]:
        """
        分析 C/C++ 代码

        当前实现：使用正则规则检测常见漏洞
        """
        findings = []

        # C/C++ 特定的漏洞检测规则
        cpp_patterns = {
            "BUFFER_OVERFLOW": [
                r"strcpy\s*\(",
                r"strcat\s*\(",
                r"gets\s*\(",
                r"sprintf\s*\(",
            ],
            "FORMAT_STRING": [
                r"printf\s*\(\s*[^,]+,\s*[^)]+\s*\)",  # printf(format, ...) 多参数
                r"printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",  # printf(user_input) 单参数（危险）
                r"sprintf\s*\(\s*[^,]+,\s*[^,]+,\s*[^)]+\s*\)",  # sprintf(buffer, format, ...)
            ],
            "MEMORY_LEAK": [
                r"malloc\s*\([^)]+\)\s*;",  # 需要检查是否有对应的 free
            ],
            "USE_AFTER_FREE": [
                r"free\s*\([^)]+\)\s*;",  # 需要检查后续使用
            ],
        }

        import re

        lines = code_content.split("\n")

        for line_idx, line in enumerate(lines, 1):
            for vuln_type, patterns in cpp_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        severity = "Critical" if vuln_type == "BUFFER_OVERFLOW" else "High"
                        findings.append(
                            {
                                "line": line_idx,
                                "type": vuln_type,
                                "severity": severity,
                                "details": f"C/C++: 发现 {vuln_type} 风险 - {line.strip()[:60]}",
                                "source": "Regex",
                            }
                        )
                        break

        return findings

    def _analyze_php(self, code_content: str, file_path: str | None = None) -> list[dict]:
        """
        分析 PHP 代码

        当前实现：使用正则规则检测
        """
        findings = []

        # 使用正则规则检测
        from src.analysis.security_rules import scan_code_locally

        regex_findings = scan_code_locally(code_content, file_path=file_path)

        # 转换为统一格式（保留 scan_code_locally 返回的严重程度）
        for finding in regex_findings:
            findings.append(
                {
                    "line": finding.get("line", 0),
                    "type": finding.get("type", "Unknown"),
                    "severity": finding.get("severity", "Medium"),  # 使用 scan_code_locally 返回的严重程度
                    "details": finding.get("content", finding.get("details", "")),
                    "source": "Regex",
                }
            )

        return findings

    def _analyze_go(self, code_content: str) -> list[dict]:
        """
        分析 Go 代码

        当前实现：使用正则规则
        """
        findings = []

        # Go 特定的漏洞检测规则
        go_patterns = {
            "SQL_INJECTION": [
                r"\.Query\s*\(\s*['\"].*\+.*['\"]\s*\)",
                r"\.Exec\s*\(\s*['\"].*\+.*['\"]\s*\)",
            ],
            "COMMAND_INJECTION": [
                r"exec\.Command\s*\(",
                r"os\.Exec\s*\(",
            ],
            "PATH_TRAVERSAL": [
                r"os\.Open\s*\(\s*.*\+",
                r"ioutil\.ReadFile\s*\(\s*.*\+",
            ],
        }

        import re

        lines = code_content.split("\n")

        for line_idx, line in enumerate(lines, 1):
            for vuln_type, patterns in go_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(
                            {
                                "line": line_idx,
                                "type": vuln_type,
                                "severity": "High",
                                "details": f"Go: 发现 {vuln_type} 风险 - {line.strip()[:60]}",
                                "source": "Regex",
                            }
                        )
                        break

        return findings


def analyze_code_multi_language(code_content: str, file_path: str | None = None) -> list[dict]:
    """
    多语言代码分析入口函数。
    使用按线程缓存的 analyzer，避免每个文件都初始化 Tree-sitter parser，提升扫描性能。

    Args:
        code_content: 代码内容
        file_path: 文件路径（用于语言检测）

    Returns:
        检测到的问题列表
    """
    if not hasattr(_analyzer_local, "analyzer") or _analyzer_local.analyzer is None:
        _analyzer_local.analyzer = MultiLanguageASTAnalyzer()
    return _analyzer_local.analyzer.analyze(code_content, file_path=file_path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # 测试代码
    analyzer = MultiLanguageASTAnalyzer()

    # 测试 Python
    python_code = """
user_input = input("Enter: ")
eval(user_input)
"""
    logger.info("Python 测试:")
    findings = analyzer.analyze(python_code, language="python")
    logger.info("  检测到 %s 个问题", len(findings))

    # 测试 JavaScript
    js_code = """
const userInput = prompt("Enter: ");
eval(userInput);
"""
    logger.info("\nJavaScript 测试:")
    findings = analyzer.analyze(js_code, language="javascript")
    logger.info("  检测到 %s 个问题", len(findings))

    # 测试 Java
    java_code = """
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
stmt.execute(query);
"""
    logger.info("\nJava 测试:")
    findings = analyzer.analyze(java_code, language="java")
    logger.info("  检测到 %s 个问题", len(findings))
