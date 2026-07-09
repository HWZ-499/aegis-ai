"""
cross_file_analyzer.py - 跨文件依赖图分析器

实现跨文件的模块依赖关系解析：
1. 解析模块导入/导出关系
2. 构建项目级依赖图

支持：
- JavaScript/TypeScript: require(), import/export
- Python: import, from...import

使用示例：
    analyzer = CrossFileAnalyzer(project_path)
    analyzer.build_dependency_graph()
    stats = analyzer.get_stats()
"""

from __future__ import annotations

import ast
import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, cast

from ..base.dataflow_tracker import DataFlowTracker

# Tree-sitter 导入
try:
    from tree_sitter import Node, Parser
    from tree_sitter_languages import get_language  # type: ignore[import-untyped]

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Parser = None  # type: ignore[misc,assignment]
    Node = None  # type: ignore[misc,assignment]
    get_language = None

logger = logging.getLogger(__name__)


class ExportType(Enum):
    """导出类型"""

    FUNCTION = auto()  # 函数导出
    CLASS = auto()  # 类导出
    VARIABLE = auto()  # 变量导出
    DEFAULT = auto()  # 默认导出
    NAMESPACE = auto()  # 命名空间导出


@dataclass
class ModuleExport:
    """模块导出信息"""

    name: str  # 导出名称
    export_type: ExportType  # 导出类型
    file_path: str  # 文件路径
    line: int = 0  # 行号
    end_line: int = 0  # 结束行号
    is_default: bool = False  # 是否默认导出
    original_name: str = ""  # 原始名称（如 export { foo as bar }）

    # 函数特有信息
    parameters: list[str] = field(default_factory=list)
    returns_tainted: bool = False
    return_tainted_params: set[int] = field(default_factory=set)
    tainted_params: set[int] = field(default_factory=set)  # 被污染的参数索引
    parameter_findings: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    reexport_local_name: str = ""
    reexport_name: str = ""


@dataclass
class ModuleImport:
    """模块导入信息"""

    imported_name: str  # 导入的名称
    local_name: str  # 本地使用的名称
    module_path: str  # 模块路径（如 './utils'）
    resolved_path: str = ""  # 解析后的完整路径
    file_path: str = ""  # 导入所在文件
    line: int = 0  # 行号
    is_default: bool = False  # 是否默认导入
    is_namespace: bool = False  # 是否命名空间导入（import * as）


@dataclass
class FunctionCall:
    """函数调用信息"""

    caller_file: str  # 调用者文件
    caller_function: str  # 调用者函数
    caller_line: int  # 调用行号
    callee_name: str  # 被调用函数名
    callee_file: str = ""  # 被调用函数所在文件
    arguments: list[str] = field(default_factory=list)  # 参数列表
    tainted_args: set[int] = field(default_factory=set)  # 被污染的参数索引


class CrossFileAnalyzer:
    """
    跨文件依赖图分析器。

    分析项目中跨文件的模块导入/导出关系，构建依赖图。

    使用示例：
        analyzer = CrossFileAnalyzer(Path("./my-project"))
        analyzer.scan_project()
        stats = analyzer.get_stats()
    """

    def __init__(self, project_path: Path, source_snapshot: Mapping[Path, str] | None = None):
        """
        初始化跨文件分析器。

        Args:
            project_path: 项目根目录
            source_snapshot: 本轮项目扫描已读取的源码快照，可避免重复目录遍历和磁盘读取。
        """
        self.project_path = Path(project_path).resolve()
        self._source_snapshot = source_snapshot or {}
        self._project_source_files: set[str] | None = None
        self._module_resolution_cache: dict[str, Path | None] = {}
        self._relative_resolution_cache: dict[tuple[str, str], Path | None] = {}

        # 模块信息
        self._exports: dict[str, list[ModuleExport]] = {}  # file -> exports
        self._imports: dict[str, list[ModuleImport]] = {}  # file -> imports

        # 调用图
        self._calls: dict[str, list[FunctionCall]] = {}  # file -> calls

        # 依赖图
        self._dependencies: dict[str, set[str]] = {}  # file -> imported files
        self._dependents: dict[str, set[str]] = {}  # file -> files that import it

        # 污点信息（从单文件分析继承）
        self._file_taints: dict[str, set[str]] = {}  # file -> tainted vars
        self._findings: list[dict[str, Any]] = []
        self._baseline_findings: dict[str, list[dict[str, Any]]] = {}

        # Tree-sitter 解析器
        self._js_parser: Parser | None = None
        self._ts_parser: Parser | None = None
        self._py_parser: Parser | None = None

        if TREE_SITTER_AVAILABLE:
            try:
                js_lang = get_language("javascript")
                self._js_parser = Parser()
                self._js_parser.set_language(js_lang)
            except (ImportError, RuntimeError, OSError) as e:
                logger.debug("Failed to init JavaScript parser for cross-file analysis: %s", e)

            try:
                ts_lang = get_language("typescript")
                self._ts_parser = Parser()
                self._ts_parser.set_language(ts_lang)
            except (ImportError, RuntimeError, OSError) as e:
                logger.debug("Failed to init TypeScript parser for cross-file analysis: %s", e)

            try:
                py_lang = get_language("python")
                self._py_parser = Parser()
                self._py_parser.set_language(py_lang)
            except (ImportError, RuntimeError, OSError) as e:
                logger.debug("Failed to init Python parser for cross-file analysis: %s", e)

    def scan_project(self) -> None:
        """
        扫描整个项目，收集导入/导出信息并构建跨文件污点发现。
        """
        self._exports.clear()
        self._imports.clear()
        self._calls.clear()
        self._dependencies.clear()
        self._dependents.clear()
        self._findings.clear()
        self._baseline_findings.clear()
        self._module_resolution_cache.clear()
        self._relative_resolution_cache.clear()

        # 过滤 node_modules 等目录
        def should_include(p: Path) -> bool:
            parts = p.parts
            excluded = {"node_modules", ".git", "dist", "build", "test", "tests"}
            return not any(ex in parts for ex in excluded)

        if self._source_snapshot:
            source_files = [path for path in self._source_snapshot if should_include(path)]
            js_files = [path for path in source_files if path.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs"}]
            ts_files = [path for path in source_files if path.suffix.lower() in {".ts", ".tsx"}]
            py_files = [path for path in source_files if path.suffix.lower() in {".py", ".pyw"}]
        else:
            # Standalone mode discovers source files directly from the project.
            js_files = (
                list(self.project_path.rglob("*.js"))
                + list(self.project_path.rglob("*.jsx"))
                + list(self.project_path.rglob("*.mjs"))
                + list(self.project_path.rglob("*.cjs"))
            )
            ts_files = list(self.project_path.rglob("*.ts")) + list(self.project_path.rglob("*.tsx"))
            py_files = list(self.project_path.rglob("*.py"))
            js_files = [f for f in js_files if should_include(f)]
            ts_files = [f for f in ts_files if should_include(f)]
            py_files = [f for f in py_files if should_include(f)]

        self._project_source_files = {self._path_index_key(path) for path in [*js_files, *ts_files, *py_files]}

        # 分析 JavaScript/TypeScript 文件
        for file_path in js_files + ts_files:
            self._analyze_js_file(file_path)

        # 分析 Python 文件
        for file_path in py_files:
            self._analyze_py_file(file_path)

        # 解析模块路径
        self._resolve_module_paths()

        # 构建依赖图
        self._build_dependency_graph()

        # 通过固定点传播包装函数、返回值和重导出契约
        self._propagate_interprocedural_contracts()

        # 根据导出函数摘要和调用端参数构建跨文件发现
        self._build_cross_file_findings()

    def _analyze_js_file(self, file_path: Path) -> None:
        """分析 JavaScript/TypeScript 文件"""
        parser = self._parser_for_js_family_file(file_path)
        if not parser:
            return

        try:
            code = self._read_source(file_path)
            tree = parser.parse(bytes(code, "utf8"))

            file_str = str(file_path)
            self._exports[file_str] = []
            self._imports[file_str] = []
            self._calls[file_str] = []

            self._traverse_js_ast(tree.root_node, file_str)

        except (OSError, RuntimeError, ValueError) as e:
            logger.warning("分析失败 %s: %s", file_path, e)

    def _parser_for_js_family_file(self, file_path: Path) -> Parser | None:
        """Return the parser matching a JavaScript-family source file."""
        if file_path.suffix.lower() in {".ts", ".tsx"}:
            return self._ts_parser or self._js_parser
        return self._js_parser

    def _read_source(self, file_path: Path) -> str:
        """Read source from the project scan snapshot before falling back to disk."""
        cached = self._source_snapshot.get(file_path)
        if cached is None:
            cached = self._source_snapshot.get(file_path.resolve())
        if cached is not None:
            return cached
        return file_path.read_text(encoding="utf-8", errors="ignore")

    def _traverse_js_ast(self, node: Any, file_path: str) -> None:
        """遍历 JavaScript/TypeScript AST"""
        if not TREE_SITTER_AVAILABLE:
            return

        # 处理 require() 导入
        if node.type == "call_expression":
            callee = self._get_child_by_type(node, "identifier")
            if callee and self._get_node_text(callee) == "require":
                args = self._get_child_by_type(node, "arguments")
                if args:
                    for arg in args.children:
                        if arg.type == "string":
                            module_path = self._get_node_text(arg).strip("'\"")
                            line = node.start_point[0] + 1

                            # 查找变量声明
                            parent = node.parent
                            name_node = None
                            if parent and parent.type == "variable_declarator":
                                name_node = self._get_child_by_field(parent, "name")
                            if name_node is not None and name_node.type == "object_pattern":
                                self._record_commonjs_destructured_import(
                                    name_node,
                                    module_path,
                                    file_path,
                                    line,
                                )
                            else:
                                local_name = self._get_node_text(name_node) if name_node is not None else ""
                                self._imports[file_path].append(
                                    ModuleImport(
                                        imported_name="default",
                                        local_name=local_name or "default",
                                        module_path=module_path,
                                        file_path=file_path,
                                        line=line,
                                        is_default=True,
                                        is_namespace=bool(local_name),
                                    )
                                )

        # 处理 ES6 import
        elif node.type == "import_statement":
            self._process_es6_import(node, file_path)

        # 处理 export
        elif node.type in ("export_statement", "export_default_declaration"):
            self._process_js_export(node, file_path)

        # 处理 module.exports
        elif node.type == "assignment_expression":
            left = self._get_child_by_field(node, "left")
            if left:
                self._process_commonjs_export(node, left, file_path)

        # 递归处理子节点
        for child in node.children:
            self._traverse_js_ast(child, file_path)

    def _process_es6_import(self, node: Any, file_path: str) -> None:
        """处理 ES6 import 语句"""
        line = node.start_point[0] + 1

        # 获取模块路径
        source_node = self._get_child_by_type(node, "string")
        if not source_node:
            return
        module_path = self._get_node_text(source_node).strip("'\"")

        # 处理不同类型的导入
        for child in node.children:
            # import foo from 'module'
            if child.type == "identifier":
                self._imports[file_path].append(
                    ModuleImport(
                        imported_name="default",
                        local_name=self._get_node_text(child),
                        module_path=module_path,
                        file_path=file_path,
                        line=line,
                        is_default=True,
                    )
                )

            # import { foo, bar } from 'module'
            elif child.type == "import_clause":
                for subchild in child.children:
                    if subchild.type == "named_imports":
                        for spec in subchild.children:
                            if spec.type == "import_specifier":
                                imported = self._get_node_text(spec.children[0]) if spec.children else ""
                                local = imported
                                # 处理 as 别名
                                if len(spec.children) >= 3:
                                    local = self._get_node_text(spec.children[-1])

                                if imported:
                                    self._imports[file_path].append(
                                        ModuleImport(
                                            imported_name=imported,
                                            local_name=local,
                                            module_path=module_path,
                                            file_path=file_path,
                                            line=line,
                                        )
                                    )

                    # import * as foo from 'module'
                    elif subchild.type == "namespace_import":
                        local = self._get_node_text(subchild.children[-1]) if subchild.children else ""
                        if local:
                            self._imports[file_path].append(
                                ModuleImport(
                                    imported_name="*",
                                    local_name=local,
                                    module_path=module_path,
                                    file_path=file_path,
                                    line=line,
                                    is_namespace=True,
                                )
                            )

    def _process_js_export(self, node: Any, file_path: str) -> None:
        """处理 JavaScript export"""
        is_default = "default" in self._get_node_text(node)
        source_node = self._get_child_by_field(node, "source")
        if source_node is None:
            source_node = self._get_child_by_type(node, "string")
        module_path = self._get_node_text(source_node).strip("'\"") if source_node is not None else ""
        export_clause = self._get_child_by_type(node, "export_clause")

        if export_clause is not None:
            for specifier in export_clause.named_children:
                if specifier.type != "export_specifier":
                    continue
                name_node = self._get_child_by_field(specifier, "name")
                alias_node = self._get_child_by_field(specifier, "alias")
                if name_node is None and specifier.named_children:
                    name_node = specifier.named_children[0]
                if name_node is None:
                    continue
                original_name = self._get_node_text(name_node)
                public_name = self._get_node_text(alias_node) if alias_node is not None else original_name
                if module_path:
                    self._imports[file_path].append(
                        ModuleImport(
                            imported_name=original_name,
                            local_name=public_name,
                            module_path=module_path,
                            file_path=file_path,
                            line=node.start_point[0] + 1,
                            is_default=original_name == "default",
                        )
                    )
                elif public_name != original_name:
                    self._exports[file_path].append(
                        ModuleExport(
                            name=public_name,
                            export_type=ExportType.VARIABLE,
                            file_path=file_path,
                            line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                            original_name=original_name,
                            reexport_local_name=original_name,
                            reexport_name=original_name,
                        )
                    )

        if module_path and "*" in self._get_node_text(node) and export_clause is None:
            self._imports[file_path].append(
                ModuleImport(
                    imported_name="*",
                    local_name="*",
                    module_path=module_path,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    is_namespace=True,
                )
            )

        for child in node.children:
            # export function foo() {}
            if child.type == "function_declaration":
                name_node = self._get_child_by_type(child, "identifier")
                name = self._get_node_text(name_node) if name_node else "default"
                self._register_js_function_export(
                    child,
                    file_path,
                    name=name,
                    is_default=is_default,
                )

            # export class Foo {}
            elif child.type == "class_declaration":
                name_node = self._get_child_by_type(child, "identifier")
                if name_node:
                    self._exports[file_path].append(
                        ModuleExport(
                            name=self._get_node_text(name_node),
                            export_type=ExportType.CLASS,
                            file_path=file_path,
                            line=child.start_point[0] + 1,
                            end_line=child.end_point[0] + 1,
                            is_default=is_default,
                        )
                    )

            # export const foo = ...
            elif child.type in ("variable_declaration", "lexical_declaration"):
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        name_node = self._get_child_by_field(decl, "name")
                        if name_node:
                            value_node = self._get_child_by_field(decl, "value")
                            if value_node is not None and value_node.type in {
                                "arrow_function",
                                "function_expression",
                                "function",
                            }:
                                self._register_js_function_export(
                                    value_node,
                                    file_path,
                                    name=self._get_node_text(name_node),
                                    is_default=is_default,
                                    export_type=ExportType.VARIABLE,
                                )
                            else:
                                self._exports[file_path].append(
                                    ModuleExport(
                                        name=self._get_node_text(name_node),
                                        export_type=ExportType.VARIABLE,
                                        file_path=file_path,
                                        line=decl.start_point[0] + 1,
                                        end_line=decl.end_point[0] + 1,
                                        is_default=is_default,
                                    )
                                )

    def _record_commonjs_destructured_import(
        self,
        pattern: Any,
        module_path: str,
        file_path: str,
        line: int,
    ) -> None:
        """Record ``const { foo: local, bar } = require(...)`` imports."""
        for child in pattern.named_children:
            if child.type == "pair_pattern":
                named = list(child.named_children)
                if len(named) >= 2:
                    imported_name = self._get_node_text(named[0])
                    local_name = self._get_node_text(named[-1])
                else:
                    continue
            elif child.type == "shorthand_property_identifier_pattern":
                imported_name = local_name = self._get_node_text(child)
            else:
                continue
            self._imports[file_path].append(
                ModuleImport(
                    imported_name=imported_name,
                    local_name=local_name,
                    module_path=module_path,
                    file_path=file_path,
                    line=line,
                )
            )

    def _process_commonjs_export(self, node: Any, left: Any, file_path: str) -> None:
        """Process CommonJS function exports without treating every property as default."""
        left_text = self._get_node_text(left)
        match = re.fullmatch(r"(?:module\.)?exports(?:\.([A-Za-z_$][\w$]*))?", left_text)
        if not match:
            return

        export_name = match.group(1) or "default"
        is_default = export_name == "default"
        value_node = self._get_child_by_field(node, "right")
        if value_node is None:
            value_node = self._get_child_by_field(node, "value")

        if value_node is not None and value_node.type in {
            "arrow_function",
            "function_expression",
            "function",
        }:
            self._register_js_function_export(
                value_node,
                file_path,
                name=export_name,
                is_default=is_default,
            )
            return

        reexport_local_name = ""
        reexport_name = ""
        if value_node is not None and value_node.type == "identifier":
            reexport_local_name = self._get_node_text(value_node)
        elif value_node is not None and value_node.type == "member_expression":
            object_node = self._get_child_by_field(value_node, "object")
            property_node = self._get_child_by_field(value_node, "property")
            if object_node is not None and property_node is not None:
                reexport_local_name = self._get_node_text(object_node)
                reexport_name = self._get_node_text(property_node)

        self._exports[file_path].append(
            ModuleExport(
                name=export_name,
                export_type=ExportType.DEFAULT if is_default else ExportType.VARIABLE,
                file_path=file_path,
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                is_default=is_default,
                reexport_local_name=reexport_local_name,
                reexport_name=reexport_name,
            )
        )

    def _register_js_function_export(
        self,
        function_node: Any,
        file_path: str,
        *,
        name: str,
        is_default: bool,
        export_type: ExportType = ExportType.FUNCTION,
    ) -> None:
        parameters = self._extract_js_parameters(function_node)
        export = ModuleExport(
            name=name,
            export_type=export_type,
            file_path=file_path,
            line=function_node.start_point[0] + 1,
            end_line=function_node.end_point[0] + 1,
            is_default=is_default,
            parameters=parameters,
        )
        self._exports[file_path].append(export)
        self._summarize_js_returns(export, function_node)
        self._summarize_export_parameters(export)

    def _extract_js_parameters(self, function_node: Any) -> list[str]:
        parameters_node = self._get_child_by_field(function_node, "parameters")
        if parameters_node is None:
            parameters_node = self._get_child_by_type(function_node, "formal_parameters")
        if parameters_node is None:
            parameter_node = self._get_child_by_field(function_node, "parameter")
            return [self._get_node_text(parameter_node)] if parameter_node is not None else []

        parameters: list[str] = []
        for child in parameters_node.named_children:
            if child.type == "identifier":
                parameters.append(self._get_node_text(child))
                continue
            identifier = self._first_named_descendant(child, {"identifier"})
            if identifier is not None:
                parameters.append(self._get_node_text(identifier))
        return parameters

    def _first_named_descendant(self, node: Any, types: set[str]) -> Any | None:
        if node.type in types:
            return node
        for child in node.named_children:
            found = self._first_named_descendant(child, types)
            if found is not None:
                return found
        return None

    def _analyze_py_file(self, file_path: Path) -> None:
        """分析 Python 文件"""
        try:
            code = self._read_source(file_path)
            file_str = str(file_path)
            self._exports[file_str] = []
            self._imports[file_str] = []
            self._calls[file_str] = []

            try:
                py_tree = ast.parse(code)
            except SyntaxError:
                if not self._py_parser:
                    return
                tree = self._py_parser.parse(bytes(code, "utf8"))
                self._traverse_py_ast(tree.root_node, file_str)
            else:
                self._process_python_ast(py_tree, file_str)

        except (OSError, RuntimeError, ValueError) as e:
            logger.warning("分析失败 %s: %s", file_path, e)

    def _process_python_ast(self, tree: ast.AST, file_path: str) -> None:
        """Process Python imports and public exports using the stdlib AST."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._process_python_import(node, file_path)
            elif isinstance(node, ast.ImportFrom):
                self._process_python_from_import(node, file_path)

        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                parameters = [
                    arg.arg
                    for arg in [
                        *node.args.posonlyargs,
                        *node.args.args,
                    ]
                ]
                export = ModuleExport(
                    name=node.name,
                    export_type=ExportType.FUNCTION,
                    file_path=file_path,
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    parameters=parameters,
                )
                self._exports[file_path].append(export)
                self._summarize_python_returns(export, node)
                self._summarize_export_parameters(export)
            elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                self._exports[file_path].append(
                    ModuleExport(
                        name=node.name,
                        export_type=ExportType.CLASS,
                        file_path=file_path,
                        line=node.lineno,
                        end_line=getattr(node, "end_lineno", node.lineno),
                    )
                )

    def _process_python_import(self, node: ast.Import, file_path: str) -> None:
        for alias in node.names:
            self._imports[file_path].append(
                ModuleImport(
                    imported_name=alias.name,
                    local_name=alias.asname or alias.name.split(".")[-1],
                    module_path=alias.name,
                    file_path=file_path,
                    line=node.lineno,
                )
            )

    def _process_python_from_import(self, node: ast.ImportFrom, file_path: str) -> None:
        module = node.module or ""
        if module == "__future__":
            return

        prefix = "." * node.level
        module_path = f"{prefix}{module}" if module else prefix
        for alias in node.names:
            self._imports[file_path].append(
                ModuleImport(
                    imported_name=alias.name,
                    local_name=alias.asname or alias.name,
                    module_path=module_path,
                    file_path=file_path,
                    line=node.lineno,
                    is_namespace=alias.name == "*",
                )
            )

    def _traverse_py_ast(self, node: Any, file_path: str) -> None:
        """遍历 Python AST"""
        if not TREE_SITTER_AVAILABLE:
            return

        # import module
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    module_name = self._get_node_text(child)
                    line = node.start_point[0] + 1
                    self._imports[file_path].append(
                        ModuleImport(
                            imported_name=module_name,
                            local_name=module_name.split(".")[-1],
                            module_path=module_name,
                            file_path=file_path,
                            line=line,
                        )
                    )

        # from module import name
        elif node.type == "import_from_statement":
            module_name = ""
            for child in node.children:
                if child.type == "dotted_name":
                    module_name = self._get_node_text(child)
                elif child.type == "import_prefix":
                    # from . import ...
                    module_name = self._get_node_text(child)

            # 获取导入的名称
            for child in node.children:
                if child.type == "dotted_name" and module_name:
                    continue
                if child.type in ("dotted_name", "identifier"):
                    imported_name = self._get_node_text(child)
                    if imported_name and imported_name != module_name:
                        line = node.start_point[0] + 1
                        self._imports[file_path].append(
                            ModuleImport(
                                imported_name=imported_name,
                                local_name=imported_name,
                                module_path=module_name,
                                file_path=file_path,
                                line=line,
                            )
                        )

        # 函数定义（作为导出）
        elif node.type == "function_definition":
            name_node = self._get_child_by_type(node, "identifier")
            if name_node:
                name = self._get_node_text(name_node)
                if not name.startswith("_"):  # 非私有函数
                    line = node.start_point[0] + 1
                    self._exports[file_path].append(
                        ModuleExport(
                            name=name,
                            export_type=ExportType.FUNCTION,
                            file_path=file_path,
                            line=line,
                        )
                    )

        # 类定义（作为导出）
        elif node.type == "class_definition":
            name_node = self._get_child_by_type(node, "identifier")
            if name_node:
                name = self._get_node_text(name_node)
                if not name.startswith("_"):  # 非私有类
                    line = node.start_point[0] + 1
                    self._exports[file_path].append(
                        ModuleExport(
                            name=name,
                            export_type=ExportType.CLASS,
                            file_path=file_path,
                            line=line,
                        )
                    )

        # 递归处理子节点
        for child in node.children:
            self._traverse_py_ast(child, file_path)

    def _resolve_module_paths(self) -> None:
        """解析相对模块路径为绝对路径"""
        for file_path, imports in self._imports.items():
            path = Path(file_path)
            file_dir = Path(file_path).parent

            for imp in imports:
                if path.suffix == ".py":
                    resolved = self._resolve_python_import(path, imp)
                    if resolved:
                        imp.resolved_path = str(resolved)
                elif imp.module_path.startswith("."):
                    # 相对路径
                    resolved = self._resolve_relative_path(file_dir, imp.module_path)
                    if resolved:
                        imp.resolved_path = str(resolved)
                else:
                    # 尝试在项目中查找
                    resolved = self._find_module_in_project(imp.module_path)
                    if resolved:
                        imp.resolved_path = str(resolved)

    def _resolve_relative_path(self, base_dir: Path, module_path: str) -> Path | None:
        """解析相对模块路径"""
        cache_key = (self._path_index_key(base_dir), module_path)
        if cache_key in self._relative_resolution_cache:
            return self._relative_resolution_cache[cache_key]

        # 移除 ./ 或 ../ 前缀并计算路径
        parts = module_path.split("/")
        current = base_dir

        for part in parts:
            if part == ".":
                continue
            elif part == "..":
                current = current.parent
            else:
                current = current / part

        # 尝试原始路径及不同扩展名
        candidates = [current]
        extensions = [
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            "/index.js",
            "/index.jsx",
            "/index.mjs",
            "/index.cjs",
            "/index.ts",
            "/index.tsx",
            ".py",
        ]
        candidates.extend(Path(str(current) + ext) for ext in extensions)
        for candidate_path in candidates:
            candidate = str(candidate_path)
            if self._source_file_exists(candidate):
                resolved = Path(candidate)
                self._relative_resolution_cache[cache_key] = resolved
                return resolved

        self._relative_resolution_cache[cache_key] = None
        return None

    def _resolve_python_import(self, importer: Path, imp: ModuleImport) -> Path | None:
        """Resolve a Python import to the imported module file when possible."""
        if imp.module_path.startswith("."):
            return self._resolve_python_relative_import(importer, imp.module_path, imp.imported_name)
        return self._resolve_python_absolute_import(imp.module_path, imp.imported_name)

    def _resolve_python_relative_import(self, importer: Path, module_path: str, imported_name: str) -> Path | None:
        level = len(module_path) - len(module_path.lstrip("."))
        module_tail = module_path[level:]

        base = importer.parent
        for _ in range(max(level - 1, 0)):
            base = base.parent

        candidate = base.joinpath(*module_tail.split(".")) if module_tail else base
        return self._resolve_python_module_candidate(candidate, imported_name, prefer_submodule=not module_tail)

    def _resolve_python_absolute_import(self, module_path: str, imported_name: str) -> Path | None:
        module_file = self._find_module_in_project(module_path)
        submodule_file = None
        if imported_name and imported_name != "*":
            submodule_file = self._find_module_in_project(f"{module_path}.{imported_name}")

        if module_file and module_file.name != "__init__.py":
            return module_file
        return submodule_file or module_file

    def _resolve_python_module_candidate(
        self,
        candidate: Path,
        imported_name: str,
        *,
        prefer_submodule: bool,
    ) -> Path | None:
        module_file = self._resolve_python_candidate(candidate)
        submodule_file = None
        if imported_name and imported_name != "*":
            submodule_file = self._resolve_python_candidate(candidate / imported_name)

        if prefer_submodule and submodule_file:
            return submodule_file
        if module_file and module_file.name != "__init__.py":
            return module_file
        return submodule_file or module_file

    def _resolve_python_candidate(self, candidate: Path) -> Path | None:
        candidates = []
        if candidate.suffix == ".py":
            candidates.append(candidate)
        else:
            candidates.extend([candidate.with_suffix(".py"), candidate / "__init__.py"])

        for path in candidates:
            if self._source_file_exists(path):
                return path
        return None

    def _source_file_exists(self, candidate: Path | str) -> bool:
        """Check the scan's project file index before falling back to disk."""
        if self._project_source_files is not None:
            return self._path_index_key(candidate) in self._project_source_files
        return Path(candidate).exists()

    @staticmethod
    def _path_index_key(path: Path | str) -> str:
        """Normalize a path for lookup without touching the filesystem."""
        return os.path.normcase(os.path.abspath(os.fspath(path)))

    def _find_module_in_project(self, module_name: str) -> Path | None:
        """在项目中查找模块"""
        if module_name in self._module_resolution_cache:
            return self._module_resolution_cache[module_name]

        # 将模块名转换为路径
        module_path = module_name.replace(".", "/")

        # 尝试不同的位置
        candidates = [
            os.path.join(self.project_path, module_path),
            os.path.join(self.project_path, "src", module_path),
            os.path.join(self.project_path, "lib", module_path),
            os.path.join(self.project_path, "app", module_path),
        ]

        extensions = [
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            ".py",
            "/index.js",
            "/index.jsx",
            "/index.mjs",
            "/index.cjs",
            "/index.ts",
            "/index.tsx",
            "/__init__.py",
        ]

        for base in candidates:
            for ext in extensions:
                candidate = base + ext
                if self._source_file_exists(candidate):
                    resolved = Path(candidate)
                    self._module_resolution_cache[module_name] = resolved
                    return resolved

        self._module_resolution_cache[module_name] = None
        return None

    def _build_dependency_graph(self) -> None:
        """构建依赖图"""
        for file_path, imports in self._imports.items():
            if file_path not in self._dependencies:
                self._dependencies[file_path] = set()

            for imp in imports:
                if imp.resolved_path:
                    self._dependencies[file_path].add(imp.resolved_path)

                    # 反向依赖
                    if imp.resolved_path not in self._dependents:
                        self._dependents[imp.resolved_path] = set()
                    self._dependents[imp.resolved_path].add(file_path)

    def _summarize_python_returns(
        self,
        export: ModuleExport,
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        trackers = self._return_trackers("python", export)
        for _, kind, node in self._python_function_events(function_node):
            if kind == 0:
                for tracker in trackers:
                    self._track_python_assignment(node, tracker)
                continue
            return_node = cast(ast.Return, node)
            if return_node.value is None:
                continue
            try:
                expression = ast.unparse(return_node.value)
            except (TypeError, ValueError):
                continue
            self._record_return_taint(export, trackers, expression)

    def _summarize_js_returns(self, export: ModuleExport, function_node: Any) -> None:
        trackers = self._return_trackers("javascript", export)
        for _, kind, node in self._js_function_events(function_node):
            if kind == 0:
                for tracker in trackers:
                    self._track_js_assignment(node, tracker)
                continue
            expression_node = next(iter(node.named_children), None)
            if expression_node is None:
                continue
            self._record_return_taint(export, trackers, self._get_node_text(expression_node))
        expression_body = self._js_expression_body(function_node)
        if expression_body is not None:
            self._record_return_taint(export, trackers, self._get_node_text(expression_body))

    @staticmethod
    def _return_trackers(language: str, export: ModuleExport) -> list[DataFlowTracker]:
        trackers = [DataFlowTracker(language=language)]
        for parameter in export.parameters:
            tracker = DataFlowTracker(language=language)
            tracker.mark_as_source(parameter, export.line, source_type="function_parameter")
            trackers.append(tracker)
        return trackers

    @staticmethod
    def _record_return_taint(
        export: ModuleExport,
        trackers: list[DataFlowTracker],
        expression: str,
    ) -> None:
        if trackers[0].check_expr_taint(expression)[0]:
            export.returns_tainted = True
        for index, tracker in enumerate(trackers[1:]):
            if tracker.check_expr_taint(expression)[0]:
                export.return_tainted_params.add(index)

    def _python_function_events(
        self,
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[tuple[int, int, ast.AST]]:
        events: list[tuple[int, int, ast.AST]] = []

        def visit(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    continue
                if isinstance(child, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    events.append((getattr(child, "lineno", 0), 0, child))
                elif isinstance(child, ast.Return):
                    events.append((getattr(child, "lineno", 0), 1, child))
                visit(child)

        for statement in function_node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                events.append((getattr(statement, "lineno", 0), 0, statement))
            elif isinstance(statement, ast.Return):
                events.append((getattr(statement, "lineno", 0), 1, statement))
            visit(statement)
        return sorted(events, key=lambda item: (item[0], item[1]))

    def _js_function_events(self, function_node: Any) -> list[tuple[int, int, Any]]:
        events: list[tuple[int, int, Any]] = []
        function_types = {
            "function_declaration",
            "function_expression",
            "arrow_function",
        }

        def visit(node: Any) -> None:
            for child in node.children:
                if child is not function_node and child.type in function_types:
                    continue
                if child.type in {"variable_declarator", "assignment_expression"}:
                    events.append((child.start_point[0] + 1, 0, child))
                elif child.type == "return_statement":
                    events.append((child.start_point[0] + 1, 1, child))
                visit(child)

        visit(function_node)
        return sorted(events, key=lambda item: (item[0], item[1]))

    def _js_expression_body(self, function_node: Any) -> Any | None:
        if function_node.type != "arrow_function":
            return None
        body = self._get_child_by_field(function_node, "body")
        if body is None or body.type == "statement_block":
            return None
        return body

    def _summarize_export_parameters(self, export: ModuleExport) -> None:
        """
        Build parameter-to-sink contracts by reusing the production analyzers.

        A synthetic user-input assignment marks one exported parameter at a time.
        Findings already present in the original file are removed, so only sinks
        whose detection depends on that parameter become cross-file contracts.
        """
        if not export.parameters or export.end_line < export.line:
            return

        file_path = Path(export.file_path)
        try:
            source = self._read_source(file_path)
            baseline = self._baseline_findings.get(export.file_path)
            if baseline is None:
                baseline = self._analyze_for_contracts(source, file_path)
                self._baseline_findings[export.file_path] = baseline
        except (OSError, RuntimeError, ValueError) as exc:
            logger.debug("无法为 %s 生成跨文件函数摘要: %s", export.file_path, exc)
            return

        baseline_ids = {self._finding_identity(finding) for finding in baseline}
        for index, parameter in enumerate(export.parameters):
            if not re.fullmatch(r"[A-Za-z_$][\w$]*", parameter):
                continue
            prefix = self._synthetic_source_assignment(file_path, parameter)
            try:
                synthetic_findings = self._analyze_for_contracts(prefix + source, file_path)
            except (RuntimeError, ValueError) as exc:
                logger.debug("参数摘要分析失败 %s:%s: %s", export.file_path, parameter, exc)
                continue

            parameter_findings: list[dict[str, Any]] = []
            for finding in synthetic_findings:
                normalized = self._shift_synthetic_finding(finding, export.file_path)
                line = normalized.get("line")
                if not isinstance(line, int) or not export.line <= line <= export.end_line:
                    continue
                if self._finding_identity(normalized) in baseline_ids:
                    continue
                parameter_findings.append(normalized)

            if parameter_findings:
                export.tainted_params.add(index)
                export.parameter_findings[index] = parameter_findings

    @staticmethod
    def _synthetic_source_assignment(file_path: Path, parameter: str) -> str:
        if file_path.suffix.lower() in {".py", ".pyw"}:
            return f'{parameter} = request.args.get("__aegis_cross_file__")\n'
        return f"const {parameter} = req.query.__aegis_cross_file__;\n"

    @staticmethod
    def _finding_identity(finding: dict[str, Any]) -> tuple[Any, ...]:
        return (
            finding.get("rule_id"),
            finding.get("type"),
            finding.get("line"),
            finding.get("start_character"),
            finding.get("end_character"),
        )

    def _analyze_for_contracts(self, source: str, file_path: Path) -> list[dict[str, Any]]:
        from ..rule_engine import analyze_source

        suffix = file_path.suffix.lower()
        language = "typescript" if suffix in {".ts", ".tsx"} else "javascript"
        if suffix in {".py", ".pyw"}:
            language = "python"
        return cast(
            list[dict[str, Any]],
            analyze_source(
                source,
                file_path,
                language=language,
                include_dsl=False,
            ),
        )

    @staticmethod
    def _shift_synthetic_finding(finding: dict[str, Any], file_path: str) -> dict[str, Any]:
        shifted = dict(finding)
        for key in ("line", "start_line", "end_line"):
            value = shifted.get(key)
            if isinstance(value, int) and value > 0:
                shifted[key] = max(value - 1, 1)

        related: list[dict[str, Any]] = []
        for raw_location in shifted.get("related_locations") or []:
            if not isinstance(raw_location, dict):
                continue
            location = dict(raw_location)
            start_line = location.get("start_line", location.get("line"))
            if start_line == 1:
                continue
            for key in ("line", "start_line", "end_line"):
                value = location.get(key)
                if isinstance(value, int) and value > 0:
                    location[key] = max(value - 1, 1)
            related.append(location)
        if related:
            shifted["related_locations"] = related
        else:
            shifted.pop("related_locations", None)

        shifted["file_path"] = file_path
        shifted["file"] = file_path
        return shifted

    def _propagate_interprocedural_contracts(self) -> None:
        function_count = sum(
            1
            for exports in self._exports.values()
            for export in exports
            if export.export_type in {ExportType.FUNCTION, ExportType.DEFAULT, ExportType.VARIABLE}
        )
        for _ in range(max(function_count, 1) + 1):
            changed = False
            for file_path, exports in self._exports.items():
                suffix = Path(file_path).suffix.lower()
                if suffix in {".py", ".pyw"}:
                    changed = self._propagate_python_contracts(Path(file_path), exports) or changed
                elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
                    changed = self._propagate_js_contracts(Path(file_path), exports) or changed
            if not changed:
                break

    def _propagate_python_contracts(self, file_path: Path, exports: list[ModuleExport]) -> bool:
        try:
            tree = ast.parse(self._read_source(file_path))
        except (OSError, SyntaxError, ValueError):
            return False
        functions = {
            node.lineno: node
            for node in getattr(tree, "body", [])
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        direct_imports, namespace_imports = self._python_import_maps(file_path)
        changed = False
        for export in exports:
            function_node = functions.get(export.line)
            if function_node is None:
                continue
            trackers = self._return_trackers("python", export)
            for _, kind, node in self._python_contract_events(function_node):
                if kind == 0:
                    for tracker in trackers:
                        if not self._track_python_imported_return_assignment(
                            node,
                            tracker,
                            direct_imports,
                            namespace_imports,
                        ):
                            self._track_python_assignment(node, tracker)
                    continue
                if kind == 1:
                    call = cast(ast.Call, node)
                    resolved = self._resolve_python_imported_call(call, direct_imports, namespace_imports)
                    if resolved is None:
                        continue
                    imp, export_name = resolved
                    callee = self._find_export(imp.resolved_path, export_name)
                    if callee is None:
                        continue
                    changed = self._propagate_python_call_contract(export, call, callee, trackers) or changed
                    continue
                return_node = cast(ast.Return, node)
                if return_node.value is None:
                    continue
                if isinstance(return_node.value, ast.Call):
                    for index, tracker in enumerate(trackers):
                        if self._python_imported_call_returns_tainted(
                            return_node.value,
                            tracker,
                            direct_imports,
                            namespace_imports,
                        ):
                            changed = self._set_return_contract(export, index) or changed
                try:
                    expression = ast.unparse(return_node.value)
                except (TypeError, ValueError):
                    continue
                before = (export.returns_tainted, len(export.return_tainted_params))
                self._record_return_taint(export, trackers, expression)
                changed = before != (export.returns_tainted, len(export.return_tainted_params)) or changed
        return changed

    def _propagate_js_contracts(self, file_path: Path, exports: list[ModuleExport]) -> bool:
        parser = self._parser_for_js_family_file(file_path)
        if parser is None:
            return False
        try:
            tree = parser.parse(self._read_source(file_path).encode("utf-8"))
        except (OSError, RuntimeError, ValueError):
            return False
        nodes: list[Any] = []
        self._collect_js_nodes(tree.root_node, nodes)
        functions = {
            node.start_point[0] + 1: node
            for node in nodes
            if node.type in {"function_declaration", "function_expression", "arrow_function"}
        }
        direct_imports, namespace_imports = self._js_import_maps(file_path)
        language = "typescript" if file_path.suffix.lower() in {".ts", ".tsx"} else "javascript"
        changed = False
        for export in exports:
            function_node = functions.get(export.line)
            if function_node is None:
                continue
            trackers = self._return_trackers(language, export)
            for _, kind, node in self._js_contract_events(function_node):
                if kind == 0:
                    for tracker in trackers:
                        if not self._track_js_imported_return_assignment(
                            node,
                            tracker,
                            direct_imports,
                            namespace_imports,
                        ):
                            self._track_js_assignment(node, tracker)
                    continue
                if kind == 1:
                    resolved = self._resolve_js_imported_call(node, direct_imports, namespace_imports)
                    if resolved is None:
                        continue
                    imp, export_name = resolved
                    callee = self._find_export(imp.resolved_path, export_name)
                    if callee is None:
                        continue
                    changed = self._propagate_js_call_contract(export, node, callee, trackers) or changed
                    continue
                expression_node = next(iter(node.named_children), None)
                if expression_node is None:
                    continue
                if expression_node.type == "call_expression":
                    for index, tracker in enumerate(trackers):
                        if self._js_imported_call_returns_tainted(
                            expression_node,
                            tracker,
                            direct_imports,
                            namespace_imports,
                        ):
                            changed = self._set_return_contract(export, index) or changed
                before = (export.returns_tainted, len(export.return_tainted_params))
                self._record_return_taint(export, trackers, self._get_node_text(expression_node))
                changed = before != (export.returns_tainted, len(export.return_tainted_params)) or changed
            expression_body = self._js_expression_body(function_node)
            if expression_body is not None:
                if expression_body.type == "call_expression":
                    for index, tracker in enumerate(trackers):
                        if self._js_imported_call_returns_tainted(
                            expression_body,
                            tracker,
                            direct_imports,
                            namespace_imports,
                        ):
                            changed = self._set_return_contract(export, index) or changed
                before = (export.returns_tainted, len(export.return_tainted_params))
                self._record_return_taint(export, trackers, self._get_node_text(expression_body))
                changed = before != (export.returns_tainted, len(export.return_tainted_params)) or changed
        return changed

    def _python_contract_events(
        self,
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[tuple[int, int, ast.AST]]:
        events: list[tuple[int, int, ast.AST]] = []

        def visit(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    continue
                if isinstance(child, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    events.append((getattr(child, "lineno", 0), 0, child))
                elif isinstance(child, ast.Call):
                    events.append((getattr(child, "lineno", 0), 1, child))
                elif isinstance(child, ast.Return):
                    events.append((getattr(child, "lineno", 0), 2, child))
                visit(child)

        for statement in function_node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                events.append((getattr(statement, "lineno", 0), 0, statement))
            elif isinstance(statement, ast.Call):
                events.append((getattr(statement, "lineno", 0), 1, statement))
            elif isinstance(statement, ast.Return):
                events.append((getattr(statement, "lineno", 0), 2, statement))
            visit(statement)
        return sorted(events, key=lambda item: (item[0], item[1]))

    def _js_contract_events(self, function_node: Any) -> list[tuple[int, int, Any]]:
        events: list[tuple[int, int, Any]] = []
        function_types = {
            "function_declaration",
            "function_expression",
            "arrow_function",
        }

        def visit(node: Any) -> None:
            for child in node.children:
                if child is not function_node and child.type in function_types:
                    continue
                if child.type in {"variable_declarator", "assignment_expression"}:
                    events.append((child.start_point[0] + 1, 0, child))
                elif child.type == "call_expression":
                    events.append((child.start_point[0] + 1, 1, child))
                elif child.type == "return_statement":
                    events.append((child.start_point[0] + 1, 2, child))
                visit(child)

        visit(function_node)
        return sorted(events, key=lambda item: (item[0], item[1]))

    def _propagate_python_call_contract(
        self,
        export: ModuleExport,
        call: ast.Call,
        callee: ModuleExport,
        trackers: list[DataFlowTracker],
    ) -> bool:
        keyword_args = {kw.arg: kw.value for kw in call.keywords if kw.arg}
        changed = False
        for callee_index, findings in callee.parameter_findings.items():
            argument = (
                call.args[callee_index]
                if callee_index < len(call.args)
                else keyword_args.get(callee.parameters[callee_index])
            )
            if argument is None:
                continue
            try:
                expression = ast.unparse(argument)
            except (TypeError, ValueError):
                continue
            for parameter_index, tracker in enumerate(trackers[1:]):
                if tracker.check_expr_taint(expression)[0]:
                    changed = self._merge_parameter_findings(export, parameter_index, findings) or changed
        return changed

    def _propagate_js_call_contract(
        self,
        export: ModuleExport,
        call: Any,
        callee: ModuleExport,
        trackers: list[DataFlowTracker],
    ) -> bool:
        arguments_node = self._get_child_by_field(call, "arguments") or self._get_child_by_type(call, "arguments")
        if arguments_node is None:
            return False
        arguments = list(arguments_node.named_children)
        changed = False
        for callee_index, findings in callee.parameter_findings.items():
            if callee_index >= len(arguments):
                continue
            expression = self._get_node_text(arguments[callee_index])
            for parameter_index, tracker in enumerate(trackers[1:]):
                if tracker.check_expr_taint(expression)[0]:
                    changed = self._merge_parameter_findings(export, parameter_index, findings) or changed
        return changed

    def _merge_parameter_findings(
        self,
        export: ModuleExport,
        parameter_index: int,
        findings: list[dict[str, Any]],
    ) -> bool:
        existing = export.parameter_findings.setdefault(parameter_index, [])
        identities = {self._finding_identity(finding) for finding in existing}
        additions = [dict(finding) for finding in findings if self._finding_identity(finding) not in identities]
        if not additions:
            return False
        existing.extend(additions)
        export.tainted_params.add(parameter_index)
        return True

    @staticmethod
    def _set_return_contract(export: ModuleExport, tracker_index: int) -> bool:
        if tracker_index == 0:
            if export.returns_tainted:
                return False
            export.returns_tainted = True
            return True
        parameter_index = tracker_index - 1
        if parameter_index in export.return_tainted_params:
            return False
        export.return_tainted_params.add(parameter_index)
        return True

    def _build_cross_file_findings(self) -> None:
        for file_path in sorted(self._imports):
            path = Path(file_path)
            if path.suffix.lower() in {".py", ".pyw"}:
                self._analyze_python_calls(path)
            elif path.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
                self._analyze_js_calls(path)

    def _analyze_python_calls(self, file_path: Path) -> None:
        try:
            tree = ast.parse(self._read_source(file_path))
        except (OSError, SyntaxError, ValueError):
            return

        direct_imports, namespace_imports = self._python_import_maps(file_path)

        function_ranges = [
            (
                node.lineno,
                getattr(node, "end_lineno", node.lineno),
                f"{node.name}@{node.lineno}",
                node.name,
            )
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        events: list[tuple[int, int, str, ast.AST]] = []
        for node in ast.walk(tree):
            line = getattr(node, "lineno", 0)
            scope, _ = self._python_scope_at_line(line, function_ranges)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                events.append((line, 0, scope, node))
            elif isinstance(node, ast.Call):
                events.append((line, 1, scope, node))

        trackers: dict[str, DataFlowTracker] = {}
        for _, kind, scope, node in sorted(events, key=lambda item: (item[0], item[1])):
            tracker = trackers.setdefault(scope, DataFlowTracker(language="python"))
            if kind == 0:
                if not self._track_python_imported_return_assignment(
                    node,
                    tracker,
                    direct_imports,
                    namespace_imports,
                ):
                    self._track_python_assignment(node, tracker)
                continue
            call = cast(ast.Call, node)
            resolved = self._resolve_python_imported_call(call, direct_imports, namespace_imports)
            if resolved is None:
                continue
            imp, export_name = resolved
            export = self._find_export(imp.resolved_path, export_name)
            if export is None or not export.parameter_findings:
                continue
            _, caller_function = self._python_scope_at_line(call.lineno, function_ranges)
            self._evaluate_python_call(file_path, call, caller_function, imp, export, tracker)

    def _python_import_maps(
        self,
        file_path: Path,
    ) -> tuple[dict[str, tuple[ModuleImport, str]], dict[str, ModuleImport]]:
        direct_imports: dict[str, tuple[ModuleImport, str]] = {}
        namespace_imports: dict[str, ModuleImport] = {}
        for imp in self._imports.get(str(file_path), []):
            if not imp.resolved_path:
                continue
            resolved_stem = Path(imp.resolved_path).stem
            if (
                isinstance(imp.imported_name, str)
                and imp.imported_name not in {"*", imp.module_path}
                and imp.imported_name != resolved_stem
            ):
                direct_imports[imp.local_name] = (imp, imp.imported_name)
            else:
                namespace_imports[imp.local_name] = imp
            if imp.module_path == imp.imported_name:
                namespace_imports[imp.local_name] = imp
        return direct_imports, namespace_imports

    def _track_python_imported_return_assignment(
        self,
        node: ast.AST,
        tracker: DataFlowTracker,
        direct_imports: dict[str, tuple[ModuleImport, str]],
        namespace_imports: dict[str, ModuleImport],
    ) -> bool:
        targets: list[ast.expr]
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.NamedExpr):
            targets = [node.target]
            value = node.value
        else:
            return False
        if not isinstance(value, ast.Call):
            return False
        resolved = self._resolve_python_imported_call(value, direct_imports, namespace_imports)
        if resolved is None:
            return False
        imp, export_name = resolved
        export = self._find_export(imp.resolved_path, export_name)
        if export is None:
            return False
        is_tainted = self._python_call_return_taint(value, export, tracker)
        line = getattr(node, "lineno", 0)
        for target in targets:
            for name in self._python_target_names(target):
                if is_tainted:
                    tracker.mark_as_source(name, line, source_type="imported_return")
                else:
                    tracker.track_assignment(name, "__aegis_clean_return__", line)
        return True

    def _python_imported_call_returns_tainted(
        self,
        call: ast.Call,
        tracker: DataFlowTracker,
        direct_imports: dict[str, tuple[ModuleImport, str]],
        namespace_imports: dict[str, ModuleImport],
    ) -> bool:
        resolved = self._resolve_python_imported_call(call, direct_imports, namespace_imports)
        if resolved is None:
            return False
        imp, export_name = resolved
        export = self._find_export(imp.resolved_path, export_name)
        return export is not None and self._python_call_return_taint(call, export, tracker)

    @staticmethod
    def _python_call_return_taint(
        call: ast.Call,
        export: ModuleExport,
        tracker: DataFlowTracker,
    ) -> bool:
        if export.returns_tainted:
            return True
        keyword_args = {kw.arg: kw.value for kw in call.keywords if kw.arg}
        for index in export.return_tainted_params:
            argument = call.args[index] if index < len(call.args) else keyword_args.get(export.parameters[index])
            if argument is None:
                continue
            try:
                expression = ast.unparse(argument)
            except (TypeError, ValueError):
                continue
            if tracker.check_expr_taint(expression)[0]:
                return True
        return False

    @staticmethod
    def _python_scope_at_line(
        line: int,
        ranges: list[tuple[int, int, str, str]],
    ) -> tuple[str, str]:
        containing = [item for item in ranges if item[0] <= line <= item[1]]
        if not containing:
            return "<module>", "<module>"
        start, end, scope, name = min(containing, key=lambda item: item[1] - item[0])
        del start, end
        return scope, name

    @staticmethod
    def _track_python_assignment(node: ast.AST, tracker: DataFlowTracker) -> None:
        targets: list[ast.expr]
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.NamedExpr):
            targets = [node.target]
            value = node.value
        else:
            return
        if value is None:
            return
        try:
            value_expr = ast.unparse(value)
        except (ValueError, TypeError):
            return
        for target in targets:
            for name in CrossFileAnalyzer._python_target_names(target):
                tracker.track_assignment(name, value_expr, getattr(node, "lineno", 0))

    @staticmethod
    def _python_target_names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for element in target.elts:
                names.extend(CrossFileAnalyzer._python_target_names(element))
            return names
        return []

    @staticmethod
    def _resolve_python_imported_call(
        call: ast.Call,
        direct_imports: dict[str, tuple[ModuleImport, str]],
        namespace_imports: dict[str, ModuleImport],
    ) -> tuple[ModuleImport, str] | None:
        if isinstance(call.func, ast.Name):
            return direct_imports.get(call.func.id)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
            imp = namespace_imports.get(call.func.value.id)
            if imp is not None:
                return imp, call.func.attr
        return None

    def _evaluate_python_call(
        self,
        caller_file: Path,
        call: ast.Call,
        caller_function: str,
        imp: ModuleImport,
        export: ModuleExport,
        tracker: DataFlowTracker,
    ) -> None:
        keyword_args = {kw.arg: kw.value for kw in call.keywords if kw.arg}
        argument_texts: list[str] = []
        tainted_args: set[int] = set()
        for index, parameter_findings in export.parameter_findings.items():
            argument: ast.AST | None = (
                call.args[index] if index < len(call.args) else keyword_args.get(export.parameters[index])
            )
            if argument is None:
                continue
            try:
                argument_text = ast.unparse(argument)
            except (ValueError, TypeError):
                continue
            argument_texts.append(argument_text)
            is_tainted, source = tracker.check_expr_taint(argument_text)
            if not is_tainted:
                continue
            tainted_args.add(index)
            source_line = source.line if source is not None and source.line > 0 else call.lineno
            for contract_finding in parameter_findings:
                self._emit_cross_file_finding(
                    caller_file,
                    call.lineno,
                    caller_function,
                    imp,
                    export,
                    index,
                    argument_text,
                    source_line,
                    contract_finding,
                )

        if argument_texts:
            self._calls[str(caller_file)].append(
                FunctionCall(
                    caller_file=str(caller_file),
                    caller_function=caller_function,
                    caller_line=call.lineno,
                    callee_name=export.name,
                    callee_file=export.file_path,
                    arguments=argument_texts,
                    tainted_args=tainted_args,
                )
            )

    def _analyze_js_calls(self, file_path: Path) -> None:
        parser = self._parser_for_js_family_file(file_path)
        if parser is None:
            return
        try:
            source = self._read_source(file_path)
            tree = parser.parse(source.encode("utf-8"))
        except (OSError, RuntimeError, ValueError):
            return

        direct_imports, namespace_imports = self._js_import_maps(file_path)

        functions: list[tuple[int, int, str, str]] = []
        nodes: list[Any] = []
        self._collect_js_nodes(tree.root_node, nodes)
        for node in nodes:
            if node.type in {
                "function_declaration",
                "function_expression",
                "arrow_function",
            }:
                name = self._js_function_name(node)
                functions.append(
                    (
                        node.start_point[0] + 1,
                        node.end_point[0] + 1,
                        f"{name}@{node.start_point[0] + 1}",
                        name,
                    )
                )

        events: list[tuple[int, int, str, Any]] = []
        for node in nodes:
            line = node.start_point[0] + 1
            scope, _ = self._js_scope_at_line(line, functions)
            if node.type in {"variable_declarator", "assignment_expression"}:
                events.append((line, 0, scope, node))
            elif node.type == "call_expression":
                events.append((line, 1, scope, node))

        language = "typescript" if file_path.suffix.lower() in {".ts", ".tsx"} else "javascript"
        trackers: dict[str, DataFlowTracker] = {}
        for _, kind, scope, node in sorted(events, key=lambda item: (item[0], item[1])):
            tracker = trackers.setdefault(scope, DataFlowTracker(language=language))
            if kind == 0:
                if not self._track_js_imported_return_assignment(
                    node,
                    tracker,
                    direct_imports,
                    namespace_imports,
                ):
                    self._track_js_assignment(node, tracker)
                continue
            resolved = self._resolve_js_imported_call(node, direct_imports, namespace_imports)
            if resolved is None:
                continue
            imp, export_name = resolved
            export = self._find_export(imp.resolved_path, export_name)
            if export is None or not export.parameter_findings:
                continue
            _, caller_function = self._js_scope_at_line(node.start_point[0] + 1, functions)
            self._evaluate_js_call(file_path, node, caller_function, imp, export, tracker)

    def _js_import_maps(
        self,
        file_path: Path,
    ) -> tuple[dict[str, tuple[ModuleImport, str]], dict[str, ModuleImport]]:
        direct_imports: dict[str, tuple[ModuleImport, str]] = {}
        namespace_imports: dict[str, ModuleImport] = {}
        for imp in self._imports.get(str(file_path), []):
            if not imp.resolved_path:
                continue
            if imp.is_namespace or imp.is_default:
                namespace_imports[imp.local_name] = imp
            if imp.is_default:
                direct_imports[imp.local_name] = (imp, "default")
            if imp.imported_name not in {"*", "default"}:
                direct_imports[imp.local_name] = (imp, imp.imported_name)
        return direct_imports, namespace_imports

    def _track_js_imported_return_assignment(
        self,
        node: Any,
        tracker: DataFlowTracker,
        direct_imports: dict[str, tuple[ModuleImport, str]],
        namespace_imports: dict[str, ModuleImport],
    ) -> bool:
        if node.type == "variable_declarator":
            target = self._get_child_by_field(node, "name")
            value = self._get_child_by_field(node, "value")
        else:
            target = self._get_child_by_field(node, "left")
            value = self._get_child_by_field(node, "right")
        if target is None or target.type != "identifier" or value is None or value.type != "call_expression":
            return False
        resolved = self._resolve_js_imported_call(value, direct_imports, namespace_imports)
        if resolved is None:
            return False
        imp, export_name = resolved
        export = self._find_export(imp.resolved_path, export_name)
        if export is None:
            return False
        target_name = self._get_node_text(target)
        line = node.start_point[0] + 1
        if self._js_call_return_taint(value, export, tracker):
            tracker.mark_as_source(target_name, line, source_type="imported_return")
        else:
            tracker.track_assignment(target_name, "__aegis_clean_return__", line)
        return True

    def _js_imported_call_returns_tainted(
        self,
        call: Any,
        tracker: DataFlowTracker,
        direct_imports: dict[str, tuple[ModuleImport, str]],
        namespace_imports: dict[str, ModuleImport],
    ) -> bool:
        resolved = self._resolve_js_imported_call(call, direct_imports, namespace_imports)
        if resolved is None:
            return False
        imp, export_name = resolved
        export = self._find_export(imp.resolved_path, export_name)
        return export is not None and self._js_call_return_taint(call, export, tracker)

    def _js_call_return_taint(
        self,
        call: Any,
        export: ModuleExport,
        tracker: DataFlowTracker,
    ) -> bool:
        if export.returns_tainted:
            return True
        arguments_node = self._get_child_by_field(call, "arguments")
        if arguments_node is None:
            arguments_node = self._get_child_by_type(call, "arguments")
        if arguments_node is None:
            return False
        arguments = list(arguments_node.named_children)
        for index in export.return_tainted_params:
            if index < len(arguments) and tracker.check_expr_taint(self._get_node_text(arguments[index]))[0]:
                return True
        return False

    def _collect_js_nodes(self, node: Any, result: list[Any]) -> None:
        result.append(node)
        for child in node.children:
            self._collect_js_nodes(child, result)

    def _js_function_name(self, node: Any) -> str:
        name_node = self._get_child_by_field(node, "name")
        if name_node is not None:
            return self._get_node_text(name_node)
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            parent_name = self._get_child_by_field(parent, "name")
            if parent_name is not None:
                return self._get_node_text(parent_name)
        return "<anonymous>"

    @staticmethod
    def _js_scope_at_line(
        line: int,
        ranges: list[tuple[int, int, str, str]],
    ) -> tuple[str, str]:
        containing = [item for item in ranges if item[0] <= line <= item[1]]
        if not containing:
            return "<module>", "<module>"
        _, _, scope, name = min(containing, key=lambda item: item[1] - item[0])
        return scope, name

    def _track_js_assignment(self, node: Any, tracker: DataFlowTracker) -> None:
        if node.type == "variable_declarator":
            target = self._get_child_by_field(node, "name")
            value = self._get_child_by_field(node, "value")
        else:
            target = self._get_child_by_field(node, "left")
            value = self._get_child_by_field(node, "right")
        if target is None or value is None:
            return
        value_expr = self._get_node_text(value)
        line = node.start_point[0] + 1
        if target.type == "identifier":
            tracker.track_assignment(self._get_node_text(target), value_expr, line)
        elif target.type == "object_pattern":
            properties: list[str] = []
            for child in target.named_children:
                identifier = self._first_named_descendant(
                    child, {"identifier", "shorthand_property_identifier_pattern"}
                )
                if identifier is not None:
                    properties.append(self._get_node_text(identifier))
            tracker.track_destructuring(properties, value_expr, line)

    def _resolve_js_imported_call(
        self,
        call: Any,
        direct_imports: dict[str, tuple[ModuleImport, str]],
        namespace_imports: dict[str, ModuleImport],
    ) -> tuple[ModuleImport, str] | None:
        callee = self._get_child_by_field(call, "function")
        if callee is None and call.named_children:
            callee = call.named_children[0]
        if callee is None:
            return None
        if callee.type == "identifier":
            return direct_imports.get(self._get_node_text(callee))
        if callee.type == "member_expression":
            object_node = self._get_child_by_field(callee, "object")
            property_node = self._get_child_by_field(callee, "property")
            if object_node is None or property_node is None:
                return None
            imp = namespace_imports.get(self._get_node_text(object_node))
            if imp is not None:
                return imp, self._get_node_text(property_node)
        return None

    def _evaluate_js_call(
        self,
        caller_file: Path,
        call: Any,
        caller_function: str,
        imp: ModuleImport,
        export: ModuleExport,
        tracker: DataFlowTracker,
    ) -> None:
        arguments_node = self._get_child_by_field(call, "arguments")
        if arguments_node is None:
            arguments_node = self._get_child_by_type(call, "arguments")
        if arguments_node is None:
            return
        arguments = list(arguments_node.named_children)
        argument_texts = [self._get_node_text(argument) for argument in arguments]
        tainted_args: set[int] = set()
        call_line = call.start_point[0] + 1
        for index, parameter_findings in export.parameter_findings.items():
            if index >= len(arguments):
                continue
            argument_text = argument_texts[index]
            is_tainted, source = tracker.check_expr_taint(argument_text)
            if not is_tainted:
                continue
            tainted_args.add(index)
            source_line = source.line if source is not None and source.line > 0 else call_line
            for contract_finding in parameter_findings:
                self._emit_cross_file_finding(
                    caller_file,
                    call_line,
                    caller_function,
                    imp,
                    export,
                    index,
                    argument_text,
                    source_line,
                    contract_finding,
                )

        self._calls[str(caller_file)].append(
            FunctionCall(
                caller_file=str(caller_file),
                caller_function=caller_function,
                caller_line=call_line,
                callee_name=export.name,
                callee_file=export.file_path,
                arguments=argument_texts,
                tainted_args=tainted_args,
            )
        )

    def _find_export(
        self,
        resolved_path: str,
        export_name: str,
        visited: set[tuple[str, str]] | None = None,
    ) -> ModuleExport | None:
        path_key = self._path_index_key(resolved_path)
        lookup_key = (path_key, export_name)
        seen = visited if visited is not None else set()
        if lookup_key in seen:
            return None
        seen.add(lookup_key)

        matching_file = ""
        for file_path, exports in self._exports.items():
            if self._path_index_key(file_path) != path_key:
                continue
            matching_file = file_path
            for export in exports:
                matches = (export_name == "default" and export.is_default) or (
                    export.name == export_name or export.original_name == export_name
                )
                if not matches:
                    continue
                if export.reexport_local_name:
                    resolved = self._resolve_local_reexport(file_path, export, seen)
                    if resolved is not None:
                        return resolved
                    return export
                return export

        if not matching_file:
            matching_file = next(
                (file_path for file_path in self._imports if self._path_index_key(file_path) == path_key),
                "",
            )
        if not matching_file:
            return None

        for imp in self._imports.get(matching_file, []):
            if not imp.resolved_path:
                continue
            if imp.local_name == export_name:
                target_name = imp.imported_name
            elif imp.imported_name == "*" or imp.local_name == "*":
                target_name = export_name
            else:
                continue
            resolved = self._find_export(imp.resolved_path, target_name, seen)
            if resolved is not None:
                return resolved
        return None

    def _resolve_local_reexport(
        self,
        file_path: str,
        export: ModuleExport,
        visited: set[tuple[str, str]],
    ) -> ModuleExport | None:
        for imp in self._imports.get(file_path, []):
            if not imp.resolved_path or imp.local_name != export.reexport_local_name:
                continue
            target_name = export.reexport_name or imp.imported_name
            if target_name == "*":
                target_name = export.name
            return self._find_export(imp.resolved_path, target_name, visited)

        target_name = export.reexport_name or export.reexport_local_name
        if target_name and target_name != export.name:
            return self._find_export(file_path, target_name, visited)
        return None

    def _emit_cross_file_finding(
        self,
        caller_file: Path,
        caller_line: int,
        caller_function: str,
        imp: ModuleImport,
        export: ModuleExport,
        parameter_index: int,
        argument_text: str,
        source_line: int,
        contract_finding: dict[str, Any],
    ) -> None:
        target_path = Path(str(contract_finding.get("file_path") or export.file_path))
        try:
            target_file = str(target_path.relative_to(self.project_path))
        except ValueError:
            target_file = str(target_path)
        try:
            caller_relative = str(caller_file.relative_to(self.project_path))
        except ValueError:
            caller_relative = str(caller_file)

        related = [
            location for location in contract_finding.get("related_locations") or [] if isinstance(location, dict)
        ]
        related.append(
            {
                "file_path": str(caller_file),
                "start_line": source_line,
                "end_line": source_line,
                "start_character": 0,
                "end_character": 999,
                "message": (
                    f"用户可控参数 {argument_text} 在此传入 {export.name}({export.parameters[parameter_index]})"
                ),
            }
        )

        finding = dict(contract_finding)
        base_details = str(finding.get("details", "")).rstrip()
        finding.update(
            {
                "file": target_file,
                "file_path": str(target_path),
                "source": "CrossFile",
                "cross_file": True,
                "caller_file": str(caller_file),
                "callee_file": str(target_path),
                "callee": export.name,
                "details": (
                    f"{base_details} 跨文件调用 {caller_relative}:{caller_line} "
                    f"将用户输入传入参数 {export.parameters[parameter_index]}。"
                ).strip(),
                "related_locations": related,
                "taint_path": [
                    {
                        "node_type": "source",
                        "variable": argument_text,
                        "file_path": str(caller_file),
                        "line": source_line,
                        "description": "跨文件调用参数来自用户输入",
                    },
                    {
                        "node_type": "sink",
                        "variable": export.parameters[parameter_index],
                        "file_path": str(target_path),
                        "line": finding.get("line", export.line),
                        "description": f"导出函数 {export.name} 的参数进入安全敏感操作",
                    },
                ],
            }
        )

        identity = (
            finding.get("rule_id"),
            finding.get("type"),
            finding.get("file_path"),
            finding.get("line"),
            finding.get("caller_file"),
            caller_line,
            parameter_index,
        )
        if any(
            (
                existing.get("rule_id"),
                existing.get("type"),
                existing.get("file_path"),
                existing.get("line"),
                existing.get("caller_file"),
                existing.get("caller_line"),
                existing.get("parameter_index"),
            )
            == identity
            for existing in self._findings
        ):
            return
        finding["caller_line"] = caller_line
        finding["parameter_index"] = parameter_index
        self._findings.append(finding)

    def get_dependency_graph(self) -> dict[str, set[str]]:
        """获取依赖图"""
        return self._dependencies

    def get_module_info(self, file_path: str) -> dict[str, Any]:
        """获取模块信息"""
        return {
            "exports": [
                {"name": e.name, "type": e.export_type.name, "line": e.line} for e in self._exports.get(file_path, [])
            ],
            "imports": [
                {
                    "name": i.imported_name,
                    "local": i.local_name,
                    "from": i.module_path,
                    "resolved": i.resolved_path,
                    "line": i.line,
                }
                for i in self._imports.get(file_path, [])
            ],
            "dependencies": list(self._dependencies.get(file_path, [])),
            "dependents": list(self._dependents.get(file_path, [])),
        }

    def get_findings(self, file_path: str | None = None) -> list[dict[str, Any]]:
        """Return all cross-file findings, or only findings whose sink is in ``file_path``."""
        if file_path is None:
            return [dict(finding) for finding in self._findings]
        target_key = self._path_index_key(file_path)
        return [
            dict(finding)
            for finding in self._findings
            if self._path_index_key(str(finding.get("file_path", ""))) == target_key
        ]

    def get_stats(self) -> dict[str, int]:
        """获取统计信息"""
        total_exports = sum(len(e) for e in self._exports.values())
        total_imports = sum(len(i) for i in self._imports.values())

        return {
            "files_analyzed": len(self._exports),
            "total_exports": total_exports,
            "total_imports": total_imports,
            "dependency_edges": sum(len(d) for d in self._dependencies.values()),
            "function_contracts": sum(
                len(export.parameter_findings) for exports in self._exports.values() for export in exports
            ),
            "cross_file_findings": len(self._findings),
        }

    # 辅助方法
    @staticmethod
    def _get_node_text(node: Any) -> str:
        """获取节点文本"""
        if hasattr(node, "text"):
            return cast(bytes, node.text).decode("utf-8")
        return ""

    @staticmethod
    def _get_child_by_type(node: Any, type_name: str) -> Any | None:
        """按类型获取子节点"""
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    @staticmethod
    def _get_child_by_field(node: Any, field_name: str) -> Any | None:
        """按字段名获取子节点"""
        if hasattr(node, "child_by_field_name"):
            return node.child_by_field_name(field_name)
        return None


__all__ = [
    "CrossFileAnalyzer",
    "ModuleExport",
    "ModuleImport",
    "FunctionCall",
    "ExportType",
]
