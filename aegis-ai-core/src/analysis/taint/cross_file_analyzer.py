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

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, cast

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
    is_default: bool = False  # 是否默认导出
    original_name: str = ""  # 原始名称（如 export { foo as bar }）

    # 函数特有信息
    parameters: list[str] = field(default_factory=list)
    returns_tainted: bool = False
    tainted_params: set[int] = field(default_factory=set)  # 被污染的参数索引


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

    def __init__(self, project_path: Path):
        """
        初始化跨文件分析器。

        Args:
            project_path: 项目根目录
        """
        self.project_path = Path(project_path).resolve()

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

        # Tree-sitter 解析器
        self._js_parser: Parser | None = None
        self._py_parser: Parser | None = None

        if TREE_SITTER_AVAILABLE:
            try:
                js_lang = get_language("javascript")
                self._js_parser = Parser()
                self._js_parser.set_language(js_lang)

                py_lang = get_language("python")
                self._py_parser = Parser()
                self._py_parser.set_language(py_lang)
            except (ImportError, RuntimeError, OSError) as e:
                logger.debug("Failed to init Tree-sitter parsers for cross-file analysis: %s", e)

    def scan_project(self) -> None:
        """
        扫描整个项目，收集导入/导出信息。
        """
        # 查找所有代码文件
        js_files = list(self.project_path.rglob("*.js"))
        ts_files = list(self.project_path.rglob("*.ts"))
        py_files = list(self.project_path.rglob("*.py"))

        # 过滤 node_modules 等目录
        def should_include(p: Path) -> bool:
            parts = p.parts
            excluded = {"node_modules", ".git", "dist", "build", "test", "tests"}
            return not any(ex in parts for ex in excluded)

        js_files = [f for f in js_files if should_include(f)]
        ts_files = [f for f in ts_files if should_include(f)]
        py_files = [f for f in py_files if should_include(f)]

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

    def _analyze_js_file(self, file_path: Path) -> None:
        """分析 JavaScript/TypeScript 文件"""
        if not self._js_parser:
            return

        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = self._js_parser.parse(bytes(code, "utf8"))

            file_str = str(file_path)
            self._exports[file_str] = []
            self._imports[file_str] = []
            self._calls[file_str] = []

            self._traverse_js_ast(tree.root_node, file_str)

        except (OSError, RuntimeError, ValueError) as e:
            logger.warning("分析失败 %s: %s", file_path, e)

    def _traverse_js_ast(self, node: Any, file_path: str) -> None:
        """遍历 JavaScript AST"""
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
                            local_name = ""
                            if parent and parent.type == "variable_declarator":
                                id_node = self._get_child_by_type(parent, "identifier")
                                if id_node:
                                    local_name = self._get_node_text(id_node)

                            self._imports[file_path].append(
                                ModuleImport(
                                    imported_name="default",
                                    local_name=local_name or "default",
                                    module_path=module_path,
                                    file_path=file_path,
                                    line=line,
                                    is_default=True,
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
            if left and "module.exports" in self._get_node_text(left):
                line = node.start_point[0] + 1
                self._exports[file_path].append(
                    ModuleExport(
                        name="default",
                        export_type=ExportType.DEFAULT,
                        file_path=file_path,
                        line=line,
                        is_default=True,
                    )
                )

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
        line = node.start_point[0] + 1
        is_default = "default" in self._get_node_text(node)

        for child in node.children:
            # export function foo() {}
            if child.type == "function_declaration":
                name_node = self._get_child_by_type(child, "identifier")
                if name_node:
                    self._exports[file_path].append(
                        ModuleExport(
                            name=self._get_node_text(name_node),
                            export_type=ExportType.FUNCTION,
                            file_path=file_path,
                            line=line,
                            is_default=is_default,
                        )
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
                            line=line,
                            is_default=is_default,
                        )
                    )

            # export const foo = ...
            elif child.type in ("variable_declaration", "lexical_declaration"):
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        name_node = self._get_child_by_type(decl, "identifier")
                        if name_node:
                            self._exports[file_path].append(
                                ModuleExport(
                                    name=self._get_node_text(name_node),
                                    export_type=ExportType.VARIABLE,
                                    file_path=file_path,
                                    line=line,
                                    is_default=is_default,
                                )
                            )

    def _analyze_py_file(self, file_path: Path) -> None:
        """分析 Python 文件"""
        if not self._py_parser:
            return

        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = self._py_parser.parse(bytes(code, "utf8"))

            file_str = str(file_path)
            self._exports[file_str] = []
            self._imports[file_str] = []
            self._calls[file_str] = []

            self._traverse_py_ast(tree.root_node, file_str)

        except (OSError, RuntimeError, ValueError) as e:
            logger.warning("分析失败 %s: %s", file_path, e)

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
            file_dir = Path(file_path).parent

            for imp in imports:
                if imp.module_path.startswith("."):
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

        # 尝试不同的扩展名
        extensions = [".js", ".ts", ".jsx", ".tsx", "/index.js", "/index.ts", ".py"]
        for ext in extensions:
            candidate = Path(str(current) + ext)
            if candidate.exists():
                return candidate

        return None

    def _find_module_in_project(self, module_name: str) -> Path | None:
        """在项目中查找模块"""
        # 将模块名转换为路径
        module_path = module_name.replace(".", "/")

        # 尝试不同的位置
        candidates = [
            self.project_path / module_path,
            self.project_path / "src" / module_path,
            self.project_path / "lib" / module_path,
            self.project_path / "app" / module_path,
        ]

        extensions = [".js", ".ts", ".py", "/index.js", "/index.ts", "/__init__.py"]

        for base in candidates:
            for ext in extensions:
                candidate = Path(str(base) + ext)
                if candidate.exists():
                    return candidate

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

    def get_stats(self) -> dict[str, int]:
        """获取统计信息"""
        total_exports = sum(len(e) for e in self._exports.values())
        total_imports = sum(len(i) for i in self._imports.values())

        return {
            "files_analyzed": len(self._exports),
            "total_exports": total_exports,
            "total_imports": total_imports,
            "dependency_edges": sum(len(d) for d in self._dependencies.values()),
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
