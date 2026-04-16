# project_scanner.py - 项目扫描器
"""
批量扫描整个项目，检测所有代码文件的安全问题
"""

import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

# P1-3：单文件大小上限（超过则跳过，避免 DoS）
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB

# 添加项目根目录到 Python 路径
_current_dir = Path(__file__).parent
_project_root = _current_dir.parent.parent.parent  # aegis-ai-core
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from src.analysis.multi_language_ast import analyze_code_multi_language
from src.analysis.rule_based_audit import merge_findings
from src.analysis.rule_engine import analyze_code_ast, scan_code_locally
from src.analysis.rule_engine import (
    analyze_go as analyze_go_new,
)
from src.analysis.rule_engine import (
    analyze_java as analyze_java_new,
)
from src.analysis.rule_engine import (
    analyze_javascript as analyze_javascript_new,
)
from src.analysis.rule_engine import (
    analyze_php as analyze_php_new,
)
from src.analysis.rule_engine import (
    analyze_python as analyze_python_new,
)
from src.scanner.false_positive_manager import InlineSuppressor
from src.scanner.performance_optimizer import PerformanceOptimizer

Finding = dict[str, Any]
ScanResults = dict[str, list[Finding]]
SkippedFileEntry = tuple[str, str]


@dataclass
class ScanDiscoverySummary:
    total_files: int = 0
    discovered_files: list[str] = field(default_factory=list)
    skipped_files: list[SkippedFileEntry] = field(default_factory=list)


@dataclass
class ScanExecutionSummary:
    scanned_files: int = 0
    files_with_issues: int = 0
    total_issues: int = 0
    scan_time: float | None = None

    def note_scanned_file(self, findings: list[Finding]) -> None:
        self.scanned_files += 1
        if findings:
            self.files_with_issues += 1
            self.total_issues += len(findings)

    def note_cross_file_finding(self) -> None:
        self.total_issues += 1


@dataclass
class ScanStats:
    discovery: ScanDiscoverySummary = field(default_factory=ScanDiscoverySummary)
    execution: ScanExecutionSummary = field(default_factory=ScanExecutionSummary)

    def to_dict(self, severity_stats: dict[str, int]) -> dict[str, Any]:
        return {
            "total_files": self.discovery.total_files,
            "discovered_files": list(self.discovery.discovered_files),
            "skipped_files": list(self.discovery.skipped_files),
            "scanned_files": self.execution.scanned_files,
            "files_with_issues": self.execution.files_with_issues,
            "total_issues": self.execution.total_issues,
            "scan_time": self.execution.scan_time,
            "severity_stats": severity_stats,
        }


class ProjectScanner:
    """
    项目扫描器

    扫描整个项目目录，检测所有代码文件的安全问题
    """

    def __init__(
        self,
        project_path: str,
        ignore_patterns: list[str] | None = None,
        use_cache: bool = True,
        use_parallel: bool = True,
        max_workers: int | None = None,
        engine: str = "new",
        extra_rule_dirs: list[Path] | list[str] | None = None,
    ):
        """
        初始化项目扫描器

        Args:
            project_path: 项目根目录路径
            ignore_patterns: 要忽略的目录/文件模式列表
            use_cache: 是否使用缓存（默认 True）
            use_parallel: 是否使用并行处理（默认 True）
            max_workers: 最大工作线程/进程数（默认 CPU 核心数）
            engine: 扫描引擎类型：
                - "new":    新规则引擎（AST + 污点分析，Python/JS/TS 完整支持，默认）
                - "legacy": 旧版引擎（ast_analyzer + security_rules，兼容保留）
            extra_rule_dirs: 额外 DSL 规则目录（如 .aegis/rules），须在 project_path 下。
        """
        self.project_path = Path(project_path).resolve()
        self._extra_rule_dirs: list[Path] = []
        if extra_rule_dirs:
            for d in extra_rule_dirs:
                p = Path(d).resolve()
                if not p.is_dir():
                    continue
                try:
                    p.relative_to(self.project_path)
                    self._extra_rule_dirs.append(p)
                except ValueError:
                    logger.warning("跳过规则目录（超出项目根）: %s", p)
        if not self.project_path.exists():
            raise ValueError(f"项目路径不存在: {project_path}")

        # 扫描引擎类型
        self.engine = engine if engine in ("legacy", "new") else "new"

        # 性能优化选项
        self.use_cache = use_cache
        self.use_parallel = use_parallel
        self.max_workers = max_workers
        self.scan_results: ScanResults = {}
        self.scan_stats: ScanStats = ScanStats()

        # 初始化性能优化器
        self.optimizer: PerformanceOptimizer | None
        if use_cache or use_parallel:
            self.optimizer = PerformanceOptimizer(
                cache_dir=str(self.project_path / ".aegis-cache"),
                max_workers=max_workers,
                use_cache=use_cache,
                use_parallel=use_parallel,
            )
        else:
            self.optimizer = None

        # ──────────────────────────────────────────────
        # 支持的文件扩展名（1.4 多语言诚实标注）
        #
        # 完整支持（AST + 规则 + 污点）：Python、JavaScript、TypeScript、PHP、Java、Go
        # 基础支持（仅正则匹配）：C/C++，无专用 AST 规则，误报率较高
        # 未支持：Rust、Swift、Kotlin、C# 等无规则语言已不列入
        # ──────────────────────────────────────────────
        self._full_support = {
            ".py": "python",
            ".pyw": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".php": "php",  # PhpTaintGraph 污点分析（SQLi/XSS/RCE/OPEN_REDIRECT）
            ".java": "java",  # Java AST + TaintAnalyzer + 规则引擎
            ".go": "go",  # Go AST + TaintAnalyzer + 规则引擎
        }
        self._partial_support = {
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".h": "c",
            ".hpp": "cpp",
        }
        self.supported_extensions = {**self._full_support, **self._partial_support}
        self._init_ignore_and_excluded(ignore_patterns)

    def _reset_scan_state(self) -> None:
        """重置单次扫描的结果与统计，避免重复调用时状态泄漏。"""
        self.scan_results = {}
        self.scan_stats = ScanStats()

    def get_support_level(self, ext: str) -> str | None:
        """
        返回扩展名的支持级别，用于诚实标注与文档。

        Args:
            ext: 文件扩展名（如 ``'.py'``、``'.java'``）

        Returns:
            ``'full'`` 完整支持（AST+规则）、``'partial'`` 基础支持（仅正则）、
            不在支持列表则返回 ``None``。
        """
        if ext in self._full_support:
            return "full"
        if ext in self._partial_support:
            return "partial"
        return None

    def _init_ignore_and_excluded(self, ignore_patterns: list[str] | None) -> None:
        self.ignore_patterns = ignore_patterns or [
            ".git",
            "__pycache__",
            "node_modules",
            ".venv",
            "venv",
            ".pytest_cache",
            ".mypy_cache",
            "dist",
            "build",
            ".idea",
            ".vscode",
            ".vs",
            "*.pyc",
            "*.pyo",
            "*.pyd",
            "coverage",
            ".nyc_output",
            "vendor",
            "bower_components",
            # 压缩文件扩展名（会在_should_ignore中检查）
            "*.min.js",
            "*.min.css",
            "*.min.js.map",
            "*.bundle.js",
            "*.chunk.js",
            "*.map",
        ]

        # 文件黑名单：已知第三方库文件和构建工具配置文件（不含业务逻辑，跳过以降低噪音）
        self.excluded_files = [
            # 第三方库文件
            "three.js",
            "dat.gui.min.js",
            "jquery.min.js",
            "lodash.min.js",
            "react.min.js",
            "vue.min.js",
            "angular.min.js",
            "backbone.min.js",
            "underscore.min.js",
            # 构建工具配置文件（不应该被扫描）
            "Gruntfile.js",
            "Gulpfile.js",
            "gulpfile.js",
            "webpack.config.js",
            "rollup.config.js",
            "vite.config.js",
            "babel.config.js",
            "jest.config.js",
            "karma.config.js",
            "tsconfig.json",
            "tsconfig.base.json",  # TypeScript 配置文件
            # 注意：package.json 不应该被排除，因为它可能包含业务逻辑
            # 'package.json', 'package-lock.json',  # 依赖配置文件（通常不包含业务逻辑）
        ]

        # 目录黑名单：路径中精确匹配则排除整个子树
        # 默认仅排除依赖、缓存、构建目录；其余目录交由用户显式配置
        self.excluded_dirs = [
            ".git",
            "__pycache__",
            "node_modules",
            "vendor",
            "bower_components",
            "dist",
            "build",
            ".venv",
            "venv",
            ".pytest_cache",
            ".mypy_cache",
            "coverage",
            ".nyc_output",
            ".idea",
            ".vscode",
            ".vs",
        ]

        # 扫描结果
        self.scan_results = {}
        self.scan_stats = ScanStats()

    def _should_ignore(self, path: Path) -> bool:
        """
        判断路径是否应该被忽略。

        Args:
            path: 文件或目录路径

        Returns:
            True 如果应该忽略，False 否则
        """
        path_str = str(path)
        path_parts = path.parts

        if path.name in self.excluded_files:
            return True

        # 精确匹配相对于 project_path 的路径组件，避免：
        # 1. 'data' 误排除 'app/data/' 中的非数据目录
        # 2. 扫描根目录名本身（如 'lib'）被排除导致整个扫描目标被跳过
        try:
            rel_parts = path.relative_to(self.project_path).parts
        except ValueError:
            rel_parts = path_parts
        for excluded_dir in self.excluded_dirs:
            if excluded_dir in rel_parts:
                return True

        compressed_extensions = [".min.js", ".min.css", ".min.js.map", ".bundle.js", ".chunk.js", ".map"]
        if any(path.name.endswith(ext) for ext in compressed_extensions):
            return True

        non_code_extensions = [
            ".md",
            ".txt",
            ".json",
            ".xml",
            ".yaml",
            ".yml",
            ".csv",
            ".tsv",
            ".log",
            ".data",
            ".dump",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
        ]
        if path.suffix.lower() in non_code_extensions:
            config_files = {"package.json", "tsconfig.json", "webpack.config.js", "babel.config.js", ".eslintrc.json"}
            if path.name.lower() not in config_files:
                return True

        test_dirs = {
            "coverage",
            ".nyc_output",
        }
        for part in path_parts:
            if part.lower() in test_dirs:
                return True

        # 使用相对路径做字符串匹配，防止绝对路径前缀（如 /usr/lib）误触发规则
        try:
            rel_str = str(path.relative_to(self.project_path))
        except ValueError:
            rel_str = path_str
        for pattern in self.ignore_patterns:
            if "*" in pattern:
                if pattern.startswith("*."):
                    ext = pattern[1:]
                    if path.name.endswith(ext):
                        return True
            elif pattern == path.name or pattern in rel_str.replace("\\", "/").split("/"):
                return True

        if path.name.startswith(".") and path.name not in {".gitignore", ".env", ".env.example"}:
            return True

        return False

    def _get_discovery(self) -> tuple[list[Path], list[tuple[Path, str]]]:
        """
        获取项目中代码文件及未纳入扫描的文件与原因（用于发现摘要）。

        Returns:
            (code_files, skipped_list)，skipped_list 元素为 (path, reason)。
        """
        code_files: list[Path] = []
        skipped: list[tuple[Path, str]] = []

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if not self._should_ignore(Path(root) / d)]

            for file in files:
                file_path = Path(root) / file
                rel_path = (
                    file_path.relative_to(self.project_path)
                    if file_path.is_relative_to(self.project_path)
                    else file_path
                )

                if self._should_ignore(file_path):
                    skipped.append((rel_path, "被忽略规则排除"))
                    continue
                if file_path.suffix not in self.supported_extensions:
                    full_str = ", ".join(sorted(self._full_support.keys()))
                    part_str = ", ".join(sorted(self._partial_support.keys()))
                    skipped.append(
                        (
                            rel_path,
                            f"扩展名 {file_path.suffix} 不在支持列表（完整支持: {full_str}；基础支持: {part_str}）",
                        )
                    )
                    continue
                try:
                    if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                        skipped.append(
                            (
                                rel_path,
                                f"文件过大 ({file_path.stat().st_size / 1024 / 1024:.1f} MB > 2 MB)",
                            )
                        )
                        continue
                except OSError:
                    pass
                code_files.append(file_path)

        return code_files, skipped

    def _get_code_files(self) -> list[Path]:
        """
        获取项目中所有代码文件。

        Returns:
            代码文件路径列表
        """
        code_files, _ = self._get_discovery()
        return code_files

    def scan_file(self, file_path: Path) -> list[Finding]:
        """
        扫描单个文件（支持多语言）

        Args:
            file_path: 文件路径

        Returns:
            检测到的问题列表
        """
        try:
            # 读取文件内容
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                code = f.read()

            # 检测语言
            language = self.supported_extensions.get(file_path.suffix, "unknown")

            # 执行检测（支持多语言）
            file_path_str = str(file_path)
            extra = self._extra_rule_dirs or None
            root = self.project_path
            if language == "python" and self.engine == "new":
                merged_findings = analyze_python_new(
                    code,
                    file_path_str,
                    extra_rule_dirs=extra,
                    rules_allowed_root=root,
                )
            elif language in ("javascript", "typescript") and self.engine == "new":
                merged_findings = analyze_javascript_new(
                    code,
                    file_path_str,
                    language=language,
                    extra_rule_dirs=extra,
                    rules_allowed_root=root,
                )
            elif language == "php" and self.engine == "new":
                merged_findings = analyze_php_new(code, file_path_str)
            elif language == "java" and self.engine == "new":
                merged_findings = analyze_java_new(
                    code,
                    file_path_str,
                    extra_rule_dirs=extra,
                    rules_allowed_root=root,
                )
            elif language == "go" and self.engine == "new":
                merged_findings = analyze_go_new(
                    code,
                    file_path_str,
                    extra_rule_dirs=extra,
                    rules_allowed_root=root,
                )
            else:
                if language == "python":
                    # 旧版 Python 引擎：AST 分析 + 本地规则匹配
                    ast_findings = analyze_code_ast(code)
                    regex_findings = scan_code_locally(code, file_path=file_path_str)
                    merged_findings = merge_findings(ast_findings, regex_findings)
                else:
                    # 其他语言: 使用多语言分析器 + 通用规则
                    multi_lang_findings = analyze_code_multi_language(code, file_path_str)
                    regex_findings = scan_code_locally(code, file_path=file_path_str)
                    # 合并结果（去重）
                    merged_findings = merge_findings(multi_lang_findings, regex_findings)

            # 添加文件信息
            for finding in merged_findings:
                finding["file"] = str(file_path.relative_to(self.project_path))
                finding["file_path"] = str(file_path)
                finding["language"] = language  # 添加语言信息

            # 应用内联抑制注释（# aegis-ignore / // aegis-ignore）
            if merged_findings:
                suppressor = InlineSuppressor(code)
                merged_findings = suppressor.filter_findings(merged_findings)

            return cast(list[Finding], merged_findings)

        except (OSError, UnicodeDecodeError, RuntimeError) as e:
            logger.warning("扫描文件失败 %s: %s", file_path, e)
            return []

    def scan_project(self, verbose: bool = False) -> ScanResults:
        """
        扫描整个项目

        Args:
            verbose: 是否显示详细信息

        Returns:
            扫描结果字典，key 为文件路径，value 为问题列表
        """
        self._reset_scan_state()
        start_time = datetime.now()

        if verbose:
            logger.info("开始扫描项目: %s", self.project_path)
            logger.info("完整支持（AST+规则）: %s", ", ".join(sorted(self._full_support.keys())))
            logger.info("基础支持（仅正则）: %s", ", ".join(sorted(self._partial_support.keys())))

        # 获取代码文件及未扫描文件列表（用于发现摘要）
        code_files, skipped_list = self._get_discovery()
        self.scan_stats.discovery.total_files = len(code_files)
        self.scan_stats.discovery.discovered_files = [
            str(p.relative_to(self.project_path)) if p.is_relative_to(self.project_path) else str(p) for p in code_files
        ]
        self.scan_stats.discovery.skipped_files = [(str(p), reason) for p, reason in skipped_list]

        if verbose:
            logger.info("发现 %d 个代码文件（已纳入扫描）", len(code_files))
            for p in code_files:
                rel = p.relative_to(self.project_path) if p.is_relative_to(self.project_path) else p
                logger.debug("  ✓ %s", rel)
            if skipped_list:
                logger.info("未纳入扫描的文件: %d 个（扩展名或忽略规则）", len(skipped_list))
                for path, reason in skipped_list[:15]:
                    logger.debug("  − %s: %s", path, reason)
                if len(skipped_list) > 15:
                    logger.debug("  … 及其他 %d 个", len(skipped_list) - 15)

        # 扫描每个文件（使用性能优化）
        if self.optimizer:
            # 使用优化的扫描方法（缓存 + 并行）
            def progress_callback(completed: int, total: int, file_path: Path) -> None:
                if verbose and completed % 10 == 0:
                    logger.info("扫描进度: %d/%d", completed, total)

            optimized_results = self.optimizer.scan_files_optimized(
                code_files,
                scan_func=self.scan_file,
                project_path=self.project_path,
                supported_extensions=self.supported_extensions,
                progress_callback=progress_callback if verbose else None,
                engine=self.engine,  # 【修复】传递引擎类型
            )

            # 处理优化后的结果
            for file_path, findings in optimized_results.items():
                self.scan_stats.execution.note_scanned_file(findings)
                if findings:
                    relative_path = str(file_path.relative_to(self.project_path))
                    self.scan_results[relative_path] = findings
        else:
            # 顺序扫描（不使用优化）
            for i, file_path in enumerate(code_files, 1):
                if verbose and i % 10 == 0:
                    logger.info("扫描进度: %d/%d", i, len(code_files))

                findings = self.scan_file(file_path)
                self.scan_stats.execution.note_scanned_file(findings)
                if findings:
                    relative_path = str(file_path.relative_to(self.project_path))
                    self.scan_results[relative_path] = findings

        # ── 跨文件污点传播分析（仅新引擎 + JS/TS/Python 项目） ──
        if self.engine == "new":
            cross_file_findings = self._run_cross_file_analysis(verbose=verbose)
            for finding in cross_file_findings:
                target_file = finding.get("file")
                if not isinstance(target_file, str) or not target_file:
                    continue
                if target_file not in self.scan_results:
                    self.scan_results[target_file] = []
                self.scan_results[target_file].append(finding)
                self.scan_stats.execution.note_cross_file_finding()
            if cross_file_findings and verbose:
                logger.info("跨文件分析发现 %d 个额外污点路径", len(cross_file_findings))

        # 计算扫描时间
        end_time = datetime.now()
        self.scan_stats.execution.scan_time = (end_time - start_time).total_seconds()

        if verbose:
            logger.info(
                "扫描完成！总文件: %d | 已扫描: %d | 有问题: %d | 总问题数: %d | 耗时: %.2fs",
                self.scan_stats.discovery.total_files,
                self.scan_stats.execution.scanned_files,
                self.scan_stats.execution.files_with_issues,
                self.scan_stats.execution.total_issues,
                self.scan_stats.execution.scan_time or 0.0,
            )

        return self.scan_results

    def _run_cross_file_analysis(self, verbose: bool = False) -> list[dict]:
        """
        运行跨文件依赖图分析。

        构建模块导入/导出依赖图，用于理解项目结构。
        当前不产出 findings（跨文件污点追踪尚未实现）。

        Args:
            verbose: 是否打印详细日志

        Returns:
            空列表（保留接口供未来跨文件污点分析使用）
        """
        try:
            from src.analysis.taint import CrossFileAnalyzer
        except ImportError:
            logger.debug("CrossFileAnalyzer 不可用，跳过跨文件分析")
            return []

        try:
            if verbose:
                logger.info("开始跨文件依赖图分析...")

            cross_analyzer = CrossFileAnalyzer(self.project_path)
            cross_analyzer.scan_project()

            stats = cross_analyzer.get_stats()
            logger.debug(
                "跨文件分析：%d 个文件，%d 个导出，%d 个导入，%d 条依赖边",
                stats.get("files_analyzed", 0),
                stats.get("total_exports", 0),
                stats.get("total_imports", 0),
                stats.get("dependency_edges", 0),
            )

            return []

        except (OSError, UnicodeDecodeError, RuntimeError) as e:
            logger.warning("跨文件依赖图分析失败: %s", e)
            return []

    def _to_relative(self, file_path: str) -> str:
        """将绝对路径转为相对于项目根目录的路径字符串。"""
        try:
            return str(Path(file_path).relative_to(self.project_path))
        except ValueError:
            return file_path

    def get_stats(self) -> dict[str, Any]:
        """
        获取扫描统计信息

        Returns:
            统计信息字典
        """
        # 按严重程度统计
        severity_stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        for findings in self.scan_results.values():
            for finding in findings:
                severity = finding.get("severity", "Medium")
                severity_stats[severity] = severity_stats.get(severity, 0) + 1

        return self.scan_stats.to_dict(severity_stats)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if len(sys.argv) < 2:
        sys.stderr.write("用法: python project_scanner.py <project_path>\n")
        sys.exit(1)

    project_path = sys.argv[1]
    scanner = ProjectScanner(project_path)
    results = scanner.scan_project(verbose=True)

    logger.info("扫描结果:")
    for file_path, findings in results.items():
        logger.info("  %s: %d 个问题", file_path, len(findings))
        for finding in findings[:3]:
            logger.info("    - [%s] %s", finding.get("severity", "Medium"), finding.get("type", "Unknown"))
