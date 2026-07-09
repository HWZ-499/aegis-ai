# project_scanner.py - 项目扫描器
"""
批量扫描整个项目，检测所有代码文件的安全问题
"""

import logging
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, cast

logger = logging.getLogger(__name__)

# P1-3：单文件大小上限（超过则跳过，避免 DoS）
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB

# 添加项目根目录到 Python 路径
_current_dir = Path(__file__).parent
_project_root = _current_dir.parent.parent.parent  # aegis-ai-core
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from src.analysis.dsl import load_dsl_rule_definitions
from src.analysis.dsl.rule_schema import DslRule
from src.analysis.languages import (
    FULL_SUPPORT_EXTENSION_LANGUAGE_MAP,
    PARTIAL_SUPPORT_EXTENSION_LANGUAGE_MAP,
)
from src.analysis.rule_engine import analyze_source
from src.core.file_metadata import get_file_size
from src.scanner.false_positive_manager import InlineSuppressor
from src.scanner.performance_optimizer import PerformanceOptimizer

Finding = dict[str, Any]
ScanResults = dict[str, list[Finding]]
SkippedFileEntry = tuple[str, str]
ScanErrorEntry = dict[str, str]


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
    errors: list[ScanErrorEntry] = field(default_factory=list)

    def note_scanned_file(self, findings: list[Finding]) -> None:
        self.scanned_files += 1
        if findings:
            self.files_with_issues += 1
            self.total_issues += len(findings)

    def note_cross_file_finding(self, *, new_file_with_issue: bool = False) -> None:
        if new_file_with_issue:
            self.files_with_issues += 1
        self.total_issues += 1

    def note_scan_error(self, file_path: str, message: str, phase: str = "scan") -> None:
        self.errors.append(
            {
                "file": file_path,
                "phase": phase,
                "message": message,
            }
        )


@dataclass
class ScanStats:
    discovery: ScanDiscoverySummary = field(default_factory=ScanDiscoverySummary)
    execution: ScanExecutionSummary = field(default_factory=ScanExecutionSummary)

    def to_dict(self, severity_stats: dict[str, int]) -> dict[str, Any]:
        error_count = len(self.execution.errors)
        return {
            "total_files": self.discovery.total_files,
            "discovered_files": list(self.discovery.discovered_files),
            "skipped_files": list(self.discovery.skipped_files),
            "scanned_files": self.execution.scanned_files,
            "files_with_issues": self.execution.files_with_issues,
            "total_issues": self.execution.total_issues,
            "scan_time": self.execution.scan_time,
            "severity_stats": severity_stats,
            "partial": error_count > 0,
            "error_count": error_count,
            "errors": list(self.execution.errors),
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
        use_cross_file: bool = False,
    ):
        """
        初始化项目扫描器

        Args:
            project_path: 项目根目录路径
            ignore_patterns: 要忽略的目录/文件模式列表
            use_cache: 是否使用缓存（默认 True）
            use_parallel: 是否使用并行处理（默认 True）
            max_workers: 最大工作线程/进程数（默认 CPU 核心数）
            engine: 兼容参数；当前仅接受 ``"new"``。
            extra_rule_dirs: 额外 DSL 规则目录（如 .aegis/rules），须在 project_path 下。
            use_cross_file: 是否启用 JS/TS/Python 跨文件参数污点传播。
        """
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise ValueError(f"项目路径不存在: {project_path}")

        self._extra_rule_dirs: list[Path] = []
        for d in extra_rule_dirs or []:
            self._add_extra_rule_dir(Path(d))

        default_rules_dir = self.project_path / ".aegis" / "rules"
        if default_rules_dir.is_dir():
            self._add_extra_rule_dir(default_rules_dir)

        if engine != "new":
            raise ValueError("legacy scan engine has been removed; use engine='new'")

        # 性能优化选项
        self.use_cache = use_cache
        self.use_parallel = use_parallel
        self.max_workers = max_workers
        self.use_cross_file = use_cross_file
        self.scan_results: ScanResults = {}
        self.scan_stats: ScanStats = ScanStats()
        self._cross_file_stats: dict[str, Any] = {}
        self._failed_scan_files: set[Path] = set()
        self._scan_state_lock = Lock()
        self._scan_session_lock = Lock()
        self._dsl_rule_definitions: dict[str, tuple[DslRule, ...]] | None = None
        self._source_snapshot: dict[Path, str] = {}

        # 初始化性能优化器
        self.optimizer: PerformanceOptimizer | None
        if use_cache or use_parallel:
            self.optimizer = PerformanceOptimizer(
                cache_dir=str(self.project_path / ".aegis-cache"),
                max_workers=max_workers,
                use_cache=use_cache,
                use_parallel=use_parallel,
                rule_dirs=self._extra_rule_dirs,
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
        self._full_support = dict(FULL_SUPPORT_EXTENSION_LANGUAGE_MAP)
        self._partial_support = dict(PARTIAL_SUPPORT_EXTENSION_LANGUAGE_MAP)
        self.supported_extensions = {**self._full_support, **self._partial_support}
        self._init_ignore_and_excluded(ignore_patterns)

    def _add_extra_rule_dir(self, rule_dir: Path) -> None:
        """Add a project-local DSL rule directory, skipping unsafe or duplicate paths."""
        candidate = rule_dir if rule_dir.is_absolute() else self.project_path / rule_dir
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError) as exc:
            logger.debug("跳过不可解析规则目录 %s: %s", rule_dir, exc)
            return

        if not resolved.is_dir():
            return
        try:
            resolved.relative_to(self.project_path)
        except ValueError:
            logger.warning("跳过规则目录（超出项目根）: %s", resolved)
            return
        if resolved not in self._extra_rule_dirs:
            self._extra_rule_dirs.append(resolved)

    def _reset_scan_state(self) -> None:
        """重置单次扫描的结果与统计，避免重复调用时状态泄漏。"""
        self.scan_results = {}
        self.scan_stats = ScanStats()
        self._failed_scan_files = set()
        self._source_snapshot = {}
        self._cross_file_stats = {}

    @contextmanager
    def scan_session(self) -> Iterator[None]:
        """
        Own one top-level scan lifecycle.

        Per-scan state and rule snapshots are always released on exit. Persistent
        disk caches and shared parser caches intentionally outlive this context.
        """
        with self._scan_session_lock:
            self._reset_scan_state()
            self._dsl_rule_definitions = load_dsl_rule_definitions(
                extra_dirs=self._extra_rule_dirs,
                allowed_root=self.project_path,
            )
            started_at = datetime.now()
            try:
                yield
            finally:
                if self.scan_stats.execution.scan_time is None:
                    self.scan_stats.execution.scan_time = (datetime.now() - started_at).total_seconds()
                self._source_snapshot = {}
                self._dsl_rule_definitions = None

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
                file_size = get_file_size(
                    file_path,
                    logger=logger,
                    component="project_discovery",
                )
                if file_size is not None and file_size > MAX_FILE_SIZE_BYTES:
                    skipped.append(
                        (
                            rel_path,
                            f"文件过大 ({file_size / 1024 / 1024:.1f} MB > 2 MB)",
                        )
                    )
                    continue
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
            code = self._read_source_file(file_path)

            # 检测语言
            language = self.supported_extensions.get(file_path.suffix, "unknown")
            if self.use_cross_file and language in {"python", "javascript", "typescript"}:
                with self._scan_state_lock:
                    self._source_snapshot[file_path.resolve()] = code

            # 执行检测（支持多语言）
            file_path_str = str(file_path)
            extra = self._extra_rule_dirs or None
            root = self.project_path
            merged_findings = analyze_source(
                code,
                file_path_str,
                language=language,
                extra_rule_dirs=extra,
                rules_allowed_root=root,
                dsl_rule_definitions=self._dsl_rule_definitions,
            )

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
            with self._scan_state_lock:
                self._failed_scan_files.add(file_path.resolve())
                self.scan_stats.execution.note_scan_error(self._to_relative(str(file_path)), str(e))
            return []

    @staticmethod
    def _read_source_file(file_path: Path) -> str:
        """Read UTF-8 source efficiently while preserving universal-newline semantics."""
        with open(file_path, "rb") as source_file:
            code = source_file.read().decode("utf-8", errors="ignore")
        return code.replace("\r\n", "\n").replace("\r", "\n")

    def scan_project(self, verbose: bool = False) -> ScanResults:
        """
        扫描整个项目

        Args:
            verbose: 是否显示详细信息

        Returns:
            扫描结果字典，key 为文件路径，value 为问题列表
        """
        with self.scan_session():
            return self._scan_project_impl(verbose)

    def _scan_project_impl(self, verbose: bool = False) -> ScanResults:
        """Execute a project scan inside an active ``scan_session``."""
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
                should_cache_result=lambda file_path, _findings: not self._scan_file_failed(file_path),
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

        if self.use_cross_file:
            self._merge_cross_file_findings(code_files, verbose=verbose)

        # 计算扫描时间
        end_time = datetime.now()
        self.scan_stats.execution.scan_time = (end_time - start_time).total_seconds()

        if verbose:
            logger.info(
                "扫描完成！总文件: %d | 已扫描: %d | 有问题: %d | 总问题数: %d | 扫描错误: %d | 耗时: %.2fs",
                self.scan_stats.discovery.total_files,
                self.scan_stats.execution.scanned_files,
                self.scan_stats.execution.files_with_issues,
                self.scan_stats.execution.total_issues,
                len(self.scan_stats.execution.errors),
                self.scan_stats.execution.scan_time or 0.0,
            )

        return self.scan_results

    def _merge_cross_file_findings(self, code_files: list[Path], verbose: bool = False) -> None:
        """Build the per-scan source snapshot and merge cross-file findings."""
        for file_path in code_files:
            if file_path.suffix.lower() not in {
                ".py",
                ".pyw",
                ".js",
                ".jsx",
                ".mjs",
                ".cjs",
                ".ts",
                ".tsx",
            }:
                continue
            resolved = file_path.resolve()
            if resolved not in self._source_snapshot:
                try:
                    self._source_snapshot[resolved] = self._read_source_file(file_path)
                except (OSError, UnicodeDecodeError):
                    continue

        cross_file_findings = self._run_cross_file_analysis(verbose=verbose)
        for finding in cross_file_findings:
            target_file = finding.get("file")
            if not isinstance(target_file, str) or not target_file:
                continue
            existing_findings = self.scan_results.setdefault(target_file, [])
            duplicate = next(
                (
                    existing
                    for existing in existing_findings
                    if existing.get("rule_id") == finding.get("rule_id")
                    and existing.get("type") == finding.get("type")
                    and existing.get("line") == finding.get("line")
                ),
                None,
            )
            if duplicate is not None:
                duplicate_related = duplicate.setdefault("related_locations", [])
                for location in finding.get("related_locations") or []:
                    if location not in duplicate_related:
                        duplicate_related.append(location)
                duplicate["cross_file"] = True
                duplicate["taint_path"] = finding.get("taint_path")
                continue
            new_file_with_issue = not existing_findings
            self.scan_results[target_file].append(finding)
            self.scan_stats.execution.note_cross_file_finding(
                new_file_with_issue=new_file_with_issue,
            )
        if cross_file_findings and verbose:
            logger.info("跨文件分析发现 %d 个额外污点路径", len(cross_file_findings))

    def _run_cross_file_analysis(self, verbose: bool = False) -> list[dict]:
        """
        运行跨文件依赖图分析。

        构建模块导入/导出依赖图，并根据导出函数参数摘要产出 findings。

        Args:
            verbose: 是否打印详细日志

        Returns:
            跨文件 finding 列表。
        """
        try:
            from src.analysis.taint import CrossFileAnalyzer
        except ImportError:
            logger.debug("CrossFileAnalyzer 不可用，跳过跨文件分析")
            return []

        try:
            if verbose:
                logger.info("开始跨文件依赖图分析...")

            cross_analyzer = CrossFileAnalyzer(
                self.project_path,
                source_snapshot=self._source_snapshot,
            )
            cross_analyzer.scan_project()

            stats = cross_analyzer.get_stats()
            self._cross_file_stats = {
                "enabled": True,
                **stats,
            }
            logger.debug(
                "跨文件分析：%d 个文件，%d 个导出，%d 个导入，%d 条依赖边，%d 个发现",
                stats.get("files_analyzed", 0),
                stats.get("total_exports", 0),
                stats.get("total_imports", 0),
                stats.get("dependency_edges", 0),
                stats.get("cross_file_findings", 0),
            )

            return cast(list[dict[str, Any]], cross_analyzer.get_findings())

        except (OSError, UnicodeDecodeError, RuntimeError) as e:
            logger.warning("跨文件依赖图分析失败: %s", e)
            return []

    def _to_relative(self, file_path: str) -> str:
        """将绝对路径转为相对于项目根目录的路径字符串。"""
        try:
            return str(Path(file_path).relative_to(self.project_path))
        except ValueError:
            return file_path

    def _scan_file_failed(self, file_path: Path) -> bool:
        return file_path.resolve() in self._failed_scan_files

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

        stats = self.scan_stats.to_dict(severity_stats)
        if self._cross_file_stats:
            stats["cross_file_analysis"] = dict(self._cross_file_stats)
        return stats


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
