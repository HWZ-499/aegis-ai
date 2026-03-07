# performance_optimizer.py - 性能优化器
"""
性能优化功能：并行处理、缓存机制
"""

import hashlib
import json
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path


class ScanCache:
    """
    扫描结果缓存管理器

    缓存已扫描文件的结果，避免重复扫描
    """

    def __init__(self, cache_dir: str | None = None, ttl_hours: int = 24):
        """
        初始化缓存管理器

        Args:
            cache_dir: 缓存目录路径，默认为 .aegis-cache
            ttl_hours: 缓存有效期（小时），默认 24 小时
        """
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.cwd() / ".aegis-cache"

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = ttl_hours

    def _get_file_hash(self, file_path: Path) -> str:
        """
        计算文件内容的哈希值

        Args:
            file_path: 文件路径

        Returns:
            文件哈希值
        """
        with open(file_path, "rb") as f:
            content = f.read()
            return hashlib.md5(content).hexdigest()

    def _get_rules_version_hash(self) -> str:
        """
        计算规则版本哈希（security_rules.py + analysis/rules 下所有 .py），
        规则变更后缓存自动失效。
        """
        analysis_dir = Path(__file__).resolve().parent.parent / "analysis"
        hashes = []
        if (analysis_dir / "security_rules.py").exists():
            hashes.append(self._get_file_hash(analysis_dir / "security_rules.py"))
        rules_dir = analysis_dir / "rules"
        if rules_dir.exists():
            for py in sorted(rules_dir.rglob("*.py")):
                hashes.append(self._get_file_hash(py))
        if not hashes:
            return ""
        combined = hashlib.md5("".join(hashes).encode()).hexdigest()
        return combined[:12]

    def _get_cache_key(self, file_path: Path) -> str:
        """
        生成缓存键

        Args:
            file_path: 文件路径

        Returns:
            缓存键（包含文件哈希和规则版本）
        """
        file_hash = self._get_file_hash(file_path)
        rules_hash = self._get_rules_version_hash()
        return f"{file_path.name}_{file_hash}_{rules_hash}"

    def get_cached_result(self, file_path: Path) -> list[dict] | None:
        """
        获取缓存的扫描结果

        Args:
            file_path: 文件路径

        Returns:
            缓存的扫描结果，如果不存在或已过期则返回 None
        """
        cache_key = self._get_cache_key(file_path)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            # 检查缓存是否过期
            cache_mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if datetime.now() - cache_mtime > timedelta(hours=self.ttl_hours):
                cache_file.unlink()  # 删除过期缓存
                return None

            # 读取缓存
            with open(cache_file, encoding="utf-8") as f:
                cache_data = json.load(f)

                # 验证文件路径是否匹配
                if cache_data.get("file_path") == str(file_path):
                    return cache_data.get("findings", [])

        except Exception as e:
            print(f"⚠️  读取缓存失败 {cache_file}: {e}")
            return None

        return None

    def save_result(self, file_path: Path, findings: list[dict]):
        """
        保存扫描结果到缓存

        Args:
            file_path: 文件路径
            findings: 扫描结果
        """
        cache_key = self._get_cache_key(file_path)
        cache_file = self.cache_dir / f"{cache_key}.json"

        try:
            cache_data = {"file_path": str(file_path), "findings": findings, "cached_at": datetime.now().isoformat()}

            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"⚠️  保存缓存失败 {cache_file}: {e}")

    def clear_cache(self, older_than_hours: int | None = None):
        """
        清理缓存

        Args:
            older_than_hours: 清理指定小时数之前的缓存，如果为 None 则清理所有缓存
        """
        if not self.cache_dir.exists():
            return

        cleared_count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                if older_than_hours:
                    cache_mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
                    if datetime.now() - cache_mtime > timedelta(hours=older_than_hours):
                        cache_file.unlink()
                        cleared_count += 1
                else:
                    cache_file.unlink()
                    cleared_count += 1
            except Exception as e:
                print(f"⚠️  删除缓存文件失败 {cache_file}: {e}")

        print(f"✅ 已清理 {cleared_count} 个缓存文件")


class ParallelScanner:
    """
    并行扫描器

    使用多进程/多线程并行扫描文件，提升扫描速度
    """

    def __init__(self, max_workers: int | None = None, use_processes: bool = False):
        """
        初始化并行扫描器

        Args:
            max_workers: 最大工作线程/进程数，默认为 CPU 核心数
            use_processes: 是否使用多进程（True）或多线程（False），默认多线程
        """
        if max_workers is None:
            max_workers = os.cpu_count() or 4

        self.max_workers = max_workers
        self.use_processes = use_processes
        self.executor_class = ProcessPoolExecutor if use_processes else ThreadPoolExecutor

    def scan_file_worker(self, args_tuple: tuple) -> tuple[Path, list[dict]]:
        """
        扫描单个文件的工作函数（用于并行执行）

        Args:
            args_tuple: (file_path, project_path, supported_extensions) 元组

        Returns:
            (文件路径, 扫描结果)
        """
        file_path, project_path, supported_extensions = args_tuple

        # 导入扫描逻辑
        from src.analysis.ast_analyzer import analyze_code_ast
        from src.analysis.multi_language_ast import analyze_code_multi_language
        from src.analysis.rule_based_audit import merge_findings
        from src.analysis.security_rules import scan_code_locally

        try:
            # 读取文件内容
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                code = f.read()

            # 检测语言
            language = supported_extensions.get(file_path.suffix, "unknown")

            # 执行检测
            file_path_str = str(file_path)
            if language == "python":
                ast_findings = analyze_code_ast(code)
                regex_findings = scan_code_locally(code, file_path=file_path_str)
                merged_findings = merge_findings(ast_findings, regex_findings)
            else:
                multi_lang_findings = analyze_code_multi_language(code, file_path_str)
                regex_findings = scan_code_locally(code, file_path=file_path_str)
                merged_findings = merge_findings(multi_lang_findings, regex_findings)

            # 添加文件信息
            project_path_obj = Path(project_path)
            for finding in merged_findings:
                finding["file"] = str(file_path.relative_to(project_path_obj))
                finding["file_path"] = str(file_path)
                finding["language"] = language

            return (file_path, merged_findings)

        except Exception as e:
            print(f"⚠️  扫描文件失败 {file_path}: {e}")
            return (file_path, [])

    def scan_files_parallel(
        self,
        file_paths: list[Path],
        project_path: Path,
        supported_extensions: dict[str, str],
        progress_callback: callable | None = None,
    ) -> dict[Path, list[dict]]:
        """
        并行扫描多个文件

        Args:
            file_paths: 文件路径列表
            project_path: 项目根目录路径
            supported_extensions: 支持的文件扩展名字典
            progress_callback: 进度回调函数（可选）

        Returns:
            扫描结果字典
        """
        results = {}
        total_files = len(file_paths)

        # 准备参数元组
        args_list = [(file_path, str(project_path), supported_extensions) for file_path in file_paths]

        with self.executor_class(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_file = {
                executor.submit(self.scan_file_worker, args): file_path
                for args, file_path in zip(args_list, file_paths)
            }

            # 收集结果
            completed = 0
            for future in as_completed(future_to_file):
                completed += 1
                file_path = future_to_file[future]

                try:
                    scanned_path, findings = future.result()
                    results[scanned_path] = findings

                    if progress_callback:
                        progress_callback(completed, total_files, file_path)

                except Exception as e:
                    print(f"⚠️  处理文件失败 {file_path}: {e}")
                    results[file_path] = []

        return results


class PerformanceOptimizer:
    """
    性能优化器

    结合缓存和并行处理，提升扫描性能
    """

    def __init__(
        self,
        cache_dir: str | None = None,
        max_workers: int | None = None,
        use_cache: bool = True,
        use_parallel: bool = True,
    ):
        """
        初始化性能优化器

        Args:
            cache_dir: 缓存目录路径
            max_workers: 最大工作线程/进程数
            use_cache: 是否使用缓存
            use_parallel: 是否使用并行处理
        """
        self.use_cache = use_cache
        self.use_parallel = use_parallel

        if use_cache:
            self.cache = ScanCache(cache_dir)
        else:
            self.cache = None

        if use_parallel:
            self.parallel_scanner = ParallelScanner(max_workers=max_workers)
        else:
            self.parallel_scanner = None

    def scan_files_optimized(
        self,
        file_paths: list[Path],
        scan_func: callable,
        project_path: Path,
        supported_extensions: dict[str, str],
        progress_callback: callable | None = None,
        engine: str = "legacy",
    ) -> dict[Path, list[dict]]:
        """
        优化的文件扫描（使用缓存和并行处理）

        Args:
            file_paths: 文件路径列表
            scan_func: 扫描函数（接受 file_path 参数，返回 findings）
            project_path: 项目根目录路径
            supported_extensions: 支持的文件扩展名字典
            progress_callback: 进度回调函数（可选）

        Returns:
            扫描结果字典
        """
        results = {}
        files_to_scan = []
        cached_results = {}

        # 1. 检查缓存
        if self.use_cache and self.cache:
            for file_path in file_paths:
                cached = self.cache.get_cached_result(file_path)
                if cached is not None:
                    cached_results[file_path] = cached
                else:
                    files_to_scan.append(file_path)
        else:
            files_to_scan = file_paths

        # 2. 并行扫描未缓存的文件
        if files_to_scan:
            if self.use_parallel and self.parallel_scanner:
                # 【修复】使用传入的 scan_func（支持新引擎），而不是内部的 scan_file_worker
                # 使用顺序扫描，但调用 scan_func（这样可以使用新引擎）
                scanned_results = {}
                total_files = len(files_to_scan)
                for idx, file_path in enumerate(files_to_scan, 1):
                    findings = scan_func(file_path)
                    scanned_results[file_path] = findings

                    if progress_callback:
                        progress_callback(idx, total_files, file_path)

                # 保存到缓存
                if self.use_cache and self.cache:
                    for file_path, findings in scanned_results.items():
                        self.cache.save_result(file_path, findings)
            else:
                # 顺序扫描
                scanned_results = {}
                total_files = len(files_to_scan)
                for idx, file_path in enumerate(files_to_scan, 1):
                    findings = scan_func(file_path)
                    scanned_results[file_path] = findings

                    # 保存到缓存
                    if self.use_cache and self.cache:
                        self.cache.save_result(file_path, findings)

                    if progress_callback:
                        progress_callback(idx, total_files, file_path)

            # 合并结果
            results.update(scanned_results)

        # 3. 添加缓存结果
        results.update(cached_results)

        return results

    def clear_cache(self, older_than_hours: int | None = None):
        """
        清理缓存

        Args:
            older_than_hours: 清理指定小时数之前的缓存
        """
        if self.cache:
            self.cache.clear_cache(older_than_hours)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="性能优化工具")
    parser.add_argument("--clear-cache", action="store_true", help="清理缓存")
    parser.add_argument("--cache-dir", help="缓存目录路径")
    parser.add_argument("--older-than", type=int, help="清理指定小时数之前的缓存")

    args = parser.parse_args()

    if args.clear_cache:
        cache = ScanCache(cache_dir=args.cache_dir)
        cache.clear_cache(older_than_hours=args.older_than)
    else:
        print("使用 --clear-cache 清理缓存")
