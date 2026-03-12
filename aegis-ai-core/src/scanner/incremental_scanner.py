# incremental_scanner.py - 增量扫描器
"""
增量扫描功能：只扫描修改的文件，提高扫描效率
支持 Git diff 集成，只扫描变更的文件
"""

import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# 添加项目根目录到 Python 路径
_current_dir = Path(__file__).parent
_project_root = _current_dir.parent.parent.parent  # aegis-ai-core
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from src.scanner.project_scanner import ProjectScanner


class IncrementalScanner:
    """
    增量扫描器

    只扫描修改的文件，提高扫描效率
    支持 Git diff 集成
    """

    def __init__(
        self,
        project_path: str,
        base_ref: str | None = None,
        extra_rule_dirs: list[Path] | None = None,
    ):
        """
        初始化增量扫描器

        Args:
            project_path: 项目根目录路径
            base_ref: Git 基准引用（如 'main', 'HEAD~1', 'abc123'），默认为 None（扫描未提交的更改）
            extra_rule_dirs: 额外 DSL 规则目录（与 ProjectScanner 一致）
        """
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise ValueError(f"项目路径不存在: {project_path}")

        self.base_ref = base_ref
        self.scanner = ProjectScanner(
            str(self.project_path),
            extra_rule_dirs=extra_rule_dirs,
        )

    def get_changed_files(self) -> set[Path]:
        """
        获取修改的文件列表

        Returns:
            修改的文件路径集合
        """
        changed_files = set()

        # 检查是否是 Git 仓库
        if not self._is_git_repo():
            print("⚠️  不是 Git 仓库，将扫描所有文件")
            return set()  # 返回空集合，让调用者决定如何处理

        try:
            if self.base_ref:
                # 与指定引用比较
                cmd = ["git", "diff", "--name-only", "--diff-filter=ACMR", self.base_ref, "HEAD"]
            else:
                # 扫描未提交的更改（工作区和暂存区）
                cmd = ["git", "diff", "--name-only", "--diff-filter=ACMR", "HEAD"]

            result = subprocess.run(cmd, cwd=self.project_path, capture_output=True, text=True, check=True)

            # 解析输出，获取修改的文件
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    file_path = self.project_path / line.strip()
                    if file_path.exists():
                        changed_files.add(file_path.resolve())

            # 如果 base_ref 为 None，也检查暂存区的文件
            if not self.base_ref:
                staged_result = subprocess.run(
                    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True,
                    check=True,
                )

                for line in staged_result.stdout.strip().split("\n"):
                    if line.strip():
                        file_path = self.project_path / line.strip()
                        if file_path.exists():
                            changed_files.add(file_path.resolve())

        except subprocess.CalledProcessError as e:
            print(f"⚠️  Git 命令执行失败: {e}")
            return set()
        except FileNotFoundError:
            print("⚠️  Git 未安装或不在 PATH 中")
            return set()

        return changed_files

    def get_changed_lines(self, file_path: Path) -> set[int]:
        """
        获取指定文件在 diff 中变更的行号（1-based）。
        用于仅报告变更行上的 findings。

        Returns:
            变更行号集合；非 Git 或出错时返回空集合。
        """
        if not self._is_git_repo():
            return set()
        try:
            if self.base_ref:
                cmd = ["git", "diff", "-U0", "--no-color", self.base_ref, "HEAD", "--", str(file_path)]
            else:
                cmd = ["git", "diff", "-U0", "--no-color", "HEAD", "--", str(file_path)]
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return set()
            lines: set[int] = set()
            for raw in result.stdout.splitlines():
                if raw.startswith("@@ "):
                    # @@ -old_start,old_count +new_start,new_count @@
                    m = re.search(r"\+(\d+)(?:,(\d+))?", raw)
                    if m:
                        start = int(m.group(1))
                        span = int(m.group(2)) if m.group(2) else 1
                        for i in range(start, start + span):
                            lines.add(i)
            return lines
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, ValueError):
            return set()

    def scan_incremental(self, verbose: bool = False) -> dict[str, list[dict]]:
        """
        执行增量扫描

        Args:
            verbose: 是否显示详细信息

        Returns:
            扫描结果字典
        """
        # 获取修改的文件
        changed_files = self.get_changed_files()

        if not changed_files:
            if verbose:
                print("ℹ️  没有检测到修改的文件")
            return {}

        if verbose:
            print(f"📝 检测到 {len(changed_files)} 个修改的文件")
            for f in sorted(changed_files):
                print(f"   - {f.relative_to(self.project_path)}")

        # 只扫描修改的文件
        results = {}
        total_files = len(changed_files)

        for idx, file_path in enumerate(changed_files, 1):
            if verbose:
                print(f"   扫描进度: {idx}/{total_files}")

            # 检查文件扩展名是否支持
            if file_path.suffix not in self.scanner.supported_extensions:
                continue

            try:
                findings = self.scanner.scan_file(file_path)
                changed_lines = self.get_changed_lines(file_path)
                if changed_lines:
                    findings = [f for f in findings if f.get("line") in changed_lines]
                if findings:
                    rel_path = str(file_path.relative_to(self.project_path)).replace("\\", "/")
                    results[rel_path] = findings

            except (OSError, UnicodeDecodeError, RuntimeError) as e:
                if verbose:
                    print(f"⚠️  扫描文件失败 {file_path}: {e}")

        return results

    def scan_with_stats(self, verbose: bool = False) -> tuple[dict[str, list[dict]], dict]:
        """
        执行增量扫描并返回统计信息

        Args:
            verbose: 是否显示详细信息

        Returns:
            (扫描结果字典, 统计信息字典)
        """
        start_time = datetime.now()

        # 获取修改的文件
        changed_files = self.get_changed_files()

        if not changed_files:
            stats = {
                "scan_type": "incremental",
                "base_ref": self.base_ref or "working directory",
                "changed_files": 0,
                "total_files": 0,
                "scanned_files": 0,
                "files_with_issues": 0,
                "total_issues": 0,
                "scan_time_seconds": 0.0,
            }
            return {}, stats

        # 执行扫描
        results = self.scan_incremental(verbose=verbose)

        # 计算统计信息
        total_issues = sum(len(findings) for findings in results.values())
        files_with_issues = len(results)

        scan_time = (datetime.now() - start_time).total_seconds()

        stats = {
            "scan_type": "incremental",
            "base_ref": self.base_ref or "working directory",
            "changed_files": len(changed_files),
            "scanned_files": len(changed_files),
            "files_with_issues": files_with_issues,
            "total_issues": total_issues,
            "scan_time_seconds": scan_time,
        }

        return results, stats

    def _is_git_repo(self) -> bool:
        """检查是否是 Git 仓库"""
        git_dir = self.project_path / ".git"
        return git_dir.exists() and git_dir.is_dir()


def scan_incremental(project_path: str, base_ref: str | None = None, verbose: bool = False) -> dict[str, list[dict]]:
    """
    便捷函数：执行增量扫描

    Args:
        project_path: 项目根目录路径
        base_ref: Git 基准引用（可选）
        verbose: 是否显示详细信息

    Returns:
        扫描结果字典
    """
    scanner = IncrementalScanner(project_path, base_ref=base_ref)
    return scanner.scan_incremental(verbose=verbose)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="增量扫描工具")
    parser.add_argument("project_path", help="项目根目录路径")
    parser.add_argument("--base-ref", help="Git 基准引用（如 main, HEAD~1）", default=None)
    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细信息")

    args = parser.parse_args()

    scanner = IncrementalScanner(args.project_path, base_ref=args.base_ref)
    results, stats = scanner.scan_with_stats(verbose=args.verbose)

    print("\n" + "=" * 70)
    print("📊 增量扫描统计:")
    print("=" * 70)
    print(f"扫描类型: {stats['scan_type']}")
    print(f"基准引用: {stats['base_ref']}")
    if "changed_files" in stats:
        print(f"修改文件数: {stats['changed_files']}")
    print(f"扫描文件数: {stats['scanned_files']}")
    print(f"有问题文件数: {stats['files_with_issues']}")
    print(f"总问题数: {stats['total_issues']}")
    print(f"扫描耗时: {stats['scan_time_seconds']:.2f} 秒")
    print("=" * 70)
