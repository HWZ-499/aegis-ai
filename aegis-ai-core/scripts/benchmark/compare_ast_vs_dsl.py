#!/usr/bin/env python3
"""
AST vs DSL 规则对比实验脚本。

在真实靶场（NodeGoat、DVWA 等）上分别运行 AST-only 与 AST+DSL 扫描，
对比检出数量与类型分布，输出报告。

用法（在 aegis-ai-core 目录）:
  python scripts/benchmark/compare_ast_vs_dsl.py --project-dir ../NodeGoat
  python scripts/benchmark/compare_ast_vs_dsl.py --project-dir C:\\DVWA --output reports
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# 确保 aegis-ai-core 在 path 中
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.rule_engine import (
    analyze_go,
    analyze_java,
    analyze_javascript,
    analyze_php,
    analyze_python,
)

SUPPORTED = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".go": "go",
}

EXCLUDED = {"node_modules", "vendor", ".git", "__pycache__", "dist", "build"}


def _should_skip(path: Path, project_root: Path) -> bool:
    """跳过测试、压缩、第三方等目录/文件。"""
    try:
        rel = path.relative_to(project_root)
    except ValueError:
        return False
    parts = rel.parts
    for exc in EXCLUDED:
        if exc in parts:
            return True
    if path.suffix in (".min.js", ".min.css", ".map"):
        return True
    for p in parts:
        if p.lower() in ("test", "tests", "__tests__", "spec", "coverage"):
            return True
    return False


def _scan_project(project_dir: Path, include_dsl: bool) -> dict[str, list[dict]]:
    """扫描项目，返回 {rel_path: findings}。"""
    results: dict[str, list[dict]] = {}
    files = [
        p
        for p in project_dir.rglob("*")
        if p.is_file() and p.suffix in SUPPORTED and not _should_skip(p, project_dir)
    ]
    for fp in files:
        try:
            code = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lang = SUPPORTED[fp.suffix]
        try:
            if lang == "python":
                findings = analyze_python(code, fp, include_dsl=include_dsl)
            elif lang in ("javascript", "typescript"):
                findings = analyze_javascript(code, fp, language=lang, include_dsl=include_dsl)
            elif lang == "php":
                findings = analyze_php(code, fp)
            elif lang == "java":
                findings = analyze_java(code, fp, include_dsl=include_dsl)
            elif lang == "go":
                findings = analyze_go(code, fp, include_dsl=include_dsl)
            else:
                continue
        except Exception:
            continue
        rel = str(fp.relative_to(project_dir))
        for f in findings:
            f["file"] = rel
        results[rel] = findings
    return results


def _aggregate_by_type(results: dict[str, list[dict]]) -> dict[str, int]:
    """按漏洞类型聚合数量。"""
    by_type: dict[str, int] = defaultdict(int)
    for findings in results.values():
        for f in findings:
            t = f.get("type", "UNKNOWN")
            by_type[t] += 1
    return dict(by_type)


def _compare(
    ast_results: dict[str, list[dict]],
    dsl_results: dict[str, list[dict]],
) -> tuple[dict, dict, dict]:
    """
    对比 AST-only 与 AST+DSL 结果。

    Returns:
        (ast_only, dsl_only, both) 每类为 {type: count}
    """
    def key(f: dict) -> tuple:
        return (f.get("file", ""), f.get("line", 0), f.get("type", ""))

    ast_set = set()
    for path, findings in ast_results.items():
        for f in findings:
            ast_set.add((path, f.get("line", 0), f.get("type", "")))

    dsl_set = set()
    for path, findings in dsl_results.items():
        for f in findings:
            dsl_set.add((path, f.get("line", 0), f.get("type", "")))

    both_set = ast_set & dsl_set
    ast_only_set = ast_set - dsl_set
    dsl_only_set = dsl_set - ast_set

    def count_by_type(s: set) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for _, _, t in s:
            out[t] += 1
        return dict(out)

    return (
        count_by_type(ast_only_set),
        count_by_type(dsl_only_set),
        count_by_type(both_set),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="AST vs DSL 规则对比实验")
    parser.add_argument("--project-dir", type=Path, required=True, help="靶场项目路径（如 NodeGoat、DVWA）")
    parser.add_argument("--output", type=Path, default=None, help="报告输出目录，默认 stdout")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式")
    parser.add_argument(
        "--clone-nodegoat",
        action="store_true",
        help="若 project-dir 不存在则克隆 NodeGoat 到该路径",
    )
    args = parser.parse_args()

    project_dir = args.project_dir.resolve()
    if not project_dir.exists() or not project_dir.is_dir():
        if args.clone_nodegoat and "nodegoat" in str(project_dir).lower():
            import subprocess
            project_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", "https://github.com/OWASP/NodeGoat.git", str(project_dir)],
                check=True,
            )
            print(f"已克隆 NodeGoat 到 {project_dir}", file=sys.stderr)
        else:
            print(f"错误: 项目路径不存在: {project_dir}", file=sys.stderr)
            return 1

    print("扫描 AST-only (include_dsl=False)...", file=sys.stderr)
    ast_results = _scan_project(project_dir, include_dsl=False)
    print("扫描 AST+DSL (include_dsl=True)...", file=sys.stderr)
    dsl_results = _scan_project(project_dir, include_dsl=True)

    ast_by_type = _aggregate_by_type(ast_results)
    dsl_by_type = _aggregate_by_type(dsl_results)
    ast_only, dsl_only, both = _compare(ast_results, dsl_results)

    total_ast = sum(ast_by_type.values())
    total_dsl = sum(dsl_by_type.values())

    report = {
        "timestamp": datetime.now().isoformat(),
        "project": str(project_dir),
        "files_scanned": len(ast_results),
        "ast_only_total": total_ast,
        "ast_plus_dsl_total": total_dsl,
        "by_type": {
            "ast_only": ast_by_type,
            "ast_plus_dsl": dsl_by_type,
        },
        "comparison": {
            "ast_only_findings": ast_only,
            "dsl_only_findings": dsl_only,
            "both": both,
        },
    }

    report_md = _format_md(report)

    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d")
        name = project_dir.name
        md_path = args.output / f"ast_vs_dsl_{name}_{date_str}.md"
        json_path = args.output / f"ast_vs_dsl_{name}_{date_str}.json"
        md_path.write_text(report_md, encoding="utf-8")
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"报告已生成: {md_path}", file=sys.stderr)
        print(f"JSON: {json_path}", file=sys.stderr)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(report_md)

    return 0


def _format_md(report: dict) -> str:
    """生成 Markdown 报告。"""
    lines = [
        "# AST vs DSL 规则对比实验报告",
        "",
        f"**项目**: {report['project']}",
        f"**扫描时间**: {report['timestamp']}",
        f"**扫描文件数**: {report['files_scanned']}",
        "",
        "## 汇总",
        "",
        f"| 模式 | 发现总数 |",
        f"|------|----------|",
        f"| AST-only | {report['ast_only_total']} |",
        f"| AST+DSL | {report['ast_plus_dsl_total']} |",
        "",
        "## 按漏洞类型",
        "",
        "| 类型 | AST-only | AST+DSL |",
        "|------|----------|---------|",
    ]
    all_types = set(report["by_type"]["ast_only"]) | set(report["by_type"]["ast_plus_dsl"])
    for t in sorted(all_types):
        a = report["by_type"]["ast_only"].get(t, 0)
        d = report["by_type"]["ast_plus_dsl"].get(t, 0)
        lines.append(f"| {t} | {a} | {d} |")

    lines.extend([
        "",
        "## 对比（AST-only vs AST+DSL）",
        "",
        "- **两者均有**: 行+类型在两种模式下均被检出",
        "- **仅 AST**: 仅 AST-only 检出",
        "- **仅 DSL 增量**: 仅 AST+DSL 多出的部分（DSL 规则补充）",
        "",
        "| 类型 | 两者均有 | 仅 AST | 仅 DSL 增量 |",
        "|------|----------|--------|-------------|",
    ])
    for t in sorted(all_types):
        b = report["comparison"]["both"].get(t, 0)
        ao = report["comparison"]["ast_only_findings"].get(t, 0)
        do = report["comparison"]["dsl_only_findings"].get(t, 0)
        lines.append(f"| {t} | {b} | {ao} | {do} |")

    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
