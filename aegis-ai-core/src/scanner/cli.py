# cli.py - 命令行工具
"""
Aegis 安全扫描命令行工具
"""

import argparse
import sys
from pathlib import Path

from src.scanner.ai_analyzer import AIAnalyzer
from src.scanner.baseline import Baseline
from src.scanner.incremental_scanner import IncrementalScanner
from src.scanner.project_scanner import ProjectScanner
from src.scanner.rag_enhancer import RAGEnhancer
from src.scanner.report_generator import ReportGenerator
from src.scanner.taint_enhancer import TAINT_ANALYSIS_AVAILABLE, TaintEnhancer, enhance_scan_results

# 跨文件分析
try:
    from src.analysis.taint import CrossFileAnalyzer

    CROSS_FILE_AVAILABLE = True
except ImportError:
    CROSS_FILE_AVAILABLE = False
    CrossFileAnalyzer = None


def main():
    """命令行主函数"""
    parser = argparse.ArgumentParser(
        description="Aegis SAST 安全扫描工具 — JavaScript/TypeScript、Python 深度 AST 检测；Java/C/Go 基础正则检测",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 扫描当前目录，输出 JSON 格式
  python -m src.scanner.cli . --format json
  
  # 扫描指定目录，输出 HTML 报告
  python -m src.scanner.cli /path/to/project --format html --output report.html
  
  # 扫描并输出 SARIF 格式（用于 GitHub）
  python -m src.scanner.cli . --format sarif --output results.sarif
        """,
    )

    parser.add_argument("project_path", type=str, help="要扫描的项目路径")

    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "html", "markdown", "sarif"],
        default="html",  # 【修复】默认使用HTML格式，更友好
        help="报告格式（默认: html）",
    )

    parser.add_argument("--output", "-o", type=str, help="输出文件路径（如果不指定，输出到标准输出）")

    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细信息")

    parser.add_argument("--ignore", nargs="+", help="要忽略的目录/文件模式（例如: --ignore node_modules .git）")

    parser.add_argument(
        "--incremental", "-i", action="store_true", help="增量扫描模式：只扫描修改的文件（需要 Git 仓库）"
    )

    parser.add_argument("--base-ref", type=str, help="增量扫描的 Git 基准引用（如 main, HEAD~1），默认扫描工作区更改")

    parser.add_argument("--no-cache", action="store_true", help="禁用缓存（不使用缓存）")

    parser.add_argument("--no-parallel", action="store_true", help="禁用并行处理（顺序扫描）")

    parser.add_argument(
        "--engine",
        choices=["legacy", "new"],
        default="new",
        help="选择扫描引擎：new=新规则引擎（默认），legacy=旧版（将弃用）",
    )

    parser.add_argument("--max-workers", type=int, help="最大工作线程/进程数（默认 CPU 核心数）")

    parser.add_argument("--rag", action="store_true", help="启用 RAG 增强：为扫描结果添加修复建议和 CVE 关联")

    parser.add_argument("--rag-db", type=str, help="RAG 知识库路径（ChromaDB 数据库目录）")

    parser.add_argument("--ai", action="store_true", help="启用 AI 分析：对高风险发现进行 AI 验证（需要 API 密钥）")

    parser.add_argument(
        "--taint", action="store_true", help="启用污点分析：追踪 Source → Sink 数据流路径（P3 高级功能）"
    )

    parser.add_argument(
        "--cross-file", action="store_true", help="启用跨文件分析：追踪模块间依赖和数据流（P4 高级功能）"
    )

    parser.add_argument(
        "--no-fail-on-findings",
        action="store_true",
        help="发现漏洞时仍返回退出码 0（用于 CI 报告生成，不阻断流水线）",
    )

    parser.add_argument(
        "--baseline",
        type=str,
        metavar="PATH",
        help="Baseline 文件路径：仅输出相对该 baseline 的新增 findings",
    )

    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="扫描后将当前结果写入 baseline 文件（路径由 --baseline 指定，默认 .aegis-baseline.json）",
    )

    parser.add_argument(
        "--rules-dir",
        type=str,
        action="append",
        metavar="PATH",
        help="额外 DSL 规则目录（可多次指定）；项目内 .aegis/rules 存在时会自动加载",
    )

    args = parser.parse_args()

    # 验证项目路径
    project_path = Path(args.project_path).resolve()
    if not project_path.exists():
        print(f"❌ 错误: 项目路径不存在: {project_path}")
        sys.exit(1)

    if not project_path.is_dir():
        print(f"❌ 错误: 项目路径不是目录: {project_path}")
        sys.exit(1)

    try:
        # 选择扫描模式
        if args.incremental:
            # 增量扫描模式
            if args.verbose:
                print(f"🚀 开始增量扫描项目: {project_path}")
                if args.base_ref:
                    print(f"📌 基准引用: {args.base_ref}")
                else:
                    print("📌 扫描工作区更改")
                print("=" * 70)

            extra_rule_dirs_list: list[Path] = []
            if getattr(args, "rules_dir", None):
                extra_rule_dirs_list.extend(Path(p) for p in args.rules_dir)
            aegis_rules = project_path / ".aegis" / "rules"
            if aegis_rules.is_dir():
                extra_rule_dirs_list.append(aegis_rules)
            incremental_scanner = IncrementalScanner(
                str(project_path),
                base_ref=args.base_ref,
                extra_rule_dirs=extra_rule_dirs_list or None,
            )
            results, stats = incremental_scanner.scan_with_stats(verbose=args.verbose)
        else:
            extra_rule_dirs: list[Path] = []
            if getattr(args, "rules_dir", None):
                extra_rule_dirs.extend(Path(p) for p in args.rules_dir)
            aegis_rules = project_path / ".aegis" / "rules"
            if aegis_rules.is_dir():
                extra_rule_dirs.append(aegis_rules)
            scanner = ProjectScanner(
                str(project_path),
                ignore_patterns=args.ignore,
                use_cache=not args.no_cache,
                use_parallel=not args.no_parallel,
                max_workers=args.max_workers,
                engine=args.engine,
                extra_rule_dirs=extra_rule_dirs or None,
            )

            if args.verbose:
                print(f"🚀 开始扫描项目: {project_path}")
                print("=" * 70)

            results = scanner.scan_project(verbose=args.verbose)
            stats = scanner.get_stats()

        # 污点分析增强
        use_taint = args.taint
        if use_taint:
            if not TAINT_ANALYSIS_AVAILABLE:
                if args.verbose:
                    print("\n⚠️ 污点分析不可用（缺少依赖）")
            else:
                if args.verbose:
                    print("\n🔍 启用污点分析（Source → Sink 路径追踪）...")

                # 增强扫描结果
                results = enhance_scan_results(results, str(project_path))

                # 执行独立污点分析
                taint_findings_count = 0
                for file_path, findings in list(results.items()):
                    full_path = project_path / file_path
                    if full_path.exists():
                        ext = full_path.suffix.lower()
                        if ext in (".js", ".jsx", ".mjs", ".ts", ".tsx"):
                            lang = "javascript"
                        elif ext == ".py":
                            lang = "python"
                        else:
                            continue

                        enhancer = TaintEnhancer(language=lang)
                        taint_results = enhancer.analyze_file(full_path)

                        if taint_results:
                            # 合并污点分析发现
                            for tf in taint_results:
                                tf["file"] = file_path
                                # 检查是否已存在相同发现
                                is_duplicate = False
                                for existing in findings:
                                    if existing.get("line") == tf.get("line") and existing.get("type") == tf.get(
                                        "type"
                                    ):
                                        is_duplicate = True
                                        # 更新现有发现的污点信息
                                        existing["taint_path"] = tf.get("taint_path", "")
                                        break
                                if not is_duplicate:
                                    findings.append(tf)
                                    taint_findings_count += 1

                if args.verbose:
                    print(f"✅ 污点分析完成: 发现 {taint_findings_count} 个新漏洞路径")

                stats["taint_analysis"] = {
                    "enabled": True,
                    "new_findings": taint_findings_count,
                }

        # 跨文件分析
        use_cross_file = args.cross_file
        if use_cross_file:
            if not CROSS_FILE_AVAILABLE:
                if args.verbose:
                    print("\n⚠️ 跨文件分析不可用（缺少依赖）")
            else:
                if args.verbose:
                    print("\n🔗 启用跨文件分析（模块依赖追踪）...")

                cross_analyzer = CrossFileAnalyzer(project_path)
                cross_analyzer.scan_project()

                cross_stats = cross_analyzer.get_stats()

                if args.verbose:
                    print("✅ 跨文件分析完成:")
                    print(f"   分析文件数: {cross_stats['files_analyzed']}")
                    print(f"   模块导出数: {cross_stats['total_exports']}")
                    print(f"   模块导入数: {cross_stats['total_imports']}")
                    print(f"   依赖边数: {cross_stats['dependency_edges']}")

                # 获取依赖图用于报告
                stats["cross_file_analysis"] = {
                    "enabled": True,
                    **cross_stats,
                }

        # RAG 增强
        use_rag = args.rag
        if use_rag:
            if args.verbose:
                print("\n🤖 启用 RAG 增强...")

            rag_enhancer = RAGEnhancer(db_path=args.rag_db, use_rag=True)

            # 增强所有发现
            for file_path, findings in results.items():
                results[file_path] = rag_enhancer.enhance_findings(findings)

            if args.verbose:
                print("✅ RAG 增强完成")

        # AI 分析
        use_ai = args.ai
        if use_ai:
            if args.verbose:
                print("\n🧠 启用 AI 分析...")

            ai_analyzer = AIAnalyzer(enabled=True)

            if ai_analyzer.enabled:
                # 收集所有发现
                all_findings = []
                for findings in results.values():
                    all_findings.extend(findings)

                # 为每个文件构建代码上下文（用于 AI 分析）
                code_contexts: dict[str, str] = {}
                for rel_path, findings in results.items():
                    # 优先使用 finding 中的绝对路径，其次用相对路径拼接
                    file_path = None
                    for f in findings:
                        fp = f.get("file_path")
                        if fp:
                            file_path = Path(fp)
                            break
                    if file_path is None:
                        file_path = project_path / rel_path
                    try:
                        code = file_path.read_text(encoding="utf-8", errors="ignore")
                        # 使用相对路径作为 key，与 finding['file'] 对齐
                        code_contexts[rel_path] = code
                    except (OSError, UnicodeDecodeError):
                        continue

                # 批量分析（携带代码上下文）
                ai_results = ai_analyzer.analyze_findings_batch(
                    all_findings,
                    code_contexts=code_contexts,
                )

                # 更新发现信息
                ai_summary = ai_analyzer.get_analysis_summary(ai_results)
                stats["ai_analysis"] = ai_summary

                if args.verbose:
                    print(f"✅ AI 分析完成: {ai_summary['true_positives']}/{ai_summary['total_analyzed']} 真阳性")
            else:
                if args.verbose:
                    print("⚠️ AI 分析未启用（缺少 API 密钥）")

        # Baseline：先更新再过滤（仅输出新增）
        baseline_path: Path | None = None
        if args.baseline:
            baseline_path = (
                (project_path / args.baseline) if not Path(args.baseline).is_absolute() else Path(args.baseline)
            )
        elif getattr(args, "update_baseline", False):
            baseline_path = project_path / ".aegis-baseline.json"

        if getattr(args, "update_baseline", False) and baseline_path:
            base = Baseline.load(baseline_path) if baseline_path.exists() else Baseline()
            base.add_findings(results, project_path)
            base.save(baseline_path, project_path)
            if args.verbose:
                print(f"✅ Baseline 已更新: {baseline_path}")

        if args.baseline and baseline_path and baseline_path.exists():
            baseline = Baseline.load(baseline_path)
            results = baseline.diff(results, project_path)
            stats["total_issues"] = sum(len(v) for v in results.values())
            stats["files_with_issues"] = len(results)
            if args.verbose:
                print(f"\n📋 Baseline 过滤后新增 findings: {stats['total_issues']}")

        # 生成报告
        project_name = project_path.name
        generator = ReportGenerator(project_name)

        if args.format == "json":
            report = generator.generate_json(results, stats)
        elif args.format == "html":
            # 如果启用了 RAG，使用增强版 HTML
            if use_rag:
                report = generator.generate_html_enhanced(results, stats)
            else:
                report = generator.generate_html(results, stats)
        elif args.format == "markdown":
            report = generator.generate_markdown(results, stats)
        elif args.format == "sarif":
            report = generator.generate_sarif(results, stats)
        else:
            print(f"❌ 错误: 不支持的格式: {args.format}")
            sys.exit(1)

        # 输出报告
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")
            print(f"\n✅ 报告已保存到: {output_path}")
        else:
            print("\n" + "=" * 70)
            print("📄 扫描报告:")
            print("=" * 70)
            print(report)

        # 显示统计信息
        if args.verbose:
            print("\n" + "=" * 70)
            print("📊 扫描统计:")
            print("=" * 70)
            if args.incremental:
                print("扫描类型: 增量扫描")
                if "changed_files" in stats:
                    print(f"修改文件数: {stats['changed_files']}")
                if "base_ref" in stats:
                    print(f"基准引用: {stats['base_ref']}")
            else:
                print(f"总文件数: {stats['total_files']}")
            print(f"扫描文件数: {stats['scanned_files']}")
            print(f"有问题文件数: {stats['files_with_issues']}")
            print(f"总问题数: {stats['total_issues']}")
            scan_time = stats.get("scan_time_seconds", stats.get("scan_time", 0))
            print(f"扫描耗时: {scan_time:.2f} 秒")

            severity_stats = stats.get("severity_stats", {})
            if severity_stats:
                print("\n严重程度统计:")
                for severity in ["Critical", "High", "Medium", "Low"]:
                    count = severity_stats.get(severity, 0)
                    if count > 0:
                        emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
                        print(f"  {emoji} {severity}: {count}")

        # 根据问题数量设置退出码（--no-fail-on-findings 时始终返回 0）
        if getattr(args, "no_fail_on_findings", False):
            sys.exit(0)
        if stats["total_issues"] > 0:
            sys.exit(1)  # 有问题，返回非零退出码
        sys.exit(0)  # 无问题，返回零退出码

    except KeyboardInterrupt:
        print("\n\n⚠️ 扫描被用户中断")
        sys.exit(130)
    except Exception as e:  # Intentional: top-level catch-all
        print(f"\n❌ 错误: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
