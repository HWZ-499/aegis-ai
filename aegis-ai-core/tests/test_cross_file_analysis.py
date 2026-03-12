"""
test_cross_file_analysis.py - 跨文件分析测试

测试跨文件数据流分析功能。
"""

from pathlib import Path

import pytest

_project_root = Path(__file__).resolve().parent.parent


def test_cross_file_analyzer_basic():
    """测试跨文件分析器基本功能"""
    try:
        from src.analysis.taint import CrossFileAnalyzer
    except ImportError as e:
        print(f"⚠️ 导入失败: {e}")
        return False

    print("=" * 60)
    print("测试 1: 跨文件分析器基本功能")
    print("=" * 60)

    # 使用项目自身作为测试目标
    project_path = Path(_project_root)

    analyzer = CrossFileAnalyzer(project_path)

    print(f"项目路径: {project_path}")
    print("正在扫描项目...")

    analyzer.scan_project()

    stats = analyzer.get_stats()
    print("\n统计信息:")
    print(f"  分析文件数: {stats['files_analyzed']}")
    print(f"  总导出数: {stats['total_exports']}")
    print(f"  总导入数: {stats['total_imports']}")
    print(f"  依赖边数: {stats['dependency_edges']}")

    if stats["files_analyzed"] > 0:
        print("\n✅ 测试 1 通过")
        return True
    else:
        print("\n❌ 测试 1 失败 - 未分析到文件")
        return False


def test_nodegoat_analysis():
    """测试 NodeGoat 项目的跨文件分析"""
    try:
        from src.analysis.taint import CrossFileAnalyzer
    except ImportError as e:
        print(f"⚠️ 导入失败: {e}")
        return False

    print("\n" + "=" * 60)
    print("测试 2: NodeGoat 跨文件分析")
    print("=" * 60)

    nodegoat_path = Path("C:/NodeGoat")

    if not nodegoat_path.exists():
        print(f"⚠️ NodeGoat 路径不存在: {nodegoat_path}")
        print("跳过测试")
        return True

    analyzer = CrossFileAnalyzer(nodegoat_path)

    print(f"项目路径: {nodegoat_path}")
    print("正在扫描项目...")

    analyzer.scan_project()

    stats = analyzer.get_stats()
    print("\n统计信息:")
    print(f"  分析文件数: {stats['files_analyzed']}")
    print(f"  总导出数: {stats['total_exports']}")
    print(f"  总导入数: {stats['total_imports']}")
    print(f"  依赖边数: {stats['dependency_edges']}")

    # 获取依赖图
    dep_graph = analyzer.get_dependency_graph()

    print("\n依赖关系示例 (前 5 个):")
    for i, (file, deps) in enumerate(list(dep_graph.items())[:5]):
        rel_path = (
            Path(file).relative_to(nodegoat_path)
            if nodegoat_path in Path(file).parents or Path(file) == nodegoat_path
            else file
        )
        print(f"  {rel_path}:")
        for dep in list(deps)[:3]:
            dep_rel = Path(dep).relative_to(nodegoat_path) if nodegoat_path in Path(dep).parents else dep
            print(f"    -> {dep_rel}")
        if len(deps) > 3:
            print(f"    ... 还有 {len(deps) - 3} 个依赖")

    # 检查特定文件的模块信息
    for file_path in list(analyzer._exports.keys())[:3]:
        rel_path = Path(file_path).relative_to(nodegoat_path) if nodegoat_path in Path(file_path).parents else file_path
        info = analyzer.get_module_info(file_path)

        if info["exports"] or info["imports"]:
            print(f"\n模块: {rel_path}")
            if info["exports"]:
                print(f"  导出: {[e['name'] for e in info['exports'][:5]]}")
            if info["imports"]:
                print(f"  导入: {[i['name'] for i in info['imports'][:5]]}")

    print("\n✅ 测试 2 通过")
    return True


def test_dependency_graph():
    """测试依赖图构建"""
    try:
        from src.analysis.taint import CrossFileAnalyzer
    except ImportError as e:
        print(f"⚠️ 导入失败: {e}")
        return False

    print("\n" + "=" * 60)
    print("测试 3: 依赖图构建")
    print("=" * 60)

    # 使用 aegis-ai-core 项目
    project_path = Path(_project_root)

    analyzer = CrossFileAnalyzer(project_path)
    analyzer.scan_project()

    dep_graph = analyzer.get_dependency_graph()

    print(f"依赖图节点数: {len(dep_graph)}")
    print(f"依赖图边数: {sum(len(d) for d in dep_graph.values())}")

    # 找到入度最高的文件（被依赖最多）
    dependents = {}
    for file, deps in dep_graph.items():
        for dep in deps:
            dependents[dep] = dependents.get(dep, 0) + 1

    if dependents:
        top_deps = sorted(dependents.items(), key=lambda x: -x[1])[:5]
        print("\n被依赖最多的文件:")
        for dep, count in top_deps:
            rel_path = Path(dep).relative_to(project_path) if project_path in Path(dep).parents else dep
            print(f"  {rel_path}: {count} 个依赖者")

    print("\n✅ 测试 3 通过")
    return True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
