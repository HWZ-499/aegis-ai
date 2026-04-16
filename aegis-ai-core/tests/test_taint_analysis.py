"""
test_taint_analysis.py - 污点分析测试

测试完整的 Source → Sink 污点分析系统。
"""

import pytest

from src.analysis.taint import EdgeType, NodeType, TaintAnalyzer, TaintGraph, get_default_registry


def test_basic_taint_path():
    """测试基本污点路径追踪：直接 Source → Sink 应产生 finding。"""
    code_direct = """
const userInput = req.body.command;
eval(userInput);
"""
    analyzer = TaintAnalyzer(language="javascript")
    findings = analyzer.analyze_code(code_direct, "test_direct.js")

    assert len(findings) > 0, "Direct taint path (req.body -> eval) should produce findings"
    assert any(f.vuln_type for f in findings), "Findings should have vuln_type"


def test_indirect_taint_path():
    """测试间接污点路径：Source → var → var → Sink 应识别到 source 和 sink。"""
    code_indirect = """
const userData = req.body;
const name = userData.name;
const query = name;
db.users.findOne({ name: query });
"""
    analyzer = TaintAnalyzer(language="javascript")
    analyzer.analyze_code(code_indirect, "test_indirect.js")

    graph = analyzer.get_graph()
    stats = graph.get_stats()

    assert stats["sources"] > 0, "Should identify at least one source (req.body)"
    assert stats["sinks"] > 0, "Should identify at least one sink (findOne)"


def test_nosql_injection():
    """测试 NoSQL 注入检测：usersCollection.findOne 应被识别为 sink。"""
    code_nosql = """
const userId = req.body.userId;
const password = req.body.password;
usersCollection.findOne({ userId: userId, password: password });
"""
    analyzer = TaintAnalyzer(language="javascript")
    analyzer.analyze_code(code_nosql, "test_nosql.js")

    graph = analyzer.get_graph()
    sources = graph.get_sources()

    assert len(sources) > 0, "Should identify sources from req.body"


def test_rce_detection():
    """测试 RCE 检测：req.query → exec 应产生 finding。"""
    code_rce = """
const cmd = req.query.cmd;
exec(cmd);
"""
    analyzer = TaintAnalyzer(language="javascript")
    findings = analyzer.analyze_code(code_rce, "test_rce.js")

    assert len(findings) > 0, "RCE taint path (req.query -> exec) should produce findings"


def test_source_sink_registry():
    """测试 Source/Sink 注册表：常见模式应正确匹配。"""
    registry = get_default_registry()
    stats = registry.get_stats()

    assert stats["sources"] > 0, "Registry should have sources"
    assert stats["sinks"] > 0, "Registry should have sinks"

    # JS sources
    assert registry.is_source("req.body.username", "javascript")
    assert registry.is_source("req.query.id", "javascript")

    # Python sources
    assert registry.is_source("request.form['name']", "python")

    # JS sinks
    assert registry.is_sink("eval(code)", "javascript")
    assert registry.is_sink("exec(cmd)", "javascript")

    # Python sinks
    assert registry.is_sink("pickle.loads(data)", "python")


def test_taint_graph():
    """测试污点图数据结构：手动构建的 Source→Sink 路径应可检索。"""
    graph = TaintGraph()

    source = graph.add_node("userInput", NodeType.SOURCE, "test.js", 1)
    var1 = graph.add_node("data", NodeType.VARIABLE, "test.js", 2)
    var2 = graph.add_node("query", NodeType.VARIABLE, "test.js", 3)
    sink = graph.add_node("eval(query)", NodeType.SINK, "test.js", 4)

    graph.add_edge(source.id, var1.id, EdgeType.ASSIGNMENT, 2)
    graph.add_edge(var1.id, var2.id, EdgeType.PROPAGATION, 3)
    graph.add_edge(var2.id, sink.id, EdgeType.PARAMETER_PASS, 4)

    paths = graph.find_paths_to_sinks()
    assert len(paths) > 0, "Should find at least one Source→Sink path"
    assert not paths[0].is_sanitized, "Path should not be sanitized"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
