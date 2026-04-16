from src.analysis.taint.cross_file_analyzer import CrossFileAnalyzer
from src.analysis.taint.taint_analyzer import TaintAnalyzer
from src.analysis.taint.taint_graph import TaintPath


class _FakeNode:
    def __init__(self, text: bytes) -> None:
        self.text = text


def test_taint_node_text_helpers_decode_bytes() -> None:
    node = _FakeNode(b"user_input")

    assert CrossFileAnalyzer._get_node_text(node) == "user_input"
    assert TaintAnalyzer._get_node_text(node) == "user_input"


def test_taint_path_allows_empty_endpoints_for_partial_paths() -> None:
    path = TaintPath()

    assert path.source_node is None
    assert path.sink_node is None
