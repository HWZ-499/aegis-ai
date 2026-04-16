import sys
from types import SimpleNamespace

from src.scanner.rag_enhancer import RAGEnhancer


def test_init_chromadb_failure_keeps_collection_none(monkeypatch) -> None:
    class FakeClient:
        def __init__(self, path: str) -> None:
            self.path = path

        def get_collection(self, name: str):
            raise RuntimeError(f"missing {name}")

    monkeypatch.setitem(sys.modules, "chromadb", SimpleNamespace(PersistentClient=FakeClient))

    enhancer = RAGEnhancer(db_path="fake-db", use_rag=True)

    assert enhancer.collection is None


def test_enhance_findings_without_collection_returns_builtin_fallback() -> None:
    enhancer = RAGEnhancer(use_rag=False)
    findings = [{"type": "SQL_INJECTION", "severity": "High", "details": "Possible SQL injection"}]

    enhanced = enhancer.enhance_findings(findings)

    assert len(enhanced) == 1
    assert enhanced[0]["type"] == "SQL_INJECTION"
    assert "remediation" in enhanced[0]
