from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_chromadb_query_demo() -> None:
    """Manual ChromaDB query demo; excluded from the default test gate."""
    import chromadb

    client = chromadb.PersistentClient(path="./aegis_db")
    collection = client.get_or_create_collection(name="cve_core")

    assert collection.count() >= 0
    for query in ["remote code execution", "deserialization issue", "JSON parsing weakness"]:
        results = collection.query(query_texts=[query], n_results=2)
        assert "ids" in results
