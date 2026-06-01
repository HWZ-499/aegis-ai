# test_query.py - 向量数据库查询演示
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_query_demo_runs_when_chromadb_available() -> None:
    chromadb = pytest.importorskip("chromadb")

    print("🔍 连接向量数据库并查询已存储的漏洞...")
    client = chromadb.PersistentClient(path="./aegis_db")
    collection = client.get_or_create_collection(name="cve_core")

    count = collection.count()
    print(f"\n📊 数据库中共有 {count} 条漏洞记录\n")

    print("=" * 60)
    print("演示 1: 查看所有存储的漏洞")
    print("=" * 60)
    results = collection.get()
    for cve_id, doc in zip(results["ids"], results["documents"]):
        print(f"\n🔴 {cve_id}")
        print(f"   内容: {doc[:100]}...")

    print("\n" + "=" * 60)
    print("演示 2: 向量语义搜索（AI 理解内容）")
    print("=" * 60)

    search_queries = ["远程代码执行漏洞", "反序列化问题", "JSON 解析缺陷"]

    for query in search_queries:
        print(f"\n🔍 搜索: '{query}'")
        try:
            results = collection.query(
                query_texts=[query],
                n_results=2,
            )
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            pytest.skip(f"ChromaDB embedding backend unavailable: {exc}")

        if results["ids"] and results["ids"][0]:
            for cve_id, distance, document in zip(results["ids"][0], results["distances"][0], results["documents"][0]):
                print(f"   ✓ {cve_id} (相似度: {distance:.3f})")
                lines = document.split("\n")
                summary = lines[1] if len(lines) > 1 else lines[0]
                print(f"     内容: {summary[:60]}...")
        else:
            print("   (无结果)")

    print("\n" + "=" * 60)
    print("✅ 查询演示完成！")
    print("=" * 60)
