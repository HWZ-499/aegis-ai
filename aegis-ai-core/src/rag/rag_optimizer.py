# rag_optimizer.py - 优化的 RAG 检索流程
"""
优化的 RAG 检索系统：
1. 多轮检索（Top-K）
2. 多维度重排序
3. 上下文融合与去重
"""

import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)


def keyword_match_score(query: str, document: str) -> float:
    """
    计算关键词匹配度（0-1）

    Args:
        query: 用户查询
        document: 文档内容

    Returns:
        匹配度分数（0-1）
    """
    # 提取查询关键词（去除停用词）
    stop_words = {
        "的",
        "了",
        "在",
        "是",
        "我",
        "有",
        "和",
        "就",
        "不",
        "人",
        "都",
        "一",
        "一个",
        "上",
        "也",
        "很",
        "到",
        "说",
        "要",
        "去",
        "你",
        "会",
        "着",
        "没有",
        "看",
        "好",
        "自己",
        "这",
    }
    query_words = set(re.findall(r"\b\w+\b", query.lower()))
    query_words = query_words - stop_words

    if not query_words:
        return 0.0

    # 计算文档中包含的关键词数量
    doc_lower = document.lower()
    matched_count = sum(1 for word in query_words if word in doc_lower)

    # 返回匹配比例
    return matched_count / len(query_words)


def severity_score(cve_id: str) -> float:
    """
    根据 CVE ID 提取严重程度分数

    Args:
        cve_id: CVE 编号（如 "CVE-2021-44228"）

    Returns:
        严重程度分数（0-1）
    """
    # 如果 CVE ID 中包含年份，新漏洞权重更高
    year_match = re.search(r"CVE-(\d{4})", cve_id)
    if year_match:
        year = int(year_match.group(1))
        current_year = datetime.now().year
        # 2020 年后的漏洞权重更高
        if year >= 2020:
            return 0.8
        elif year >= 2015:
            return 0.5
        else:
            return 0.3

    return 0.5  # 默认分数


def freshness_score(date_str: str = None) -> float:
    """
    计算时间新鲜度分数（新漏洞权重更高）

    Args:
        date_str: 日期字符串（可选）

    Returns:
        新鲜度分数（0-1）
    """
    if not date_str:
        return 0.5  # 默认分数

    try:
        # 尝试解析日期
        if isinstance(date_str, str):
            # 假设日期格式为 YYYY-MM-DD
            date_obj = datetime.strptime(date_str[:10], "%Y-%m-%d")
        else:
            return 0.5

        # 计算距离现在的天数
        days_diff = (datetime.now() - date_obj).days

        # 一年内的漏洞权重最高
        if days_diff <= 365:
            return 1.0
        elif days_diff <= 730:  # 2 年内
            return 0.7
        elif days_diff <= 1095:  # 3 年内
            return 0.5
        else:
            return 0.3
    except Exception as e:
        logger.debug("日期解析失败，使用默认权重: %s", e)
        return 0.5


def rerank_results(query: str, candidates: list[dict]) -> list[tuple[dict, float]]:
    """
    多维度重排序算法

    Args:
        query: 用户查询
        candidates: 候选结果列表，每个元素包含：
            - 'id': CVE ID
            - 'document': 文档内容
            - 'distance': 向量距离
            - 'metadata': 元数据（可选）

    Returns:
        排序后的结果列表，每个元素为 (candidate, final_score)
    """
    scored_results = []

    for candidate in candidates:
        score = 0.0

        # 维度 1：向量相似度（距离越小越好，转换为分数）
        distance = candidate.get("distance", 2.0)
        # 将距离转换为相似度分数（距离 0 = 1.0，距离 2.0 = 0.0）
        similarity_score = max(0, 1.0 - (distance / 2.0))
        score += similarity_score * 0.4  # 权重 40%

        # 维度 2：关键词匹配度
        doc = candidate.get("document", "")
        keyword_score = keyword_match_score(query, doc)
        score += keyword_score * 0.3  # 权重 30%

        # 维度 3：CVE 严重程度
        cve_id = candidate.get("id", "")
        severity = severity_score(cve_id)
        score += severity * 0.2  # 权重 20%

        # 维度 4：时间新鲜度
        metadata = candidate.get("metadata", {})
        date_str = metadata.get("date") if isinstance(metadata, dict) else None
        freshness = freshness_score(date_str)
        score += freshness * 0.1  # 权重 10%

        scored_results.append((candidate, score))

    # 按分数降序排序，返回 Top-N
    scored_results.sort(key=lambda x: x[1], reverse=True)
    return scored_results


def merge_contexts(ranked_results: list[tuple[dict, float]], top_n: int = 3) -> str:
    """
    上下文融合：将多条结果合并为上下文

    Args:
        ranked_results: 排序后的结果列表
        top_n: 取前 N 条结果

    Returns:
        融合后的上下文字符串
    """
    if not ranked_results:
        return ""

    # 取前 top_n 条
    top_results = ranked_results[:top_n]

    context_parts = []
    for i, (candidate, score) in enumerate(top_results, 1):
        doc = candidate.get("document", "")
        cve_id = candidate.get("id", "")

        # 格式化上下文
        context_parts.append(f"【参考 {i}】(相关度: {score:.2f}, CVE: {cve_id})\n{doc}\n")

    return "\n".join(context_parts)


def deduplicate_contexts(contexts: list[str], similarity_threshold: float = 0.8) -> list[str]:
    """
    去重：基于简单的内容相似度去重

    Args:
        contexts: 上下文列表
        similarity_threshold: 相似度阈值（超过此值认为是重复）

    Returns:
        去重后的上下文列表
    """
    if len(contexts) <= 1:
        return contexts

    deduplicated = []
    seen_keywords = []

    for ctx in contexts:
        # 提取关键词
        keywords = set(re.findall(r"\b\w{4,}\b", ctx.lower()))  # 至少 4 个字符的词

        # 检查是否与已有内容相似
        is_duplicate = False
        for seen_kw in seen_keywords:
            # 计算关键词重叠度
            overlap = len(keywords & seen_kw) / max(len(keywords), len(seen_kw), 1)
            if overlap > similarity_threshold:
                is_duplicate = True
                break

        if not is_duplicate:
            deduplicated.append(ctx)
            seen_keywords.append(keywords)

    return deduplicated


def optimized_rag_retrieval(collection, query: str, top_k: int = 5, return_top_n: int = 3) -> dict:
    """
    优化的 RAG 检索流程

    Args:
        collection: ChromaDB collection 对象
        query: 用户查询
        top_k: 初始检索数量
        return_top_n: 最终返回数量

    Returns:
        包含检索结果的字典：
        {
            'context': str,  # 融合后的上下文
            'ranked_results': List,  # 排序后的结果
            'distance': float,  # 最佳匹配的距离
            'has_match': bool  # 是否有有效匹配
        }
    """
    # 1. 多轮检索：检索 Top-K
    results = collection.query(query_texts=[query], n_results=top_k)

    if not results["ids"] or not results["ids"][0]:
        return {"context": "", "ranked_results": [], "distance": 2.0, "has_match": False}

    # 2. 构建候选列表
    candidates = []
    for i in range(len(results["ids"][0])):
        candidate = {
            "id": results["ids"][0][i],
            "document": results["documents"][0][i],
            "distance": results["distances"][0][i],
            "metadata": results.get("metadatas", [None])[0][i] if results.get("metadatas") else None,
        }
        candidates.append(candidate)

    # 3. 重排序
    ranked_results = rerank_results(query, candidates)

    # 4. 上下文融合
    context = merge_contexts(ranked_results, top_n=return_top_n)

    # 5. 获取最佳匹配的距离
    best_distance = ranked_results[0][0]["distance"] if ranked_results else 2.0

    # 6. 判断是否有有效匹配（距离阈值 1.5）
    has_match = best_distance < 1.5

    return {
        "context": context,
        "ranked_results": ranked_results[:return_top_n],
        "distance": best_distance,
        "has_match": has_match,
        "total_candidates": len(candidates),
    }
