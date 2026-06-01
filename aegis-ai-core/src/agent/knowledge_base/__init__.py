"""Deterministic Markdown knowledge retrieval for Aegis Agent."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)?", re.IGNORECASE)


@dataclass(frozen=True)
class KnowledgeDocument:
    """A loaded Markdown knowledge document."""

    title: str
    source: str
    body: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class KnowledgeHit:
    """A ranked knowledge retrieval result."""

    title: str
    source: str
    score: float
    snippet: str
    tags: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "title": self.title,
            "source": self.source,
            "score": round(self.score, 4),
            "snippet": self.snippet,
            "tags": list(self.tags),
        }


def _tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def _extract_title(markdown: str, fallback: str) -> str:
    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return fallback


def _extract_tags(markdown: str) -> tuple[str, ...]:
    for line in markdown.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("tags:"):
            raw = stripped.split(":", 1)[1]
            return tuple(tag.strip().lower() for tag in raw.split(",") if tag.strip())
    return ()


def _snippet(text: str, query_terms: set[str], limit: int = 360) -> str:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    if not paragraphs:
        return text[:limit].strip()
    best = max(paragraphs, key=lambda p: sum(1 for token in _tokenize(p) if token in query_terms))
    if len(best) <= limit:
        return best
    return best[: limit - 3].rstrip() + "..."


class MarkdownKnowledgeBase:
    """Small, deterministic retrieval layer over bundled Markdown docs."""

    def __init__(self, docs: list[KnowledgeDocument] | None = None) -> None:
        self._docs = docs if docs is not None else self._load_bundled_docs()
        self._doc_terms: dict[str, Counter[str]] = {
            doc.source: Counter(_tokenize(" ".join([doc.title, doc.body, " ".join(doc.tags)]))) for doc in self._docs
        }

    @staticmethod
    def _load_bundled_docs() -> list[KnowledgeDocument]:
        docs: list[KnowledgeDocument] = []
        root = resources.files("src.agent.knowledge_base")
        for item in sorted(root.iterdir(), key=lambda resource: resource.name):
            if item.name == "__init__.py" or not item.name.endswith(".md"):
                continue
            markdown = item.read_text(encoding="utf-8")
            docs.append(
                KnowledgeDocument(
                    title=_extract_title(markdown, Path(item.name).stem),
                    source=item.name,
                    body=markdown,
                    tags=_extract_tags(markdown),
                )
            )
        return docs

    def search(self, query: str, top_k: int = 3) -> list[KnowledgeHit]:
        """Return top ranked knowledge documents for a query."""
        query_terms = Counter(_tokenize(query))
        if not query_terms:
            return []

        hits: list[KnowledgeHit] = []
        query_set = set(query_terms)
        query_norm = math.sqrt(sum(value * value for value in query_terms.values())) or 1.0

        for doc in self._docs:
            doc_terms = self._doc_terms[doc.source]
            overlap = sum(query_terms[token] * doc_terms.get(token, 0) for token in query_terms)
            if overlap <= 0:
                continue
            doc_norm = math.sqrt(sum(value * value for value in doc_terms.values())) or 1.0
            score = overlap / (query_norm * doc_norm)
            tag_bonus = 0.08 * len(query_set.intersection(doc.tags))
            title_bonus = 0.05 * sum(1 for token in query_set if token in _tokenize(doc.title))
            score += tag_bonus + title_bonus
            hits.append(
                KnowledgeHit(
                    title=doc.title,
                    source=doc.source,
                    score=score,
                    snippet=_snippet(doc.body, query_set),
                    tags=doc.tags,
                )
            )

        return sorted(hits, key=lambda hit: (-hit.score, hit.source))[: max(1, top_k)]


__all__ = ["KnowledgeDocument", "KnowledgeHit", "MarkdownKnowledgeBase"]
