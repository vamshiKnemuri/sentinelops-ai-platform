from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from sentinelops.models import Evidence, IncidentSignal

TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]+")


def tokenize(text: str) -> list[str]:
    return TOKEN_PATTERN.findall(text.lower())


class RunbookRetriever:
    """Small, deterministic BM25-style retriever for versioned Markdown runbooks."""

    def __init__(self, knowledge_path: str | Path) -> None:
        self.knowledge_path = Path(knowledge_path)
        self.documents: list[tuple[str, str, Counter[str]]] = []
        self.document_frequency: Counter[str] = Counter()
        self.average_length = 1.0
        self.reload()

    def reload(self) -> None:
        self.documents.clear()
        self.document_frequency.clear()
        for path in sorted(self.knowledge_path.glob("*.md")):
            content = path.read_text(encoding="utf-8")
            terms = Counter(tokenize(content))
            self.documents.append((path.name, content, terms))
            self.document_frequency.update(terms.keys())
        if self.documents:
            self.average_length = sum(sum(doc[2].values()) for doc in self.documents) / len(
                self.documents
            )

    def search(self, signal: IncidentSignal, limit: int = 3) -> list[Evidence]:
        query = tokenize(
            " ".join([signal.title, signal.service, signal.summary, *signal.labels.values()])
        )
        scored: list[tuple[float, str, str]] = []
        total_documents = max(len(self.documents), 1)
        for name, content, terms in self.documents:
            score = 0.0
            document_length = max(sum(terms.values()), 1)
            for term in query:
                frequency = terms.get(term, 0)
                if not frequency:
                    continue
                document_frequency = self.document_frequency.get(term, 0)
                inverse_document_frequency = math.log(
                    1 + (total_documents - document_frequency + 0.5) / (document_frequency + 0.5)
                )
                denominator = frequency + 1.5 * (
                    0.25 + 0.75 * document_length / self.average_length
                )
                score += inverse_document_frequency * frequency * 2.5 / denominator
            if score:
                scored.append((score, name, content))

        scored.sort(reverse=True)
        ceiling = scored[0][0] if scored else 1.0
        return [
            Evidence(
                evidence_id=f"runbook:{name}",
                source=name,
                content=content[:4_000],
                relevance=round(min(score / ceiling, 1.0), 3),
            )
            for score, name, content in scored[:limit]
        ]
