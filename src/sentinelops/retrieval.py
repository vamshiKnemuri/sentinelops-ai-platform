from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from sentinelops.models import Evidence, IncidentSignal

TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]+")


def tokenize(text: str) -> list[str]:
    return TOKEN_PATTERN.findall(text.lower())


class RunbookSearch(Protocol):
    def search(self, signal: IncidentSignal, limit: int = 3) -> list[Evidence]: ...


class RankedRunbookRetriever:
    """Deterministic BM25-style ranking shared by local and S3 runbook sources."""

    def __init__(self) -> None:
        self.documents: list[tuple[str, str, Counter[str]]] = []
        self.document_frequency: Counter[str] = Counter()
        self.average_length = 1.0

    def _replace_documents(self, documents: Iterable[tuple[str, str]]) -> None:
        self.documents.clear()
        self.document_frequency.clear()
        for name, content in sorted(documents):
            terms = Counter(tokenize(content))
            self.documents.append((name, content, terms))
            self.document_frequency.update(terms.keys())
        if self.documents:
            self.average_length = sum(sum(doc[2].values()) for doc in self.documents) / len(
                self.documents
            )
        else:
            self.average_length = 1.0

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


class RunbookRetriever(RankedRunbookRetriever):
    """Load versioned Markdown runbooks from the local filesystem."""

    def __init__(self, knowledge_path: str | Path) -> None:
        super().__init__()
        self.knowledge_path = Path(knowledge_path)
        self.reload()

    def reload(self) -> None:
        self._replace_documents(
            (path.name, path.read_text(encoding="utf-8"))
            for path in self.knowledge_path.glob("*.md")
        )


class S3RunbookRetriever(RankedRunbookRetriever):
    """Load checksum-verified, versioned Markdown runbooks from S3."""

    def __init__(self, bucket: str, prefix: str = "runbooks/", client=None) -> None:
        super().__init__()
        if client is None:
            import boto3

            client = boto3.client("s3")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.reload()

    def reload(self) -> None:
        documents: list[tuple[str, str]] = []
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for item in page.get("Contents", []):
                key = item["Key"]
                if not key.endswith(".md"):
                    continue
                response = self.client.get_object(Bucket=self.bucket, Key=key)
                body = response["Body"].read()
                expected_checksum = response.get("Metadata", {}).get("sha256")
                actual_checksum = hashlib.sha256(body).hexdigest()
                if not expected_checksum or not hmac.compare_digest(
                    expected_checksum, actual_checksum
                ):
                    raise ValueError(f"runbook checksum validation failed: {key}")
                documents.append((Path(key).name, body.decode("utf-8")))
        self._replace_documents(documents)
