from sentinelops.models import IncidentSignal
from sentinelops.retrieval import RunbookRetriever


def test_crashloop_retrieves_matching_runbook() -> None:
    retriever = RunbookRetriever("knowledge/runbooks")
    evidence = retriever.search(
        IncidentSignal(
            source="test",
            title="KubePodCrashLooping",
            service="checkout-api",
            summary="pod is OOMKilled and restarting after deployment",
        )
    )

    assert evidence
    assert evidence[0].source == "crashloop.md"
    assert evidence[0].relevance == 1.0


def test_unknown_query_returns_no_false_evidence() -> None:
    retriever = RunbookRetriever("knowledge/runbooks")
    evidence = retriever.search(
        IncidentSignal(
            source="test",
            title="certificate expiration",
            service="edge",
            summary="certificate chain validation failed",
        )
    )

    assert evidence == []
