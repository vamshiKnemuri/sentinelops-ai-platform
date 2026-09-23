from sentinelops.audit import HashChainAuditLog
from sentinelops.llm import DeterministicProvider, LLMProviderError
from sentinelops.models import AnalysisStatus, IncidentSignal
from sentinelops.policy import SafetyPolicy
from sentinelops.retrieval import RunbookRetriever
from sentinelops.service import IncidentService
from sentinelops.store import IncidentStore
from sentinelops.tools import default_registry


def build_service() -> IncidentService:
    return IncidentService(
        retriever=RunbookRetriever("knowledge/runbooks"),
        tools=default_registry(),
        provider=DeterministicProvider(),
        policy=SafetyPolicy(),
        store=IncidentStore(),
        audit=HashChainAuditLog(),
    )


def test_analysis_is_evidence_backed_and_idempotent() -> None:
    service = build_service()
    signal = IncidentSignal(
        source="alertmanager",
        title="KubePodCrashLooping",
        service="checkout-api",
        summary="Pods are OOMKilled after deployment",
        labels={"namespace": "payments"},
    )

    first = service.analyze(signal)
    second = service.analyze(signal)

    assert first.incident_id == second.incident_id
    assert first.analysis.confidence >= 0.65
    assert first.analysis.recommendations[0].action == "rollback_release"
    available_evidence = {evidence.evidence_id for evidence in first.evidence}
    available_evidence.update(item.evidence_id for item in first.tool_observations)
    assert set(first.analysis.evidence_ids).issubset(available_evidence)
    assert len(service.audit.list_events()) == 1
    assert service.audit.verify()


def test_unknown_incident_escalates_instead_of_mutating() -> None:
    service = build_service()
    report = service.analyze(
        IncidentSignal(
            source="alertmanager",
            title="UnknownFailure",
            service="mystery-service",
            summary="No matching operational evidence is available",
        )
    )

    assert report.analysis.confidence < 0.65
    assert report.analysis.recommendations[0].action == "escalate_to_human"


class FailingProvider:
    name = "failing-test-provider"

    def analyze(self, signal, evidence, observations):  # noqa: ANN001, ANN201
        raise LLMProviderError("synthetic provider failure")


def test_provider_failure_returns_audited_fail_closed_analysis() -> None:
    service = IncidentService(
        retriever=RunbookRetriever("knowledge/runbooks"),
        tools=default_registry(),
        provider=FailingProvider(),
        policy=SafetyPolicy(),
        store=IncidentStore(),
        audit=HashChainAuditLog(),
    )
    report = service.analyze(
        IncidentSignal(
            source="alertmanager",
            title="KubePodCrashLooping",
            service="checkout-api",
            summary="Pods are OOMKilled after deployment",
        )
    )

    assert report.analysis.status is AnalysisStatus.DEGRADED
    assert report.analysis.confidence == 0.0
    assert report.analysis.recommendations[0].action == "escalate_to_human"
    assert [event["event_type"] for event in service.audit.list_events()] == [
        "incident.analysis_degraded",
        "incident.analyzed",
    ]
