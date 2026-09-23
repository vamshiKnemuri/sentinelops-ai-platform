import asyncio

import httpx
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from sentinelops import observability
from sentinelops.api import create_app
from sentinelops.audit import HashChainAuditLog
from sentinelops.llm import DeterministicProvider
from sentinelops.observability import ATTRIBUTE_ALLOWLIST, safe_attributes
from sentinelops.policy import SafetyPolicy
from sentinelops.retrieval import RunbookRetriever
from sentinelops.service import IncidentService
from sentinelops.store import IncidentStore
from sentinelops.tools import default_registry


def test_trace_attribute_allowlist_drops_payloads_and_secrets() -> None:
    attributes = safe_attributes(
        **{
            "incident.id": "inc-123",
            "service.name": "checkout-api",
            "action.name": "rollback_release",
            "alert.summary": "sensitive incident payload",
            "approval.token": "secret-token",
            "aws.access_key": "AKIAEXAMPLE",
        }
    )

    assert attributes == {
        "incident.id": "inc-123",
        "service.name": "checkout-api",
        "action.name": "rollback_release",
    }
    assert set(attributes).issubset(ATTRIBUTE_ALLOWLIST)


def test_complete_incident_workflow_emits_expected_spans(monkeypatch) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=ALWAYS_ON)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(
        observability.trace,
        "get_tracer",
        lambda _name: provider.get_tracer("sentinelops-test"),
    )
    service = IncidentService(
        retriever=RunbookRetriever("knowledge/runbooks"),
        tools=default_registry(),
        provider=DeterministicProvider(),
        policy=SafetyPolicy(),
        store=IncidentStore(),
        audit=HashChainAuditLog(),
    )

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=create_app(service))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            analysis = (
                await client.post(
                    "/v1/incidents/analyze",
                    json={
                        "source": "test",
                        "title": "KubePodCrashLooping",
                        "service": "checkout-api",
                        "summary": "Pods are OOMKilled after deployment",
                    },
                )
            ).json()
            incident_id = analysis["incident_id"]
            approval = await client.post(
                f"/v1/incidents/{incident_id}/approvals",
                json={
                    "incident_id": incident_id,
                    "action": "rollback_release",
                    "requested_by": "oncall@example.com",
                },
            )
            execution = await client.post(
                f"/v1/incidents/{incident_id}/execute", json=approval.json()
            )
            assert execution.status_code == 200

    asyncio.run(scenario())
    span_names = {span.name for span in exporter.get_finished_spans()}
    assert {
        "sentinelops.api.analyze",
        "sentinelops.retrieval.search",
        "sentinelops.tools.collect",
        "sentinelops.tool.execute",
        "sentinelops.model.analyze",
        "sentinelops.policy.validate",
        "sentinelops.approval.issue",
        "sentinelops.remediation.execute",
    }.issubset(span_names)
