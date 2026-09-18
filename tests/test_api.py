import asyncio

import httpx

from sentinelops.api import create_app
from sentinelops.audit import HashChainAuditLog
from sentinelops.llm import DeterministicProvider
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


def test_health_and_analysis_endpoints() -> None:
    async def scenario() -> None:
        transport = httpx.ASGITransport(app=create_app(build_service()))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"

            response = await client.post(
                "/v1/incidents/analyze",
                json={
                    "source": "alertmanager",
                    "title": "KubePodCrashLooping",
                    "service": "checkout-api",
                    "severity": "critical",
                    "summary": "Pods are OOMKilled after deployment",
                    "labels": {"namespace": "payments"},
                },
            )
            assert response.status_code == 200
            recommendation = response.json()["analysis"]["recommendations"][0]
            assert recommendation["requires_approval"] is True

            audit = await client.get("/v1/audit")
            assert audit.status_code == 200
            assert audit.json()["valid"] is True

    asyncio.run(scenario())


def test_approval_and_simulated_execution_are_bound_and_single_use() -> None:
    async def scenario() -> None:
        transport = httpx.ASGITransport(app=create_app(build_service()))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            analysis = (
                await client.post(
                    "/v1/incidents/analyze",
                    json={
                        "source": "alertmanager",
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

            assert approval.status_code == 200
            execution = await client.post(
                f"/v1/incidents/{incident_id}/execute",
                json=approval.json(),
            )
            assert execution.status_code == 200
            assert execution.json()["status"] == "simulated_success"
            assert execution.json()["simulated"] is True

            replay = await client.post(
                f"/v1/incidents/{incident_id}/execute",
                json=approval.json(),
            )
            assert replay.status_code == 403

    asyncio.run(scenario())
