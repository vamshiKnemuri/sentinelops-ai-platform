from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

from sentinelops.audit import DynamoDBHashChainAuditLog, HashChainAuditLog
from sentinelops.llm import BedrockProvider, DeterministicProvider
from sentinelops.models import (
    ApprovalDecision,
    ApprovalRequest,
    IncidentReport,
    IncidentSignal,
    RemediationResult,
)
from sentinelops.observability import configure_tracing, traced
from sentinelops.policy import ApprovalSigner, PolicyViolation, SafetyPolicy
from sentinelops.remediation import SimulatedExecutor
from sentinelops.retrieval import RunbookRetriever, S3RunbookRetriever
from sentinelops.service import IncidentService
from sentinelops.store import (
    DynamoDBApprovalStore,
    DynamoDBIncidentStore,
    DynamoDBReplayStore,
    IncidentStore,
    InMemoryApprovalStore,
    InMemoryReplayStore,
)
from sentinelops.tools import default_registry

INCIDENTS = Counter("sentinelops_incidents_total", "Analyzed incidents", ["severity", "provider"])
ANALYSIS_LATENCY = Histogram("sentinelops_analysis_seconds", "Incident analysis latency")
APPROVALS = Counter("sentinelops_approvals_total", "Issued approvals", ["action"])
REMEDIATIONS = Counter(
    "sentinelops_remediations_total",
    "Remediation execution outcomes",
    ["action", "status"],
)
POLICY_DENIALS = Counter("sentinelops_policy_denials_total", "Denied control-plane requests")


def build_service() -> IncidentService:
    provider_name = os.getenv("SENTINELOPS_LLM_PROVIDER", "deterministic")
    if provider_name == "bedrock":
        provider = BedrockProvider(
            model_id=os.getenv("SENTINELOPS_BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0"),
            region=os.getenv("AWS_REGION", "us-east-1"),
        )
    elif provider_name == "deterministic":
        provider = DeterministicProvider()
    else:
        raise ValueError(f"unsupported LLM provider: {provider_name}")
    runbooks_bucket = os.getenv("SENTINELOPS_RUNBOOKS_BUCKET")
    retriever = (
        S3RunbookRetriever(runbooks_bucket)
        if runbooks_bucket
        else RunbookRetriever(os.getenv("SENTINELOPS_KNOWLEDGE_PATH", "knowledge/runbooks"))
    )
    table_name = os.getenv("SENTINELOPS_DYNAMODB_TABLE")
    store = DynamoDBIncidentStore(table_name) if table_name else IncidentStore()
    audit = DynamoDBHashChainAuditLog(table_name) if table_name else HashChainAuditLog()
    return IncidentService(
        retriever=retriever,
        tools=default_registry(),
        provider=provider,
        policy=SafetyPolicy(),
        store=store,
        audit=audit,
    )


def create_app(service: IncidentService | None = None) -> FastAPI:
    configure_tracing()
    app = FastAPI(title="SentinelOps AI", version="0.1.0")
    app.state.service = service or build_service()
    app.state.signer = ApprovalSigner(
        os.getenv("SENTINELOPS_APPROVAL_SECRET", "local-development-secret-change-me"),
        ttl_seconds=int(os.getenv("SENTINELOPS_APPROVAL_TTL_SECONDS", "600")),
    )
    table_name = os.getenv("SENTINELOPS_DYNAMODB_TABLE")
    app.state.approvals = (
        DynamoDBApprovalStore(table_name) if table_name else InMemoryApprovalStore()
    )
    replay_store = DynamoDBReplayStore(table_name) if table_name else InMemoryReplayStore()
    app.state.executor = SimulatedExecutor(app.state.signer, replay_store)

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "sentinelops-ai"}

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post("/v1/incidents/analyze", response_model=IncidentReport)
    def analyze(signal: IncidentSignal) -> IncidentReport:
        with traced(
            "sentinelops.api.analyze",
            **{
                "service.name": signal.service,
                "deployment.environment": signal.environment,
            },
        ):
            with ANALYSIS_LATENCY.time():
                report = app.state.service.analyze(signal)
        INCIDENTS.labels(severity=signal.severity, provider=report.model_provider).inc()
        return report

    @app.get("/v1/incidents/{incident_id}", response_model=IncidentReport)
    def get_incident(incident_id: str) -> IncidentReport:
        report = app.state.service.store.get(incident_id)
        if report is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return report

    @app.get("/v1/audit")
    def get_audit() -> dict:
        audit = app.state.service.audit
        return {"valid": audit.verify(), "events": audit.list_events()}

    @app.post("/v1/incidents/{incident_id}/approvals", response_model=ApprovalDecision)
    def approve(incident_id: str, request: ApprovalRequest) -> ApprovalDecision:
        with traced(
            "sentinelops.approval.issue",
            **{"incident.id": incident_id, "action.name": request.action},
        ):
            report = app.state.service.store.get(incident_id)
            if report is None:
                raise HTTPException(status_code=404, detail="incident not found")
            if request.incident_id != incident_id:
                raise HTTPException(status_code=400, detail="incident ID mismatch")
            recommended = {item.action for item in report.analysis.recommendations}
            if request.action not in recommended or request.action == "escalate_to_human":
                POLICY_DENIALS.inc()
                raise HTTPException(
                    status_code=400, detail="action was not recommended for approval"
                )
            decision = app.state.signer.issue(request)
            app.state.approvals.save(decision)
            APPROVALS.labels(action=request.action).inc()
            app.state.service.audit.append(
                "remediation.approved",
                request.requested_by,
                {"incident_id": incident_id, "action": request.action},
            )
            return decision

    @app.post("/v1/incidents/{incident_id}/execute", response_model=RemediationResult)
    def execute(incident_id: str, decision: ApprovalDecision) -> RemediationResult:
        if decision.incident_id != incident_id:
            raise HTTPException(status_code=400, detail="incident ID mismatch")
        try:
            with traced(
                "sentinelops.remediation.execute",
                **{"incident.id": incident_id, "action.name": decision.action},
            ):
                result = app.state.executor.execute(decision)
        except PolicyViolation as exc:
            POLICY_DENIALS.inc()
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        REMEDIATIONS.labels(action=result.action, status=result.status).inc()
        app.state.service.audit.append(
            "remediation.simulated",
            decision.approved_by,
            result.model_dump(),
        )
        return result

    return app


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run("sentinelops.api:app", host="0.0.0.0", port=int(os.getenv("PORT", "8080")))  # noqa: S104
