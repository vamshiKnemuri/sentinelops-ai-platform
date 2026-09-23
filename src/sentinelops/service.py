from __future__ import annotations

import hashlib
import json

from sentinelops.audit import AuditLog
from sentinelops.llm import LLMProvider, LLMProviderError, fail_closed_analysis
from sentinelops.models import Evidence, IncidentReport, IncidentSignal
from sentinelops.observability import traced
from sentinelops.policy import PolicyViolation, SafetyPolicy
from sentinelops.retrieval import RunbookSearch
from sentinelops.store import IncidentRepository
from sentinelops.tools import ToolRegistry


class IncidentService:
    def __init__(
        self,
        retriever: RunbookSearch,
        tools: ToolRegistry,
        provider: LLMProvider,
        policy: SafetyPolicy,
        store: IncidentRepository,
        audit: AuditLog,
    ) -> None:
        self.retriever = retriever
        self.tools = tools
        self.provider = provider
        self.policy = policy
        self.store = store
        self.audit = audit

    @staticmethod
    def incident_id(signal: IncidentSignal) -> str:
        stable_signal = signal.model_dump(mode="json", exclude={"observed_at"})
        digest = hashlib.sha256(json.dumps(stable_signal, sort_keys=True).encode()).hexdigest()
        return f"inc-{digest[:12]}"

    def analyze(self, signal: IncidentSignal) -> IncidentReport:
        incident_id = self.incident_id(signal)
        existing = self.store.get(incident_id)
        if existing:
            return existing

        with traced(
            "sentinelops.retrieval.search",
            **{"incident.id": incident_id, "service.name": signal.service},
        ):
            evidence = self.retriever.search(signal)
        if not evidence:
            evidence = [
                Evidence(
                    evidence_id="signal:original",
                    source=signal.source,
                    content=signal.summary,
                    relevance=1.0,
                )
            ]
        with traced(
            "sentinelops.tools.collect",
            **{"incident.id": incident_id, "service.name": signal.service},
        ):
            observations = self.tools.run_all(signal)
        allowed_evidence_ids = {item.evidence_id for item in evidence}
        allowed_evidence_ids.update(item.evidence_id for item in observations)
        provider_failed = False
        try:
            with traced(
                "sentinelops.model.analyze",
                **{
                    "incident.id": incident_id,
                    "ai.provider": self.provider.name,
                    "ai.model": getattr(self.provider, "model_id", self.provider.name),
                },
            ) as model_span:
                analysis = self.provider.analyze(signal, evidence, observations)
                confidence_bucket = (
                    "low"
                    if analysis.confidence < 0.65
                    else "medium"
                    if analysis.confidence < 0.85
                    else "high"
                )
                model_span.set_attribute("ai.status", analysis.status)
                model_span.set_attribute("ai.confidence_bucket", confidence_bucket)
        except LLMProviderError:
            provider_failed = True
            analysis = fail_closed_analysis(sorted(allowed_evidence_ids))
        with traced(
            "sentinelops.policy.validate",
            **{
                "incident.id": incident_id,
                "ai.status": analysis.status,
            },
        ) as policy_span:
            try:
                self.policy.validate_analysis(analysis, allowed_evidence_ids)
            except PolicyViolation:
                policy_span.set_attribute("policy.outcome", "denied")
                raise
            policy_span.set_attribute("policy.outcome", "accepted")
        report = IncidentReport(
            incident_id=incident_id,
            signal=signal,
            analysis=analysis,
            evidence=evidence,
            tool_observations=observations,
            model_provider=self.provider.name,
        )
        stored = self.store.put_if_absent(report)
        if provider_failed:
            self.audit.append(
                event_type="incident.analysis_degraded",
                actor="sentinelops-control-plane",
                payload={"incident_id": incident_id, "provider": self.provider.name},
            )
        self.audit.append(
            event_type="incident.analyzed",
            actor="sentinelops-agent",
            payload={
                "incident_id": incident_id,
                "provider": self.provider.name,
                "confidence": analysis.confidence,
                "evidence_ids": analysis.evidence_ids,
            },
        )
        return stored
