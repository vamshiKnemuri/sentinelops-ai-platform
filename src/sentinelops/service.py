from __future__ import annotations

import hashlib
import json

from sentinelops.audit import HashChainAuditLog
from sentinelops.llm import LLMProvider, LLMProviderError, fail_closed_analysis
from sentinelops.models import Evidence, IncidentReport, IncidentSignal
from sentinelops.policy import SafetyPolicy
from sentinelops.retrieval import RunbookRetriever
from sentinelops.store import IncidentStore
from sentinelops.tools import ToolRegistry


class IncidentService:
    def __init__(
        self,
        retriever: RunbookRetriever,
        tools: ToolRegistry,
        provider: LLMProvider,
        policy: SafetyPolicy,
        store: IncidentStore,
        audit: HashChainAuditLog,
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
        observations = self.tools.run_all(signal)
        allowed_evidence_ids = {item.evidence_id for item in evidence}
        allowed_evidence_ids.update(item.evidence_id for item in observations)
        provider_failed = False
        try:
            analysis = self.provider.analyze(signal, evidence, observations)
        except LLMProviderError:
            provider_failed = True
            analysis = fail_closed_analysis(sorted(allowed_evidence_ids))
        self.policy.validate_analysis(analysis, allowed_evidence_ids)
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
