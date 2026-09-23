from __future__ import annotations

from sentinelops.models import ApprovalDecision, RemediationResult
from sentinelops.policy import ApprovalSigner, PolicyViolation
from sentinelops.store import InMemoryReplayStore, ReplayStore


class SimulatedExecutor:
    """Portfolio-safe executor that proves control flow without mutating a cluster."""

    def __init__(self, signer: ApprovalSigner, replay_store: ReplayStore | None = None) -> None:
        self.signer = signer
        self.replay_store = replay_store or InMemoryReplayStore()

    def execute(self, decision: ApprovalDecision) -> RemediationResult:
        if not self.signer.verify(decision):
            raise PolicyViolation("approval token is invalid or expired")
        if not self.replay_store.consume(decision.approval_token, decision.expires_at):
            raise PolicyViolation("approval token has already been used")
        return RemediationResult(
            incident_id=decision.incident_id,
            action=decision.action,
            status="simulated_success",
            executed_by=decision.approved_by,
            simulated=True,
        )
