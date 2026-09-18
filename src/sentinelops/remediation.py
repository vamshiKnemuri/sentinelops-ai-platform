from __future__ import annotations

from threading import Lock

from sentinelops.models import ApprovalDecision, RemediationResult
from sentinelops.policy import ApprovalSigner, PolicyViolation


class SimulatedExecutor:
    """Portfolio-safe executor that proves control flow without mutating a cluster."""

    def __init__(self, signer: ApprovalSigner) -> None:
        self.signer = signer
        self._used_tokens: set[str] = set()
        self._lock = Lock()

    def execute(self, decision: ApprovalDecision) -> RemediationResult:
        if not self.signer.verify(decision):
            raise PolicyViolation("approval token is invalid or expired")
        with self._lock:
            if decision.approval_token in self._used_tokens:
                raise PolicyViolation("approval token has already been used")
            self._used_tokens.add(decision.approval_token)
        return RemediationResult(
            incident_id=decision.incident_id,
            action=decision.action,
            status="simulated_success",
            executed_by=decision.approved_by,
            simulated=True,
        )
