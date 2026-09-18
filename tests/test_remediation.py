import pytest

from sentinelops.models import ApprovalRequest
from sentinelops.policy import ApprovalSigner, PolicyViolation
from sentinelops.remediation import SimulatedExecutor


def test_executor_rejects_token_replay() -> None:
    signer = ApprovalSigner("a-secure-test-secret-value")
    executor = SimulatedExecutor(signer)
    approval = signer.issue(
        ApprovalRequest(
            incident_id="inc-123",
            action="restart_deployment",
            requested_by="oncall@example.com",
        )
    )

    assert executor.execute(approval).simulated is True
    with pytest.raises(PolicyViolation, match="already been used"):
        executor.execute(approval)
