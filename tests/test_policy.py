import time

import pytest

from sentinelops.models import (
    AnalysisResult,
    ApprovalRequest,
    DiagnosticHypothesis,
    Recommendation,
    Risk,
)
from sentinelops.policy import ApprovalSigner, PolicyViolation, SafetyPolicy


def test_policy_rejects_uncited_evidence() -> None:
    analysis = AnalysisResult(
        diagnosis="A deployment caused the failure.",
        confidence=0.9,
        evidence_ids=["invented:evidence"],
        hypotheses=[
            DiagnosticHypothesis(
                statement="The deployment caused the failure.",
                confidence=0.9,
                evidence_ids=["invented:evidence"],
                test_next="Compare the deployment revisions.",
            )
        ],
        recommendations=[
            Recommendation(
                action="rollback_release",
                rationale="Restore the prior revision.",
                risk=Risk.HIGH,
            )
        ],
    )

    with pytest.raises(PolicyViolation, match="not retrieved"):
        SafetyPolicy().validate_analysis(analysis, {"runbook:crashloop.md"})


def test_policy_rejects_mutation_without_approval() -> None:
    analysis = AnalysisResult(
        diagnosis="The service is saturated.",
        confidence=0.8,
        evidence_ids=["runbook:high-latency.md"],
        hypotheses=[
            DiagnosticHypothesis(
                statement="The service is saturated.",
                confidence=0.8,
                evidence_ids=["runbook:high-latency.md"],
                test_next="Inspect CPU throttling and request rate.",
            )
        ],
        recommendations=[
            Recommendation(
                action="scale_deployment",
                rationale="Add capacity.",
                risk=Risk.MEDIUM,
                requires_approval=False,
            )
        ],
    )

    with pytest.raises(PolicyViolation, match="require approval"):
        SafetyPolicy().validate_analysis(analysis, {"runbook:high-latency.md"})


def test_policy_rejects_understated_action_risk() -> None:
    analysis = AnalysisResult(
        diagnosis="The new revision is repeatedly failing.",
        confidence=0.9,
        evidence_ids=["runbook:crashloop.md"],
        hypotheses=[
            DiagnosticHypothesis(
                statement="The release introduced a memory regression.",
                confidence=0.9,
                evidence_ids=["runbook:crashloop.md"],
                test_next="Compare memory usage and limits by revision.",
            )
        ],
        recommendations=[
            Recommendation(
                action="rollback_release",
                rationale="Restore the last known-good release.",
                risk=Risk.LOW,
            )
        ],
    )

    with pytest.raises(PolicyViolation, match="action risk must be high"):
        SafetyPolicy().validate_analysis(analysis, {"runbook:crashloop.md"})


def test_policy_rejects_uncited_hypothesis() -> None:
    analysis = AnalysisResult(
        diagnosis="The service is saturated.",
        confidence=0.8,
        evidence_ids=["runbook:high-latency.md"],
        hypotheses=[
            DiagnosticHypothesis(
                statement="A downstream database is unavailable.",
                confidence=0.7,
                evidence_ids=["tool:invented-database-check"],
                test_next="Inspect database health.",
            )
        ],
        recommendations=[
            Recommendation(
                action="scale_deployment",
                rationale="Add capacity after confirming local saturation.",
                risk=Risk.MEDIUM,
            )
        ],
    )

    with pytest.raises(PolicyViolation, match="not retrieved"):
        SafetyPolicy().validate_analysis(analysis, {"runbook:high-latency.md"})


def test_approval_token_is_bound_to_action_and_identity() -> None:
    signer = ApprovalSigner("a-secure-test-secret-value", ttl_seconds=60)
    decision = signer.issue(
        ApprovalRequest(
            incident_id="inc-123",
            action="rollback_release",
            requested_by="oncall@example.com",
        )
    )

    assert signer.verify(decision)
    assert decision.expires_at.timestamp() > time.time()

    tampered = decision.model_copy(update={"action": "scale_deployment"})
    assert not signer.verify(tampered)
