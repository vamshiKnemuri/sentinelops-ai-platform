from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from sentinelops.models import AnalysisResult, ApprovalDecision, ApprovalRequest, Risk


class PolicyViolation(ValueError):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class SafetyPolicy:
    ALLOWED_ACTIONS = {
        "restart_deployment": Risk.MEDIUM,
        "rollback_release": Risk.HIGH,
        "scale_deployment": Risk.MEDIUM,
        "escalate_to_human": Risk.LOW,
    }

    def validate_analysis(self, analysis: AnalysisResult, evidence_ids: set[str]) -> None:
        cited_ids = set(analysis.evidence_ids)
        cited_ids.update(
            evidence_id
            for hypothesis in analysis.hypotheses
            for evidence_id in hypothesis.evidence_ids
        )
        if not cited_ids.issubset(evidence_ids):
            raise PolicyViolation("analysis cited evidence that was not retrieved")
        if analysis.confidence < 0.65:
            for recommendation in analysis.recommendations:
                if recommendation.action != "escalate_to_human":
                    raise PolicyViolation("low-confidence analysis cannot propose remediation")
        for recommendation in analysis.recommendations:
            if recommendation.action not in self.ALLOWED_ACTIONS:
                raise PolicyViolation(f"action is not allowlisted: {recommendation.action}")
            expected_risk = self.ALLOWED_ACTIONS[recommendation.action]
            if recommendation.risk != expected_risk:
                raise PolicyViolation(
                    f"action risk must be {expected_risk}: {recommendation.action}"
                )
            if (
                recommendation.action != "escalate_to_human"
                and not recommendation.requires_approval
            ):
                raise PolicyViolation("mutating recommendations must require approval")
            if recommendation.action == "escalate_to_human" and recommendation.requires_approval:
                raise PolicyViolation("human escalation must not require remediation approval")

        actions = [item.action for item in analysis.recommendations]
        if len(actions) != len(set(actions)):
            raise PolicyViolation("analysis contains duplicate recommendations")


class ApprovalSigner:
    def __init__(self, secret: str, ttl_seconds: int = 600) -> None:
        if len(secret) < 16:
            raise ValueError("approval secret must contain at least 16 characters")
        self.secret = secret.encode()
        self.ttl_seconds = ttl_seconds

    def issue(self, request: ApprovalRequest) -> ApprovalDecision:
        expires_epoch = int(time.time()) + self.ttl_seconds
        claims = {
            "incident_id": request.incident_id,
            "action": request.action,
            "approved_by": request.requested_by,
            "expires": expires_epoch,
        }
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
        return ApprovalDecision(
            incident_id=request.incident_id,
            action=request.action,
            approved_by=request.requested_by,
            approval_token=f"{expires_epoch}.{signature}",
            expires_at=datetime.fromtimestamp(expires_epoch, tz=UTC),
        )

    def verify(self, decision: ApprovalDecision) -> bool:
        try:
            expires_text, supplied_signature = decision.approval_token.split(".", 1)
            expires_epoch = int(expires_text)
        except (ValueError, TypeError):
            return False
        if expires_epoch < int(time.time()):
            return False
        claims = {
            "incident_id": decision.incident_id,
            "action": decision.action,
            "approved_by": decision.approved_by,
            "expires": expires_epoch,
        }
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(supplied_signature, expected)
