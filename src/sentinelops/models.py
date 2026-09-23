from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AnalysisStatus(StrEnum):
    COMPLETE = "complete"
    DEGRADED = "degraded"


class IncidentSignal(BaseModel):
    source: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=200)
    service: str = Field(min_length=1, max_length=100)
    environment: str = Field(default="production", max_length=40)
    severity: Severity = Severity.WARNING
    summary: str = Field(min_length=1, max_length=4_000)
    labels: dict[str, str] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("labels")
    @classmethod
    def bound_labels(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 30:
            raise ValueError("labels cannot contain more than 30 entries")
        return value


class Evidence(BaseModel):
    evidence_id: str
    source: str
    content: str
    relevance: float = Field(ge=0, le=1)


class ToolObservation(BaseModel):
    evidence_id: str
    tool: str
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    read_only: bool = True


class Recommendation(BaseModel):
    action: str
    rationale: str
    risk: Risk
    requires_approval: bool = True


class DiagnosticHypothesis(BaseModel):
    statement: str = Field(min_length=1, max_length=600)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1, max_length=10)
    test_next: str = Field(min_length=1, max_length=600)


class AnalysisResult(BaseModel):
    status: AnalysisStatus = AnalysisStatus.COMPLETE
    diagnosis: str
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)
    hypotheses: list[DiagnosticHypothesis] = Field(min_length=1, max_length=5)
    recommendations: list[Recommendation] = Field(min_length=1, max_length=5)
    uncertainties: list[str] = Field(default_factory=list, max_length=10)
    safety_notes: list[str] = Field(default_factory=list, max_length=10)


class IncidentReport(BaseModel):
    incident_id: str
    signal: IncidentSignal
    analysis: AnalysisResult
    evidence: list[Evidence]
    tool_observations: list[ToolObservation]
    model_provider: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApprovalRequest(BaseModel):
    incident_id: str
    action: str
    requested_by: str = Field(min_length=1, max_length=120)


class ApprovalDecision(BaseModel):
    incident_id: str
    action: str
    approved_by: str
    approval_token: str
    expires_at: datetime


class RemediationResult(BaseModel):
    incident_id: str
    action: str
    status: str
    executed_by: str
    simulated: bool = True
