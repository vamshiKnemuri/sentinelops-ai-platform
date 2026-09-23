from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from moto import mock_aws

from sentinelops.audit import DynamoDBHashChainAuditLog
from sentinelops.models import (
    AnalysisResult,
    ApprovalDecision,
    DiagnosticHypothesis,
    IncidentReport,
    IncidentSignal,
    Recommendation,
    Risk,
)
from sentinelops.retrieval import S3RunbookRetriever
from sentinelops.store import (
    DynamoDBApprovalStore,
    DynamoDBIncidentStore,
    DynamoDBReplayStore,
)


def create_table(client, table_name: str) -> None:
    client.create_table(
        TableName=table_name,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
    )
    client.update_time_to_live(
        TableName=table_name,
        TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl_epoch"},
    )


def sample_report(summary: str = "Pods are OOMKilled") -> IncidentReport:
    evidence_id = "runbook:crashloop.md"
    return IncidentReport(
        incident_id="inc-aws-adapter",
        signal=IncidentSignal(
            source="test",
            title="KubePodCrashLooping",
            service="checkout-api",
            summary=summary,
        ),
        analysis=AnalysisResult(
            diagnosis="The workload exceeded its memory limit.",
            confidence=0.9,
            evidence_ids=[evidence_id],
            hypotheses=[
                DiagnosticHypothesis(
                    statement="The new revision has a memory regression.",
                    confidence=0.9,
                    evidence_ids=[evidence_id],
                    test_next="Compare memory limits by revision.",
                )
            ],
            recommendations=[
                Recommendation(
                    action="rollback_release",
                    rationale="Restore the last known-good revision.",
                    risk=Risk.HIGH,
                )
            ],
        ),
        evidence=[],
        tool_observations=[],
        model_provider="test",
    )


@mock_aws
def test_dynamodb_adapters_are_durable_idempotent_and_replay_safe() -> None:
    client = boto3.client("dynamodb", region_name="us-east-1")
    table_name = "sentinelops-test"
    create_table(client, table_name)

    incidents = DynamoDBIncidentStore(table_name, client)
    original = sample_report()
    conflicting = sample_report("A different duplicate payload")
    assert incidents.put_if_absent(original).signal.summary == "Pods are OOMKilled"
    assert incidents.put_if_absent(conflicting).signal.summary == "Pods are OOMKilled"
    assert incidents.get(original.incident_id) == original

    decision = ApprovalDecision(
        incident_id=original.incident_id,
        action="rollback_release",
        approved_by="oncall@example.com",
        approval_token="1700000000.secret-signature-value",  # noqa: S106 - synthetic token
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    approvals = DynamoDBApprovalStore(table_name, client)
    approvals.save(decision)
    replay = DynamoDBReplayStore(table_name, client)
    assert replay.consume(decision.approval_token, decision.expires_at) is True
    assert replay.consume(decision.approval_token, decision.expires_at) is False

    scan = client.scan(TableName=table_name)["Items"]
    serialized = repr(scan)
    assert decision.approval_token not in serialized
    assert hashlib.sha256(decision.approval_token.encode()).hexdigest() in serialized
    assert any("ttl_epoch" in item for item in scan if item["pk"]["S"].startswith("APPROVAL#"))
    assert (
        client.describe_time_to_live(TableName=table_name)["TimeToLiveDescription"]["AttributeName"]
        == "ttl_epoch"
    )

    audit = DynamoDBHashChainAuditLog(table_name, client)
    audit.append("incident.analyzed", "agent", {"incident_id": original.incident_id})
    audit.append("remediation.approved", "operator", {"incident_id": original.incident_id})
    assert audit.verify()
    assert len(audit.list_events()) == 2


@mock_aws
def test_s3_runbooks_require_matching_sha256_metadata() -> None:
    client = boto3.client("s3", region_name="us-east-1")
    bucket = "sentinelops-runbooks-test"
    client.create_bucket(Bucket=bucket)
    content = b"# CrashLoop\nOOMKilled after a deployment requires rollback review."
    checksum = hashlib.sha256(content).hexdigest()
    client.put_object(
        Bucket=bucket,
        Key="runbooks/crashloop.md",
        Body=content,
        Metadata={"sha256": checksum},
    )

    retriever = S3RunbookRetriever(bucket, client=client)
    results = retriever.search(
        IncidentSignal(
            source="test",
            title="CrashLoop",
            service="checkout-api",
            summary="OOMKilled after deployment",
        )
    )
    assert results[0].source == "crashloop.md"

    client.put_object(
        Bucket=bucket,
        Key="runbooks/tampered.md",
        Body=b"tampered",
        Metadata={"sha256": "0" * 64},
    )
    with pytest.raises(ValueError, match="checksum validation failed"):
        S3RunbookRetriever(bucket, client=client)
