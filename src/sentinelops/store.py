from __future__ import annotations

import hashlib
import time
from datetime import datetime
from threading import Lock
from typing import Protocol

from botocore.exceptions import ClientError

from sentinelops.models import ApprovalDecision, IncidentReport


class IncidentRepository(Protocol):
    def put_if_absent(self, report: IncidentReport) -> IncidentReport: ...

    def get(self, incident_id: str) -> IncidentReport | None: ...


class ReplayStore(Protocol):
    def consume(self, token: str, expires_at: datetime) -> bool: ...


class ApprovalRepository(Protocol):
    def save(self, decision: ApprovalDecision) -> None: ...


class IncidentStore:
    def __init__(self) -> None:
        self._reports: dict[str, IncidentReport] = {}
        self._lock = Lock()

    def put_if_absent(self, report: IncidentReport) -> IncidentReport:
        with self._lock:
            return self._reports.setdefault(report.incident_id, report)

    def get(self, incident_id: str) -> IncidentReport | None:
        return self._reports.get(incident_id)


class InMemoryReplayStore:
    def __init__(self) -> None:
        self._used_tokens: set[str] = set()
        self._lock = Lock()

    def consume(self, token: str, expires_at: datetime) -> bool:
        del expires_at
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            if token_hash in self._used_tokens:
                return False
            self._used_tokens.add(token_hash)
            return True


class InMemoryApprovalStore:
    def __init__(self) -> None:
        self._decisions: dict[str, ApprovalDecision] = {}
        self._lock = Lock()

    def save(self, decision: ApprovalDecision) -> None:
        token_hash = hashlib.sha256(decision.approval_token.encode()).hexdigest()
        with self._lock:
            self._decisions[token_hash] = decision


class DynamoDBIncidentStore:
    def __init__(self, table_name: str, client=None) -> None:
        if client is None:
            import boto3

            client = boto3.client("dynamodb")
        self.client = client
        self.table_name = table_name

    @staticmethod
    def _key(incident_id: str) -> dict:
        return {"pk": {"S": f"INCIDENT#{incident_id}"}, "sk": {"S": "REPORT"}}

    def put_if_absent(self, report: IncidentReport) -> IncidentReport:
        item = {
            **self._key(report.incident_id),
            "document": {"S": report.model_dump_json()},
            "record_type": {"S": "incident"},
        }
        try:
            self.client.put_item(
                TableName=self.table_name,
                Item=item,
                ConditionExpression="attribute_not_exists(pk)",
            )
            return report
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            existing = self.get(report.incident_id)
            if existing is None:
                raise RuntimeError(
                    "conditional incident write failed without an existing record"
                ) from exc
            return existing

    def get(self, incident_id: str) -> IncidentReport | None:
        response = self.client.get_item(
            TableName=self.table_name,
            Key=self._key(incident_id),
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not item:
            return None
        return IncidentReport.model_validate_json(item["document"]["S"])


class DynamoDBApprovalStore:
    def __init__(self, table_name: str, client=None) -> None:
        if client is None:
            import boto3

            client = boto3.client("dynamodb")
        self.client = client
        self.table_name = table_name

    def save(self, decision: ApprovalDecision) -> None:
        token_hash = hashlib.sha256(decision.approval_token.encode()).hexdigest()
        try:
            self.client.put_item(
                TableName=self.table_name,
                Item={
                    "pk": {"S": f"APPROVAL#{token_hash}"},
                    "sk": {"S": "DECISION"},
                    "incident_id": {"S": decision.incident_id},
                    "action": {"S": decision.action},
                    "approved_by": {"S": decision.approved_by},
                    "ttl_epoch": {"N": str(int(decision.expires_at.timestamp()))},
                    "record_type": {"S": "approval"},
                },
                ConditionExpression="attribute_not_exists(pk)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise


class DynamoDBReplayStore:
    def __init__(self, table_name: str, client=None) -> None:
        if client is None:
            import boto3

            client = boto3.client("dynamodb")
        self.client = client
        self.table_name = table_name

    def consume(self, token: str, expires_at: datetime) -> bool:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            self.client.put_item(
                TableName=self.table_name,
                Item={
                    "pk": {"S": f"REPLAY#{token_hash}"},
                    "sk": {"S": "CONSUMED"},
                    "consumed_at": {"N": str(int(time.time()))},
                    "ttl_epoch": {"N": str(int(expires_at.timestamp()))},
                    "record_type": {"S": "approval_replay"},
                },
                ConditionExpression="attribute_not_exists(pk)",
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise
