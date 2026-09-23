from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Protocol

from botocore.exceptions import ClientError


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    occurred_at: str
    event_type: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


class AuditLog(Protocol):
    def append(self, event_type: str, actor: str, payload: dict[str, Any]) -> AuditEvent: ...

    def list_events(self) -> list[dict[str, Any]]: ...

    def verify(self) -> bool: ...


class HashChainAuditLog:
    """Append-only in-memory chain; production adapters persist events to DynamoDB."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = Lock()

    def append(self, event_type: str, actor: str, payload: dict[str, Any]) -> AuditEvent:
        with self._lock:
            previous_hash = self._events[-1].event_hash if self._events else "GENESIS"
            body = {
                "sequence": len(self._events) + 1,
                "occurred_at": datetime.now(UTC).isoformat(),
                "event_type": event_type,
                "actor": actor,
                "payload": payload,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            event = AuditEvent(**body, event_hash=event_hash)
            self._events.append(event)
            return event

    def list_events(self) -> list[dict[str, Any]]:
        return [asdict(event) for event in self._events]

    def verify(self) -> bool:
        previous_hash = "GENESIS"
        for event in self._events:
            body = asdict(event)
            event_hash = body.pop("event_hash")
            if body["previous_hash"] != previous_hash:
                return False
            expected_hash = hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if event_hash != expected_hash:
                return False
            previous_hash = event_hash
        return True


class DynamoDBHashChainAuditLog:
    """Hash-chained audit records with an optimistic, transactional head pointer."""

    def __init__(self, table_name: str, client=None, max_retries: int = 4) -> None:
        if client is None:
            import boto3

            client = boto3.client("dynamodb")
        self.client = client
        self.table_name = table_name
        self.max_retries = max_retries

    def _head(self) -> tuple[int, str]:
        response = self.client.get_item(
            TableName=self.table_name,
            Key={"pk": {"S": "AUDIT"}, "sk": {"S": "HEAD"}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not item:
            return 0, "GENESIS"
        return int(item["last_sequence"]["N"]), item["last_hash"]["S"]

    def append(self, event_type: str, actor: str, payload: dict[str, Any]) -> AuditEvent:
        for _ in range(self.max_retries):
            last_sequence, previous_hash = self._head()
            body = {
                "sequence": last_sequence + 1,
                "occurred_at": datetime.now(UTC).isoformat(),
                "event_type": event_type,
                "actor": actor,
                "payload": payload,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(
                json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            event = AuditEvent(**body, event_hash=event_hash)
            event_item = {
                "pk": {"S": "AUDIT"},
                "sk": {"S": f"EVENT#{event.sequence:020d}"},
                "document": {"S": json.dumps(asdict(event), sort_keys=True)},
                "record_type": {"S": "audit_event"},
            }
            head_update = {
                "TableName": self.table_name,
                "Key": {"pk": {"S": "AUDIT"}, "sk": {"S": "HEAD"}},
                "UpdateExpression": "SET last_sequence = :sequence, last_hash = :hash",
                "ExpressionAttributeValues": {
                    ":sequence": {"N": str(event.sequence)},
                    ":hash": {"S": event_hash},
                },
            }
            if last_sequence == 0:
                head_update["ConditionExpression"] = "attribute_not_exists(last_hash)"
            else:
                head_update["ConditionExpression"] = "last_hash = :previous_hash"
                head_update["ExpressionAttributeValues"][":previous_hash"] = {"S": previous_hash}
            try:
                self.client.transact_write_items(
                    TransactItems=[
                        {
                            "Put": {
                                "TableName": self.table_name,
                                "Item": event_item,
                                "ConditionExpression": "attribute_not_exists(pk)",
                            }
                        },
                        {"Update": head_update},
                    ]
                )
                return event
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "TransactionCanceledException":
                    raise
        raise RuntimeError("audit append contention exceeded retry limit")

    def list_events(self) -> list[dict[str, Any]]:
        request = {
            "TableName": self.table_name,
            "KeyConditionExpression": "pk = :pk AND begins_with(sk, :event)",
            "ExpressionAttributeValues": {
                ":pk": {"S": "AUDIT"},
                ":event": {"S": "EVENT#"},
            },
            "ConsistentRead": True,
        }
        events: list[dict[str, Any]] = []
        while True:
            response = self.client.query(**request)
            events.extend(json.loads(item["document"]["S"]) for item in response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                return events
            request["ExclusiveStartKey"] = last_key

    def verify(self) -> bool:
        previous_hash = "GENESIS"
        for event in self.list_events():
            event_hash = event.pop("event_hash")
            if event["previous_hash"] != previous_hash:
                return False
            expected_hash = hashlib.sha256(
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if event_hash != expected_hash:
                return False
            previous_hash = event_hash
        return True
