from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    occurred_at: str
    event_type: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


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
