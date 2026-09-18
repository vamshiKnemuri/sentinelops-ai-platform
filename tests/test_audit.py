from sentinelops.audit import HashChainAuditLog


def test_audit_chain_verifies() -> None:
    audit = HashChainAuditLog()
    audit.append("incident.received", "alertmanager", {"incident_id": "inc-1"})
    audit.append("incident.analyzed", "agent", {"incident_id": "inc-1"})

    assert audit.verify()
    assert audit.list_events()[1]["previous_hash"] == audit.list_events()[0]["event_hash"]
