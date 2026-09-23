# Durable AWS Persistence

Local mode remains dependency-free and uses in-memory repositories. AWS mode is enabled by setting `SENTINELOPS_DYNAMODB_TABLE` and `SENTINELOPS_RUNBOOKS_BUCKET`; the guarded deployment workflow passes both values from Terraform into Helm.

## DynamoDB records

The table uses `pk` and `sk` keys so one encrypted table can hold isolated record types:

| Record | Partition key | Sort key | Write behavior |
|---|---|---|---|
| Incident | `INCIDENT#<id>` | `REPORT` | Conditional create for idempotency |
| Approval | `APPROVAL#<token-sha256>` | `DECISION` | Conditional create; raw token is never stored |
| Replay | `REPLAY#<token-sha256>` | `CONSUMED` | Conditional create gives cross-replica single use |
| Audit event | `AUDIT` | `EVENT#<sequence>` | Transactionally advances the hash-chain head |

Approval and replay records use the table TTL attribute `ttl_epoch`. Encryption, point-in-time recovery, and least-privilege pod-identity access are configured in Terraform.

## S3 runbooks

Terraform uploads each Markdown runbook with SHA-256 metadata. The runtime downloads versioned objects and refuses to index any object with a missing or mismatched checksum. Public access is blocked and objects use the project KMS key.

## Failure behavior

- A duplicate incident returns the existing report.
- A consumed approval token fails closed across every application replica.
- Concurrent audit writers use an optimistic transactional head update and retry bounded contention.
- Invalid S3 runbook content prevents the retriever from starting rather than silently indexing unverified guidance.
