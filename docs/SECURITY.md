# Security and AI Safety

## Primary risks

1. Prompt injection inside alerts, logs, or runbooks.
2. Hallucinated evidence or unsafe remediation.
3. Over-privileged Kubernetes and AWS identities.
4. Approval replay or action substitution.
5. Leakage of secrets through prompts, logs, or model responses.
6. Model or diagnostic-tool outages during an incident.

## Controls

- The system prompt defines retrieved content as untrusted data.
- The model receives only bounded evidence and read-only observations.
- Output is parsed into a strict schema and citations on both the diagnosis and hypotheses are checked.
- Only four action types are recognized; declared action risk must match policy and mutating proposals always require approval.
- Approval tokens are signed, expire, and bind the incident, action, and approver.
- Real execution is disabled by default and uses a separate identity when enabled.
- Secrets and raw credentials are excluded from prompts and audit payloads.
- Provider failures and invalid model output become an audited, non-mutating human escalation.
- Every accepted model decision records provider, confidence, citations, and audit hash.
- DynamoDB conditional writes prevent incident duplication and approval-token replay across replicas.
- S3 runbooks require a matching SHA-256 object metadata value before indexing.
- OpenTelemetry attributes use a fixed allowlist; alert text, runbook content, identities, tokens, and credentials are excluded.

## Production hardening

- Replace the HMAC demo signer with enterprise identity and a KMS-backed signing workflow.
- Archive DynamoDB audit events to an S3 Object Lock retention bucket.
- Use private cluster endpoints and controlled runners.
- Add Bedrock Guardrails for sensitive-information filters and denied topics.
- Apply NetworkPolicy, Pod Security Standards, image signing, admission policy, and egress controls.
- Red-team alert, log, and runbook content before enabling any real executor.

## Responsible claim

SentinelOps assists responders; it does not replace incident command. The portfolio demonstration must show both a successful recommendation and a denied unsafe or insufficiently evidenced request.
