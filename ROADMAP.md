# Roadmap

This roadmap separates implemented capability from planned engineering work. It is intentionally evidence-driven: an item moves to complete only when code, tests, and reproducible proof are committed.

## Completed for v0.1.0

- Structured incident analysis with cited runbook evidence.
- Provider-neutral LLM integration and deterministic offline evaluation.
- Read-only MCP tools with bounded inputs.
- Policy-gated remediation with human approval, expiration, and replay protection.
- Hash-chained audit events.
- EKS reference infrastructure, Helm packaging, Argo CD registration, and guarded deploy/destroy workflows.
- CI checks covering application behavior, AI safety, containers, Terraform, Helm, and IaC security.

## Next

The current `main` branch also includes the next decision-contract iteration: cited diagnostic hypotheses, explicit uncertainty, fail-closed model handling, and adversarial evaluation cases. These remain unreleased until the next version is tagged.

- Run the short-lived AWS demonstration and publish redacted deployment and teardown evidence.
- Add fault-injection and recovery-time evaluation scenarios.

## Completed on main after v0.1.0

- Durable DynamoDB incident, approval, replay, and transactional audit storage.
- Versioned S3 runbooks with SHA-256 ingestion validation.
- OpenTelemetry spans with an attribute allowlist and a versioned Grafana dashboard.

## Later

- Private EKS endpoint with self-hosted deployment runners.
- Slack or ServiceNow approval integration.
- Multi-account AWS landing-zone deployment.
- Signed container provenance and admission-policy enforcement.

See the public GitHub issues for acceptance criteria and progress.
