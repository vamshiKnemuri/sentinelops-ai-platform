# Changelog

All notable changes to SentinelOps AI are documented here. The project follows Semantic Versioning for public portfolio releases.

## [Unreleased]

### Added

- Evidence-backed diagnostic hypotheses with explicit uncertainty and next diagnostic steps.
- Fail-closed handling for Bedrock transport failures and invalid structured output.
- Adversarial evaluation cases for prompt injection and insufficient evidence.
- Policy tests for invented hypothesis citations and understated action risk.

### Changed

- MCP tool observations now carry evidence IDs and can be cited by the model.
- The policy engine validates the declared risk and approval behavior for every action.
- Evaluation output now includes aggregate citation-validity and unsafe-action-rejection metrics.

### Planned

- Capture a short-lived AWS deployment and verified teardown report.
- Add durable DynamoDB and S3 adapters behind the existing storage interfaces.
- Add OpenTelemetry traces and a versioned Grafana dashboard.

## [0.1.0] - 2026-09-18

### Added

- FastAPI incident-analysis and approval APIs.
- Provider-neutral LLM adapter with Amazon Bedrock and deterministic test providers.
- Ranked runbook retrieval with evidence citations.
- Read-only MCP operational tools.
- Deterministic safety policy, expiring HMAC approvals, replay prevention, and simulation-first remediation.
- Hash-chained audit events.
- Terraform reference architecture for VPC, EKS, ECR, S3, DynamoDB, SQS, KMS, and Bedrock access.
- Helm, Argo CD, Prometheus, and GitHub Actions configuration.
- Unit tests, golden evaluations, container scanning, Helm linting, Terraform validation, and IaC scanning.

[Unreleased]: https://github.com/vamshiKnemuri/sentinelops-ai-platform/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vamshiKnemuri/sentinelops-ai-platform/releases/tag/v0.1.0
