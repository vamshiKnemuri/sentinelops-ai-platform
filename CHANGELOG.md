# Changelog

All notable changes to SentinelOps AI are documented here. The project follows Semantic Versioning for public portfolio releases.

## [Unreleased]

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
