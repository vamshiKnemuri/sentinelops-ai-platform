# ADR 0002: Provider-neutral LLM boundary

- Status: Accepted
- Date: 2026-09-18

## Context

The platform needs real Amazon Bedrock inference for an AWS demonstration and repeatable, credential-free behavior for testing. Coupling orchestration directly to one model API would make evaluation brittle and provider changes expensive.

## Decision

All model calls pass through a structured provider interface. The Amazon Bedrock adapter uses the Converse API. The deterministic adapter produces repeatable, schema-valid responses for local development and CI. Policy checks remain outside both providers.

## Consequences

- Tests do not depend on network access or model variability.
- Model providers can be evaluated against the same contract.
- The deterministic provider must never be represented as live AI inference.
- Provider-specific features are deliberately hidden unless added to the shared contract.
