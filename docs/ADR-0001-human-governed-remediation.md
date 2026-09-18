# ADR 0001: Human-governed remediation

- Status: Accepted
- Date: 2026-09-18

## Context

An LLM can summarize evidence and propose an operational response, but model output is probabilistic and may be affected by incomplete signals, retrieval errors, or prompt injection. Direct cluster mutation would give that probabilistic component an unsafe authority boundary.

## Decision

The model may propose only allowlisted remediation types. A deterministic policy validates evidence, confidence, and parameters. Any mutation then requires a short-lived HMAC approval tied to the incident, exact action, approver, and expiry. An approval is single-use and every transition enters the hash-chained audit log.

## Consequences

- The LLM cannot directly change Kubernetes resources.
- Operators retain accountability and can inspect evidence before approval.
- The workflow adds latency compared with autonomous remediation.
- Approval identity and signing-key management become production responsibilities.
