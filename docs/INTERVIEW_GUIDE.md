# Interview Guide

## Thirty-second summary

I built SentinelOps AI to reduce Kubernetes incident investigation time without giving an LLM uncontrolled production access. Alerts are correlated with read-only MCP diagnostics and versioned runbooks, then Amazon Bedrock returns a structured, evidence-cited diagnosis. Deterministic policy validates every citation and action. Remediation requires an expiring approval bound to the incident and approver, and all decisions enter a tamper-evident audit chain.

## Senior-level decisions

- Separated probabilistic reasoning from deterministic authorization.
- Designed read-only tool identities independently from any mutation identity.
- Made insufficient evidence a first-class safe outcome.
- Added idempotency, replay protection, timeouts, failure isolation, and an audit chain.
- Evaluated retrieval, citation validity, action safety, latency, and model-change regressions.
- Used GitHub OIDC and EKS Pod Identity instead of long-lived cloud credentials.
- Kept the demo destroyable and tagged every resource for cost control.

## Tradeoffs

The local retriever is intentionally small and transparent. A production implementation would use an enterprise vector store and durable workflow engine, but those services add cost and obscure the safety mechanics in a portfolio demo. The simulated executor proves approval and replay controls without making a destructive action part of the demonstration.

## Questions to expect

- Why MCP instead of direct SDK calls?
- How do you defend against prompt injection in logs or runbooks?
- What happens when Bedrock or Prometheus is unavailable?
- How do you prevent hallucinated citations?
- Why is approval authorization outside the model?
- Which metrics gate a model or prompt release?
- How would you add Slack and ServiceNow while preserving identity and auditability?
