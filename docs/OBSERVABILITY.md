# Observability

SentinelOps exposes Prometheus metrics and manual OpenTelemetry spans across the complete control path: API receipt, runbook retrieval, diagnostic tools, model analysis, policy validation, approval, and simulated execution.

## Safe trace attributes

Trace attributes pass through a fixed allowlist. Permitted values describe control-plane behavior, such as incident ID, service name, model provider, action, policy outcome, and deployment environment. Alert summaries, runbook content, tool payloads, approval identities, tokens, and credentials are never exported.

Set an OTLP HTTP endpoint to enable export:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318/v1/traces
```

Without an endpoint, spans remain local and no network exporter is configured.

## Grafana

`observability/sentinelops-dashboard.json` is the versioned dashboard source. The AWS deploy workflow loads it through Grafana's dashboard sidecar. Panels cover analysis latency, incident rate, policy denials, approvals, remediation outcomes, and Bedrock token usage.

The project validator checks the dashboard UID, schema, unique panel IDs, panel queries, and the trace attribute allowlist during CI.
