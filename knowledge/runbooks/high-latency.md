# High API Latency

## Signals

- P95 or P99 request latency exceeds the service objective.
- Error rate, queue depth, CPU throttling, connection saturation, or dependency latency may rise.

## Read-only investigation

1. Compare request rate, latency, and errors for the affected service.
2. Check CPU throttling, memory pressure, replica availability, and horizontal-pod-autoscaler state.
3. Correlate the start time with deployments and dependency latency.
4. Separate application saturation from downstream failure before proposing scale-out.

## Safe response

Scaling is appropriate only when evidence shows workload saturation and dependencies remain healthy. A deployment rollback may be safer when latency begins immediately after a release. Both actions require approval.

## Verification

Confirm latency returns below the objective without transferring errors or saturation to a dependency.
