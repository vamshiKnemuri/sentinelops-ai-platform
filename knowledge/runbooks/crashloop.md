# CrashLoopBackOff and OOMKilled

## Signals

- Pod restart count increases repeatedly.
- The prior container termination reason is `OOMKilled` or the process exits during startup.
- The incident begins shortly after a deployment or configuration change.

## Read-only investigation

1. Inspect pod status, previous termination reason, restart count, and warning events.
2. Compare deployment image, resource requests, limits, and environment variables with the prior revision.
3. Correlate memory working-set metrics with the configured limit.
4. Confirm whether all replicas or one node are affected.

## Safe response

If a new revision introduced the failure and the last revision is healthy, propose a rollback. A human must verify the diff and approve the rollback. Do not repeatedly restart an OOMKilled workload without correcting the cause.

## Verification

Confirm available replicas, restart-rate stabilization, error-rate recovery, and Argo CD synchronization.
