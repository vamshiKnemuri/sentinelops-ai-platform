# ADR 0003: Simulation-first execution

- Status: Accepted
- Date: 2026-09-18

## Context

A public portfolio project should demonstrate remediation controls without risking an unintended change to a real cluster or implying unsupported production readiness.

## Decision

The default and AWS portfolio modes use a simulated executor. It verifies the approved action, records the requested mutation, and returns a deterministic result without changing Kubernetes state. A real executor is intentionally outside the v0.1.0 scope.

## Consequences

- Demonstrations are safe and repeatable.
- The repository proves governance flow, not autonomous production mutation.
- A future real executor must have separate least-privilege credentials, integration tests, rollback behavior, and an additional architecture review.
