# ADR 0004: Use an evidence-first AI decision contract

- Status: Accepted
- Date: 2026-09-23

## Context

A single diagnosis string can look convincing while hiding unsupported assumptions. Model outages and malformed output also need a safe operational result rather than an unhandled API error.

## Decision

The provider must return a versioned structured contract containing a diagnosis, bounded confidence, cited hypotheses, explicit uncertainty, verification steps, and allowlisted recommendations. Deterministic policy validates every citation, action, declared risk, and approval requirement.

Provider transport or schema failures are converted into a degraded analysis with zero confidence and one permitted outcome: escalation to a human. The failure is recorded in the audit chain without storing raw provider errors.

## Consequences

- Responders can see what evidence supports each hypothesis and what to test next.
- Provider changes can be evaluated against stable safety invariants.
- Model failures preserve API availability without creating false operational confidence.
- Adding fields requires coordinated prompt, schema, policy, and evaluation changes.
