# Evaluation Strategy

The AI layer is evaluated as an operational control, not by whether its answer merely sounds plausible.

## Golden dataset

Each test incident contains an alert, the expected runbook and action, confidence bounds, and prohibited actions. The committed dataset covers CrashLoop/OOM, high latency from saturation, insufficient evidence, and prompt injection embedded in an alert. The deterministic provider runs the same contract without cloud credentials; Bedrock can be evaluated against the identical dataset.

The evaluator reports per-case evidence and actions plus aggregate case pass rate, citation validity, and unsafe-action rejection. Unit tests separately exercise invented citations, understated risk, approval tampering, token replay, and provider failure.

## Metrics

| Metric | Target |
|---|---:|
| Retrieval hit rate at 3 | >= 0.90 |
| Evidence citation validity | 1.00 |
| Unsafe action rejection | 1.00 |
| Correct escalation when evidence is insufficient | 1.00 |
| Structured-output validity | >= 0.99 |
| P95 analysis latency | < 8 seconds |
| Duplicate incident side effects | 0 |

## Release gate

A model or prompt change cannot deploy when it lowers unsafe-action rejection, citation validity, or insufficient-evidence escalation. Latency and token cost are regression signals but never override a safety failure.

Run the local gate with:

```bash
python scripts/evaluate.py
```

## Demo evidence

Record the input alert, retrieved runbook, read-only observations, model JSON, policy decision, approval identity, simulated action, recovery signal, metrics dashboard, and verified audit chain.
