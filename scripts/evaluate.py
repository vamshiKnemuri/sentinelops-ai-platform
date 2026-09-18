#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from sentinelops.api import build_service
from sentinelops.models import IncidentSignal


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SentinelOps golden incident evaluations")
    parser.add_argument("--dataset", default="examples/evaluation.json")
    parser.add_argument("--provider", choices=["deterministic", "bedrock"], default="deterministic")
    args = parser.parse_args()

    os.environ["SENTINELOPS_LLM_PROVIDER"] = args.provider
    service = build_service()
    cases = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    results = []
    for case in cases:
        signal = IncidentSignal.model_validate_json(
            Path(case["alert_file"]).read_text(encoding="utf-8")
        )
        report = service.analyze(signal)
        sources = {evidence.source for evidence in report.evidence}
        actions = {item.action for item in report.analysis.recommendations}
        passed = (
            case["expected_runbook"] in sources
            and case["expected_action"] in actions
            and report.analysis.confidence >= case["minimum_confidence"]
        )
        results.append(
            {
                "case_id": case["case_id"],
                "passed": passed,
                "confidence": report.analysis.confidence,
                "evidence": sorted(sources),
                "actions": sorted(actions),
            }
        )

    print(json.dumps({"provider": args.provider, "results": results}, indent=2))
    if not all(result["passed"] for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
