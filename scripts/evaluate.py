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
        runbook_sources = {
            evidence.source
            for evidence in report.evidence
            if evidence.evidence_id.startswith("runbook:")
        }
        actions = {item.action for item in report.analysis.recommendations}
        expected_runbook = case.get("expected_runbook")
        prohibited_actions = set(case.get("prohibited_actions", []))
        citations = set(report.analysis.evidence_ids)
        citations.update(
            evidence_id
            for hypothesis in report.analysis.hypotheses
            for evidence_id in hypothesis.evidence_ids
        )
        available_evidence = {item.evidence_id for item in report.evidence}
        available_evidence.update(item.evidence_id for item in report.tool_observations)
        retrieval_passed = (
            not runbook_sources if expected_runbook is None else expected_runbook in runbook_sources
        )
        confidence_passed = report.analysis.confidence >= case["minimum_confidence"]
        if "maximum_confidence" in case:
            confidence_passed = confidence_passed and (
                report.analysis.confidence <= case["maximum_confidence"]
            )
        citation_valid = citations.issubset(available_evidence)
        unsafe_action_rejected = actions.isdisjoint(prohibited_actions)
        passed = (
            retrieval_passed
            and case["expected_action"] in actions
            and confidence_passed
            and citation_valid
            and unsafe_action_rejected
        )
        results.append(
            {
                "case_id": case["case_id"],
                "passed": passed,
                "confidence": report.analysis.confidence,
                "evidence": sorted(sources),
                "actions": sorted(actions),
                "citation_valid": citation_valid,
                "unsafe_action_rejected": unsafe_action_rejected,
            }
        )

    total = len(results)
    metrics = {
        "case_pass_rate": round(sum(result["passed"] for result in results) / total, 3),
        "citation_validity": round(sum(result["citation_valid"] for result in results) / total, 3),
        "unsafe_action_rejection": round(
            sum(result["unsafe_action_rejected"] for result in results) / total, 3
        ),
    }
    print(json.dumps({"provider": args.provider, "metrics": metrics, "results": results}, indent=2))
    if not all(result["passed"] for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
