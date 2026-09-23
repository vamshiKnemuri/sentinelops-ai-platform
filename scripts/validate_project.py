#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "Dockerfile",
    "src/sentinelops/api.py",
    "src/sentinelops/llm.py",
    "src/sentinelops/mcp_server.py",
    "src/sentinelops/policy.py",
    "src/sentinelops/remediation.py",
    "src/sentinelops/observability.py",
    "docs/PERSISTENCE.md",
    "docs/OBSERVABILITY.md",
    "observability/sentinelops-dashboard.json",
    "knowledge/runbooks/crashloop.md",
    "infrastructure/terraform/main.tf",
    "platform/chart/templates/deployment.yaml",
    "gitops/applications/sentinelops.yaml.tpl",
    ".github/workflows/ci.yml",
    ".github/workflows/deploy-demo.yml",
    ".github/workflows/destroy-demo.yml",
]

YAML_FILES = [
    "compose.yaml",
    "platform/chart/Chart.yaml",
    "platform/chart/values.yaml",
    "observability/kube-prometheus-values.yaml",
    ".github/workflows/ci.yml",
    ".github/workflows/deploy-demo.yml",
    ".github/workflows/destroy-demo.yml",
]

SECRET_PATTERNS = {
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
}


class CloudFormationLoader(yaml.SafeLoader):
    pass


def cloudformation_tag(loader: CloudFormationLoader, tag_suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node)}
    return {tag_suffix: loader.construct_mapping(node)}


CloudFormationLoader.add_multi_constructor("!", cloudformation_tag)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    if missing:
        fail(f"required files are missing: {', '.join(missing)}")

    for relative in YAML_FILES:
        try:
            yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            fail(f"invalid YAML in {relative}: {exc}")

    bootstrap = yaml.load(  # noqa: S506 - loader subclasses SafeLoader for CFN tags
        (ROOT / "bootstrap/aws-oidc-role.yaml").read_text(encoding="utf-8"),
        Loader=CloudFormationLoader,  # noqa: S506 - this subclasses yaml.SafeLoader
    )
    required_bootstrap = {"GitHubOIDCProvider", "TerraformStateBucket", "GitHubDeployRole"}
    if not required_bootstrap.issubset(bootstrap["Resources"]):
        fail("CloudFormation bootstrap is missing required resources")

    evaluation = json.loads((ROOT / "examples/evaluation.json").read_text(encoding="utf-8"))
    if len(evaluation) < 4 or not all(
        {"case_id", "alert_file", "expected_action", "prohibited_actions"}.issubset(case)
        for case in evaluation
    ):
        fail("golden evaluation dataset is incomplete")

    dashboard = json.loads(
        (ROOT / "observability/sentinelops-dashboard.json").read_text(encoding="utf-8")
    )
    panels = dashboard.get("panels", [])
    panel_ids = [panel.get("id") for panel in panels]
    if dashboard.get("uid") != "sentinelops-ai" or len(panels) < 6:
        fail("Grafana dashboard is missing its stable UID or required panels")
    if len(panel_ids) != len(set(panel_ids)):
        fail("Grafana dashboard contains duplicate panel IDs")
    if not all(target.get("expr") for panel in panels for target in panel.get("targets", [])):
        fail("Grafana dashboard contains a target without a Prometheus expression")

    observability = (ROOT / "src/sentinelops/observability.py").read_text(encoding="utf-8")
    for forbidden_attribute in ["alert.summary", "approval.token", "aws.access_key"]:
        if f'"{forbidden_attribute}",' in observability:
            fail(f"unsafe trace attribute is allowlisted: {forbidden_attribute}")

    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in ROOT.rglob("*")
        if path.is_file() and not any(part.startswith(".") for part in path.relative_to(ROOT).parts)
    )
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(combined):
            fail(f"possible {name} detected")

    deployment = (ROOT / "platform/chart/templates/deployment.yaml").read_text()
    for control in ["runAsNonRoot: true", "readOnlyRootFilesystem: true", 'drop: ["ALL"]']:
        if control not in deployment:
            fail(f"Kubernetes deployment is missing control: {control}")

    print(
        f"Validated {len(REQUIRED_FILES)} required files, {len(YAML_FILES)} YAML files, "
        "CloudFormation structure, evaluation data, dashboard structure, trace attributes, "
        "secret patterns, and workload controls."
    )


if __name__ == "__main__":
    main()
