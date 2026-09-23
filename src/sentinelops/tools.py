from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from sentinelops.models import IncidentSignal, ToolObservation
from sentinelops.observability import traced


@dataclass(frozen=True)
class DiagnosticTool:
    name: str
    description: str
    read_only: bool
    handler: Callable[[IncidentSignal], ToolObservation]


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, DiagnosticTool] = {}

    def register(self, tool: DiagnosticTool) -> None:
        if not tool.read_only:
            raise ValueError("diagnostic tool registry accepts read-only tools only")
        self._tools[tool.name] = tool

    def run_all(self, signal: IncidentSignal) -> list[ToolObservation]:
        observations: list[ToolObservation] = []
        for tool in self._tools.values():
            try:
                with traced(
                    "sentinelops.tool.execute",
                    **{"tool.name": tool.name, "service.name": signal.service},
                ):
                    observations.append(tool.handler(signal))
            except Exception as exc:  # noqa: BLE001 - tool failures become bounded evidence
                observations.append(
                    ToolObservation(
                        evidence_id=f"tool:{tool.name}",
                        tool=tool.name,
                        summary="Tool was unavailable; analysis continued with remaining evidence.",
                        data={"error_type": type(exc).__name__},
                    )
                )
        return observations


def simulated_kubernetes_health(signal: IncidentSignal) -> ToolObservation:
    return ToolObservation(
        evidence_id="tool:kubernetes_workload_health",
        tool="kubernetes_workload_health",
        summary=f"Collected read-only workload health for {signal.service}.",
        data={"service": signal.service, "namespace": signal.labels.get("namespace", "default")},
    )


def prometheus_query_tool(base_url: str, expression: str, timeout_seconds: float = 3.0) -> dict:
    scheme = urllib.parse.urlsplit(base_url).scheme
    if scheme not in {"http", "https"}:
        raise ValueError("Prometheus URL must use http or https")
    query = urllib.parse.urlencode({"query": expression})
    request = urllib.request.Request(  # noqa: S310 - scheme is restricted above
        f"{base_url.rstrip('/')}/api/v1/query?{query}"
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
        payload = json.load(response)
    if payload.get("status") != "success":
        raise RuntimeError("Prometheus query did not succeed")
    return payload["data"]


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        DiagnosticTool(
            name="kubernetes_workload_health",
            description="Read pod status, restart counts, and recent warning events.",
            read_only=True,
            handler=simulated_kubernetes_health,
        )
    )
    return registry
