from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from sentinelops.models import IncidentSignal
from sentinelops.retrieval import RunbookRetriever
from sentinelops.tools import simulated_kubernetes_health

mcp = FastMCP("SentinelOps Diagnostics")


@mcp.tool()
def search_runbooks(query: str, service: str = "unknown") -> list[dict]:
    """Search versioned operational runbooks. This tool never changes infrastructure."""
    retriever = RunbookRetriever(os.getenv("SENTINELOPS_KNOWLEDGE_PATH", "knowledge/runbooks"))
    signal = IncidentSignal(
        source="mcp",
        title=query,
        service=service,
        summary=query,
    )
    return [item.model_dump() for item in retriever.search(signal)]


@mcp.tool()
def get_workload_health(service: str, namespace: str = "default") -> dict:
    """Read bounded workload-health metadata for one Kubernetes service."""
    signal = IncidentSignal(
        source="mcp",
        title="workload health",
        service=service,
        summary="read-only diagnostic request",
        labels={"namespace": namespace},
    )
    return simulated_kubernetes_health(signal).model_dump()


def run() -> None:
    mcp.run(transport="stdio")
