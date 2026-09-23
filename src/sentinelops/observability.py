from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

ATTRIBUTE_ALLOWLIST = {
    "action.name",
    "action.status",
    "ai.confidence_bucket",
    "ai.model",
    "ai.provider",
    "ai.status",
    "deployment.environment",
    "incident.id",
    "policy.outcome",
    "service.name",
    "tool.name",
}

_configured = False


def safe_attributes(**attributes: Any) -> dict[str, Any]:
    """Drop payloads and arbitrary labels before they reach trace exporters."""
    return {
        key: value
        for key, value in attributes.items()
        if key in ATTRIBUTE_ALLOWLIST and isinstance(value, str | bool | int | float)
    }


def configure_tracing(service_name: str = "sentinelops-ai") -> None:
    global _configured
    if _configured or os.getenv("OTEL_SDK_DISABLED", "false").lower() == "true":
        return
    current_provider = trace.get_tracer_provider()
    if isinstance(current_provider, TracerProvider):
        provider = current_provider
    else:
        provider = TracerProvider(
            resource=Resource.create(
                {
                    "service.name": service_name,
                    "deployment.environment": os.getenv("SENTINELOPS_ENVIRONMENT", "local"),
                }
            )
        )
        trace.set_tracer_provider(provider)
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    _configured = True


@contextmanager
def traced(name: str, **attributes: Any) -> Iterator[trace.Span]:
    tracer = trace.get_tracer("sentinelops")
    with tracer.start_as_current_span(name) as span:
        for key, value in safe_attributes(**attributes).items():
            span.set_attribute(key, value)
        yield span
