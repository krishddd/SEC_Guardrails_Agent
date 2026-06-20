"""T6 — OpenTelemetry setup (GenAI semconv).

Returns a tracer the gateway uses to span each request/rail decision. Degrades to None if
opentelemetry isn't installed, so the control plane runs without it (spans are then simply not
emitted). Tests pass an in-memory exporter to assert span emission.
"""

from __future__ import annotations

from typing import Any


def setup_tracing(
    exporter: Any | None = None, *, service_name: str = "sec-guardrails"
) -> Any | None:
    """Build a tracer backed by a fresh provider. If `exporter` is given, spans are exported to it
    synchronously (SimpleSpanProcessor) — convenient for tests. Returns None if OTel is unavailable.
    """
    try:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    except Exception:
        return None

    provider = TracerProvider()
    if exporter is not None:
        provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer(service_name)
