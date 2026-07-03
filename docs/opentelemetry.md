# OpenTelemetry Instrumentation in Service Portal

This document describes how to configure and use **OpenTelemetry (OTel)** to capture and observe HTTP/HTTPS traffic through the Service Portal. 

Service Portal provides **built-in direct code-level OpenTelemetry instrumentation** (via the standard `otelhttp` library). With this direct integration, there is no need to use complex eBPF-based auto-instrumentation, which is limited in platform support and configuration.

---

## Code-Level Instrumentation

We provide built-in optional OpenTelemetry instrumentation utilizing `otelhttp` on the server and client transports. When enabled, this extracts trace contexts from incoming HTTP requests, starts a trace span for the proxy, propagates tracing headers (W3C Trace Context), and creates child spans for outgoing backend/upstream requests.

### Configuration

To enable the built-in OTel instrumentation, set the following environment variable on your Service Portal container:

```yaml
env:
- name: OTEL_INSTRUMENTATION_ENABLED
  value: "true"
```

### How It Works

1. **Server-Side Integration:** The incoming HTTP/HTTPS request handler is wrapped with `otelhttp.NewHandler`. It reads the standard `traceparent` and `baggage` headers from incoming requests to extract the parent span context.
2. **Client-Side Integration:** The outgoing proxy transport is wrapped with `otelhttp.NewTransport`. It injects the trace context headers into the request forwarded to the upstream API (e.g., Gemini or Anthropic endpoints), allowing end-to-end distributed tracing.
3. **Caching Integration:** If `CACHE_TTL` is enabled, the cache lookup happens before the outgoing request is initiated. On a cache hit, no outgoing client span is generated, which accurately reflects that no network request was made.

---

## Standard OpenTelemetry Environment Variables

When using built-in OpenTelemetry instrumentation (`OTEL_INSTRUMENTATION_ENABLED=true`), you can configure tracing using the standard OpenTelemetry environment variables:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `OTEL_SERVICE_NAME` | The name of the service shown in trace spans. | `service-portal` |
| `OTEL_TRACES_EXPORTER` | Tracing exporter to use. | `otlp` or `none` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | The OTLP receiver endpoint (collector). | `http://otel-collector.monitoring.svc:4317` |
| `OTEL_PROPAGATORS` | Text map propagators to use. | `tracecontext,baggage` |

For more details on standard OTel configuration, refer to the [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).
