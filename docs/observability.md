# Observability and audit logging

## OpenTelemetry

Set the following to export custom MCP and Kubernetes metrics and traces over OTLP:

```text
KubeMcp__Telemetry__Enabled=true
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.example.internal:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer <collector credential>
```

`http/protobuf` is also supported through `OTEL_EXPORTER_OTLP_PROTOCOL`. Keep exporter credentials in the deployment's secret-management system.

Custom instruments cover:

- MCP request count, duration, and denials
- Kubernetes duration and errors
- safe tool-content response size
- LIST object count
- sanitized Secret GET count
- server and upstream timeouts

Only curated spans at the `/mcp` middleware and Kubernetes tool boundary are exported. Generic ASP.NET URL, query, and user-agent spans are not exported. Request and response bodies and arbitrary exception events are not recorded.

Metrics and spans use fixed operations, outcomes, HTTP status codes, and safe error categories. They do not tag Kubernetes names, namespaces, request or response bodies, tokens, Secret fingerprints, or arbitrary exception text.

## Audit logging

The structured `ILogger` audit sink is enabled by default. Additional organization-specific sinks can implement `IAuditSink` and be composed with it.

All sinks run behind a bounded, non-blocking, best-effort dispatcher rather than on request threads:

- The queue holds 1,024 records and drops the newest record when full.
- `AuditQueueFull` reports aggregate local drops every 30 seconds from a separate background loop.
- `CompositeAuditSink` invokes sinks sequentially with a two-second deadline per sink.
- Sink exceptions and deadlines do not prevent later sinks from running.
- A sink that ignores cancellation may have at most one outstanding invocation; later records skip it until it completes.
- Sink failures never replace the HTTP/MCP response or the original tool error.
- Graceful shutdown drains the queue within the host shutdown window; cancellation can leave records undelivered.

Deployments needing durable, tamper-resistant retention should register an appropriate audit provider and alert on sink failures, deadlines, and queue drops.

See the [security model](security.md#audit-guarantees) for event contents and redaction guarantees.

## Client identity

Audit identity is derived without recording bearer credentials:

- Unauthenticated development mode: `anonymous`
- Static API key: `static-api-key`

When a request arrives through a configured trusted proxy, the audit event records the forwarded originating client IP. Forwarded values from untrusted peers are ignored.
