# Observability and audit logging

The application emits sanitized structured logs and audit records. Infrastructure-provided ingress, pod, and container metrics remain available through the deployment platform; the application does not configure a telemetry exporter.

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

Audit events retain the authenticated identity and request ID but do not record client IP addresses or forwarded-header values. The ingress, load balancer, or service mesh owns originating-client IP, external scheme, and external host logging.
