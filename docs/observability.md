# Observability and audit logging

The application emits sanitized structured logs. Infrastructure-provided ingress, pod, and container metrics remain available through the deployment platform; the application does not configure a telemetry exporter.

## Audit logging

Already-sanitized audit events are written directly through a dedicated `ILogger<AuditLogger>` category and the standard logging pipeline. There is no application audit queue, fan-out layer, custom sink interface, or background delivery service. Logging is best effort: a logging-provider failure never replaces the HTTP/MCP response or original tool error.

Every dispatched `k8s_get` call logs its result, including success, application-policy denial, Kubernetes/RBAC failure, timeout, cancellation, and internal failure. Application-owned authorization denials are logged without Kubernetes coordinates and without reading arbitrary MCP request bodies. Authentication failures remain the responsibility of ASP.NET Core and infrastructure access logs.

Each Kubernetes audit event includes UTC timestamp, client identity, authentication mode, GET/LIST operation, resource, namespace, optional name, result, object count when available, fixed error category, duration, and request ID. Untrusted string fields are length-bounded and have control characters replaced. Events exclude Kubernetes response bodies, Secret values and fingerprints, credentials, keys, tokens, arbitrary exception text, client IP addresses, and forwarded-header values.

Deployments needing durable, tamper-resistant retention should configure their standard logging infrastructure to retain and protect the `KubeMcp.Audit.AuditLogger` category.

See the [security model](security.md#audit-guarantees) for event contents and redaction guarantees.

## Client identity

Audit identity is derived without recording bearer credentials:

- Unauthenticated development mode: `anonymous`
- Static API key: `static-api-key`

Audit events retain the authenticated identity and request ID but do not record client IP addresses or forwarded-header values. The ingress, load balancer, or service mesh owns originating-client IP, external scheme, and external host logging.
