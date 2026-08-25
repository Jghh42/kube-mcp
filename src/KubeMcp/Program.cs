using KubeMcp.Audit;
using KubeMcp.Authentication;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using KubeMcp.Observability;
using KubeMcp.Security;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using ModelContextProtocol.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOptions<KubeMcpOptions>()
    .Bind(builder.Configuration.GetSection(KubeMcpOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();
builder.Services.AddSingleton<IValidateOptions<KubeMcpOptions>, KubeMcpOptionsValidator>();
var authenticationMode = builder.Services.AddKubeMcpAuthentication(builder.Configuration);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpContextAccessor();
// The default structured ILogger sink and any organization sinks are all invoked
// only by the bounded background dispatcher, never on request threads.
builder.Services.AddSingleton<StructuredLoggerAuditSink>();
builder.Services.AddSingleton<IAuditSink>(serviceProvider =>
    serviceProvider.GetRequiredService<StructuredLoggerAuditSink>());
builder.Services.AddSingleton<CompositeAuditSink>();
builder.Services.AddSingleton<AuditSinkDispatcher>();
builder.Services.AddSingleton<IAuditEventPublisher>(serviceProvider =>
    serviceProvider.GetRequiredService<AuditSinkDispatcher>());
builder.Services.AddHostedService(serviceProvider =>
    serviceProvider.GetRequiredService<AuditSinkDispatcher>());
builder.Services.AddSingleton<IAuditLogger, AuditLogger>();
builder.Services.AddKubeMcpTelemetry(builder.Configuration);
builder.Services.AddRequestTimeouts();
builder.Services.AddSingleton<IConfigureOptions<RequestTimeoutOptions>, McpRequestTimeoutOptionsSetup>();
builder.Services.AddSingleton<SecretFingerprinter>();
builder.Services.AddSingleton<SecretSanitizer>();
builder.Services.AddSingleton<KubernetesListSummarizer>();
builder.Services.AddSingleton<ResourceAllowlist>();
builder.Services.AddSingleton<NamespaceAccessPolicy>();
builder.Services.AddSingleton<IKubernetesClientFactory>(services =>
    new KubernetesClientFactory(
        services.GetRequiredService<IOptions<KubeMcpOptions>>().Value));
builder.Services.AddSingleton<IKubernetesReader, KubernetesReader>();
builder.Services.AddSingleton<KubernetesReadinessHealthCheck>();

builder.Services
    .AddMcpServer()
    .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
    .WithTools<KubernetesGetTool>();
builder.Services
    .AddHealthChecks()
    .AddCheck<KubernetesReadinessHealthCheck>(
        KubernetesReadinessHealthCheck.Name,
        failureStatus: HealthStatus.Unhealthy,
        tags: [KubernetesReadinessHealthCheck.Tag],
        timeout: KubernetesReadinessHealthCheck.Timeout);

var app = builder.Build();

var kubeMcpOptions = app.Services.GetRequiredService<IOptions<KubeMcpOptions>>().Value;

if (authenticationMode == AuthenticationMode.None)
{
    app.Logger.LogWarning(
        "Authentication is disabled (Mode=None). The MCP endpoint is reachable WITHOUT credentials. This mode is intended ONLY for isolated local development and must never be exposed to a shared or untrusted network. Set KubeMcp:Authentication:Mode to ApiKey for every non-development deployment.");
}

app.UseRouting();
// The application retains its end-to-end MCP deadline. HTTP body, header, rate,
// and concurrency limits belong at the private-network ingress or service mesh.
app.UseWhen(
    context => context.Request.Path.StartsWithSegments("/mcp"),
    branch =>
    {
        branch.UseRequestTimeouts();
        branch.UseMiddleware<McpRequestObservabilityMiddleware>();
    });

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Ok(new
{
    service = "kube-mcp",
    status = "running"
}));
app.MapHealthChecks("/healthz", new HealthCheckOptions
{
    // Liveness is intentionally process-only so a dependency outage cannot
    // trigger Kubernetes restarts.
    Predicate = static _ => false,
    ResponseWriter = WriteHealthStatusAsync
});
app.MapHealthChecks("/readyz", new HealthCheckOptions
{
    Predicate = static check => check.Tags.Contains(KubernetesReadinessHealthCheck.Tag),
    ResponseWriter = WriteHealthStatusAsync
});
var mcpEndpoint = app.MapMcp("/mcp")
    .WithRequestTimeout(McpRequestTimeoutOptionsSetup.PolicyName);
if (authenticationMode != AuthenticationMode.None)
{
    mcpEndpoint.RequireAuthorization(AuthenticationConfiguration.McpAccessPolicy);
}

app.Run();

static Task WriteHealthStatusAsync(HttpContext context, HealthReport report)
{
    context.Response.ContentType = "text/plain; charset=utf-8";
    return context.Response.WriteAsync(report.Status.ToString());
}

// Exposes the generated Program type to the functional test project.
public partial class Program;
