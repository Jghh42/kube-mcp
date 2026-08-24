using KubeMcp.Audit;
using KubeMcp.Authentication;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using KubeMcp.Observability;
using KubeMcp.Security;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.RateLimiting;
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
// Structured ILogger audit output is the immediate best-effort default. Any
// additional IAuditSink registrations are fanned out through the bounded queue.
builder.Services.AddSingleton<StructuredLoggerAuditSink>();
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
builder.Services.AddRateLimiter();
builder.Services.AddSingleton<IConfigureOptions<RateLimiterOptions>, McpConcurrencyRateLimiterOptionsSetup>();
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

if (kubeMcpOptions.ResourcePolicy.Mode == ResourcePolicyMode.AllowAll)
{
    app.Logger.LogWarning(
        "Resource policy AllowAll is enabled. Every namespaced Kubernetes resource supporting GET or LIST may be requested, subject to namespace policy and Kubernetes RBAC.");
}

if (authenticationMode == AuthenticationMode.None)
{
    app.Logger.LogWarning(
        "Authentication is disabled (Mode=None). The MCP endpoint is reachable WITHOUT credentials. This mode is intended ONLY for isolated local development and must never be exposed to a shared or untrusted network. Set KubeMcp:Authentication:Mode to ApiKey or OAuthClientCredentials for any non-development deployment.");
}

// Honor forwarded headers only from explicitly configured, known proxies/networks
// (and loopback) before authentication and audit handling. This lets audit
// records observe the originating client IP and forwarded-host validation sees
// the production hostname behind a trusted proxy without trusting every proxy.
var forwardedHeadersOptions = new ForwardedHeadersOptions();
ForwardedHeadersConfiguration.Apply(
    kubeMcpOptions.ForwardedHeaders,
    forwardedHeadersOptions,
    builder.Configuration["AllowedHosts"]);
app.UseForwardedHeaders(forwardedHeadersOptions);

app.UseRouting();
// The end-to-end deadline is deliberately scoped to the MCP branch. Health,
// readiness, and root responses are not governed by the MCP timeout policy.
app.UseWhen(
    context => context.Request.Path.StartsWithSegments("/mcp"),
    branch =>
    {
        branch.UseRequestTimeouts();
        branch.UseMiddleware<McpRequestObservabilityMiddleware>();
    });

app.UseAuthentication();
app.UseAuthorization();
// Limit only endpoint-selected MCP requests, after authentication and
// authorization. Invalid credentials cannot occupy the process-wide queue or
// permits; health/readiness/root endpoints do not carry limiter metadata.
app.UseRateLimiter();

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
    .WithRequestTimeout(McpRequestTimeoutOptionsSetup.PolicyName)
    .RequireRateLimiting(McpConcurrencyRateLimiterOptionsSetup.PolicyName);
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
