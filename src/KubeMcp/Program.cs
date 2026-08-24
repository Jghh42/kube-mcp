using KubeMcp.Audit;
using KubeMcp.Authentication;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using KubeMcp.Observability;
using KubeMcp.Security;
using Microsoft.AspNetCore.Http.Timeouts;
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
builder.Services.AddSingleton<SecretFingerprinter>();
builder.Services.AddSingleton<SecretSanitizer>();
builder.Services.AddSingleton<KubernetesListSummarizer>();
builder.Services.AddSingleton<ResourceAllowlist>();
builder.Services.AddSingleton<NamespaceAccessPolicy>();
builder.Services.AddSingleton<IKubernetesReader, KubernetesReader>();

builder.Services
    .AddMcpServer()
    .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
    .WithTools<KubernetesGetTool>();
builder.Services.AddHealthChecks();

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

app.MapGet("/", () => Results.Ok(new
{
    service = "kube-mcp",
    status = "running"
}));
app.MapHealthChecks("/healthz");
app.MapHealthChecks("/readyz");
var mcpEndpoint = app.MapMcp("/mcp")
    .WithRequestTimeout(McpRequestTimeoutOptionsSetup.PolicyName);
if (authenticationMode != AuthenticationMode.None)
{
    mcpEndpoint.RequireAuthorization(AuthenticationConfiguration.McpAccessPolicy);
}

app.Run();

// Exposes the generated Program type to the functional test project.
public partial class Program;
