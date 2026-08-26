using KubeMcp.Audit;
using KubeMcp.Authentication;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
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
builder.Services.AddSingleton<IAuditLogger, AuditLogger>();
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

builder.Services
    .AddMcpServer()
    .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
    .WithTools<KubernetesGetTool>()
    .WithTools<KubernetesListNamespacesTool>();

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
        branch.UseMiddleware<McpAccessAuditMiddleware>();
    });

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Ok(new
{
    service = "kube-mcp",
    status = "running"
}));
// Both public probe endpoints are deliberately process-only and opaque. Startup
// option validation completes before the application can serve either route.
app.MapGet("/healthz", static () => Results.Text("Healthy"));
app.MapGet("/readyz", static () => Results.Text("Ready"));
var mcpEndpoint = app.MapMcp("/mcp")
    .WithRequestTimeout(McpRequestTimeoutOptionsSetup.PolicyName);
if (authenticationMode != AuthenticationMode.None)
{
    mcpEndpoint.RequireAuthorization(AuthenticationConfiguration.McpAccessPolicy);
}

app.Run();

// Exposes the generated Program type to the functional test project.
public partial class Program;
