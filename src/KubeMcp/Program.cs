using KubeMcp.Authentication;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using KubeMcp.Security;
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

if (app.Services.GetRequiredService<IOptions<KubeMcpOptions>>().Value.ResourcePolicy.Mode ==
    ResourcePolicyMode.AllowAll)
{
    app.Logger.LogWarning(
        "Resource policy AllowAll is enabled. Every namespaced Kubernetes resource supporting GET or LIST may be requested, subject to namespace policy and Kubernetes RBAC.");
}

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Ok(new
{
    service = "kube-mcp",
    status = "running"
}));
app.MapHealthChecks("/healthz");
app.MapHealthChecks("/readyz");
var mcpEndpoint = app.MapMcp("/mcp");
if (authenticationMode != AuthenticationMode.None)
{
    mcpEndpoint.RequireAuthorization(AuthenticationConfiguration.McpAccessPolicy);
}

app.Run();

// Exposes the generated Program type to the functional test project.
public partial class Program;
