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

builder.Services.AddSingleton<SecretFingerprinter>();
builder.Services.AddSingleton<SecretSanitizer>();
builder.Services.AddSingleton<IKubernetesReader, KubernetesReader>();

builder.Services
    .AddMcpServer()
    .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
    .WithTools<KubernetesGetTool>();
builder.Services.AddHealthChecks();

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "kube-mcp",
    status = "running"
}));
app.MapHealthChecks("/healthz");
app.MapHealthChecks("/readyz");
app.MapMcp("/mcp");

app.Run();

// Exposes the generated Program type to the functional test project.
public partial class Program;
