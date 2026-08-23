var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHealthChecks();

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "kube-mcp",
    status = "running"
}));
app.MapHealthChecks("/healthz");
app.MapHealthChecks("/readyz");

app.Run();

// Exposes the generated Program type to the functional test project.
public partial class Program;
