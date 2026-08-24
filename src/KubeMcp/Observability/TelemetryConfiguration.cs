using KubeMcp.Configuration;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace KubeMcp.Observability;

internal static class TelemetryConfiguration
{
    public static IServiceCollection AddKubeMcpTelemetry(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddSingleton<KubeMcpTelemetry>();

        if (!configuration.GetValue<bool>(
                $"{KubeMcpOptions.SectionName}:Telemetry:Enabled"))
        {
            return services;
        }

        // AddOtlpExporter consumes the standard OTEL_EXPORTER_OTLP_ENDPOINT,
        // OTEL_EXPORTER_OTLP_PROTOCOL, OTEL_EXPORTER_OTLP_HEADERS, and timeout
        // variables used by organization-managed OpenTelemetry collectors.
        services.AddOpenTelemetry()
            .ConfigureResource(resource => resource.AddService("kube-mcp"))
            .WithMetrics(metrics => metrics
                .AddMeter(KubeMcpTelemetry.InstrumentationName)
                .AddOtlpExporter())
            .WithTracing(tracing => tracing
                // Export only the explicitly curated custom source. Generic
                // ASP.NET instrumentation is intentionally excluded because its
                // URL/query/user-agent attributes are caller-controlled. The MCP
                // middleware records no bodies or arbitrary exceptions.
                .AddSource(KubeMcpTelemetry.InstrumentationName)
                .AddOtlpExporter());

        return services;
    }
}
