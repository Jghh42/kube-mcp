using System.Diagnostics;
using System.Diagnostics.Metrics;
using KubeMcp.Audit;

namespace KubeMcp.Observability;

/// <summary>
/// Low-cardinality application telemetry. Tag values are limited to fixed
/// operations, outcomes, status codes, and safe error categories. Resource names,
/// namespaces, object names, bodies, tokens, fingerprints, and arbitrary exception
/// text are never attached.
/// </summary>
public sealed class KubeMcpTelemetry : IDisposable
{
    public const string InstrumentationName = "KubeMcp";

    private readonly IHttpContextAccessor httpContextAccessor;
    private readonly Meter meter;
    private readonly ActivitySource activitySource;
    private readonly Counter<long> mcpRequests;
    private readonly Histogram<double> mcpRequestDuration;
    private readonly Counter<long> mcpDenials;
    private readonly Histogram<double> kubernetesDuration;
    private readonly Counter<long> kubernetesErrors;
    private readonly Histogram<long> responseSize;
    private readonly Histogram<long> listCount;
    private readonly Counter<long> secretGets;
    private readonly Counter<long> timeouts;

    public KubeMcpTelemetry(IHttpContextAccessor httpContextAccessor)
    {
        this.httpContextAccessor = httpContextAccessor;
        meter = new Meter(InstrumentationName);
        activitySource = new ActivitySource(InstrumentationName);
        mcpRequests = meter.CreateCounter<long>(
            "kube_mcp.mcp.requests",
            description: "MCP HTTP requests.");
        mcpRequestDuration = meter.CreateHistogram<double>(
            "kube_mcp.mcp.request.duration",
            unit: "s",
            description: "End-to-end MCP HTTP request duration.");
        mcpDenials = meter.CreateCounter<long>(
            "kube_mcp.mcp.denials",
            description: "MCP authentication, authorization, and concurrency denials.");
        kubernetesDuration = meter.CreateHistogram<double>(
            "kube_mcp.kubernetes.request.duration",
            unit: "s",
            description: "Kubernetes reader operation duration.");
        kubernetesErrors = meter.CreateCounter<long>(
            "kube_mcp.kubernetes.errors",
            description: "Kubernetes reader failures by safe category.");
        responseSize = meter.CreateHistogram<long>(
            "kube_mcp.response.size",
            unit: "By",
            description: "Safe MCP tool-content response size.");
        listCount = meter.CreateHistogram<long>(
            "kube_mcp.list.count",
            unit: "{object}",
            description: "Objects returned in a safe Kubernetes LIST response.");
        secretGets = meter.CreateCounter<long>(
            "kube_mcp.secret.gets",
            description: "Sanitized Kubernetes Secret GET responses.");
        timeouts = meter.CreateCounter<long>(
            "kube_mcp.timeouts",
            description: "Server-deadline and upstream Kubernetes timeouts.");
    }

    public Activity? StartMcpRequest()
    {
        // ASP.NET creates an ambient hosting activity even though generic ASP.NET
        // export is disabled. When a remote traceparent exists, make the curated
        // MCP span its direct child instead of exporting a generic server span
        // with caller-controlled URL/query/user-agent attributes.
        var hostingActivity = Activity.Current;
        if (hostingActivity is not null && hostingActivity.ParentSpanId != default)
        {
            var remoteParent = new ActivityContext(
                hostingActivity.TraceId,
                hostingActivity.ParentSpanId,
                hostingActivity.ActivityTraceFlags,
                traceState: null,
                isRemote: true);
            return activitySource.StartActivity("mcp.request", ActivityKind.Server, remoteParent);
        }

        // With no incoming parent, detach from the unexported ASP.NET hosting
        // activity so the default root sampler can create an exportable MCP span.
        // Keep the MCP span current for Kubernetes child-span correlation.
        Activity.Current = null;
        var rootActivity = activitySource.StartActivity(
            "mcp.request",
            ActivityKind.Server,
            default(ActivityContext));
        if (rootActivity is null)
        {
            Activity.Current = hostingActivity;
        }

        return rootActivity;
    }

    public Activity? StartKubernetesRequest(string operation)
    {
        var activity = activitySource.StartActivity("kubernetes.read", ActivityKind.Client);
        activity?.SetTag("kubernetes.operation", operation);
        return activity;
    }

    public void RecordMcpRequest(TimeSpan duration, int statusCode, string category)
    {
        var tags = new TagList
        {
            { "mcp.result", ResultFor(category) },
            { "mcp.error.category", category },
            { "http.response.status_code", statusCode }
        };
        mcpRequests.Add(1, tags);
        mcpRequestDuration.Record(duration.TotalSeconds, tags);

        if (category is AuditCategories.AuthenticationDenied or
            AuditCategories.AuthorizationDenied or
            AuditCategories.RateLimited)
        {
            mcpDenials.Add(1, new TagList { { "mcp.error.category", category } });
        }

        if (category == AuditCategories.ServerTimeout)
        {
            timeouts.Add(1, new TagList
            {
                { "timeout.scope", "mcp" },
                { "mcp.error.category", category }
            });
        }
    }

    public void RecordKubernetesRequest(
        string operation,
        TimeSpan duration,
        string category,
        int? responseBytes,
        int? objectCount,
        bool secretGet)
    {
        var tags = new TagList
        {
            { "kubernetes.operation", operation },
            { "mcp.result", ResultFor(category) },
            { "mcp.error.category", category }
        };
        kubernetesDuration.Record(duration.TotalSeconds, tags);

        if (category != AuditCategories.Success)
        {
            kubernetesErrors.Add(1, tags);
        }

        if (responseBytes is not null)
        {
            responseSize.Record(responseBytes.Value, new TagList
            {
                { "kubernetes.operation", operation },
                { "mcp.result", "success" }
            });
        }

        if (operation == "LIST" && objectCount is not null)
        {
            listCount.Record(objectCount.Value, new TagList { { "mcp.result", "success" } });
        }

        if (secretGet)
        {
            secretGets.Add(1, new TagList { { "mcp.result", "success" } });
        }

        if (category == "upstream_timeout")
        {
            timeouts.Add(1, new TagList
            {
                { "timeout.scope", "kubernetes" },
                { "mcp.error.category", category }
            });
        }
    }

    public void SetCurrentRequestCategory(string category)
    {
        var state = httpContextAccessor.HttpContext?.Features.Get<McpRequestState>();
        if (state is not null)
        {
            state.Category = category;
        }
    }

    internal static void CompleteActivity(Activity? activity, string category)
    {
        if (activity is null)
        {
            return;
        }

        activity.SetTag("mcp.result", ResultFor(category));
        activity.SetTag("mcp.error.category", category);
        activity.SetStatus(
            category == AuditCategories.Success ? ActivityStatusCode.Ok : ActivityStatusCode.Error);
    }

    private static string ResultFor(string category) => category switch
    {
        AuditCategories.Success => "success",
        AuditCategories.AuthenticationDenied or
        AuditCategories.AuthorizationDenied or
        AuditCategories.RateLimited => "denied",
        AuditCategories.ClientCancelled => "cancelled",
        AuditCategories.ServerTimeout or "upstream_timeout" => "timeout",
        _ => "error"
    };

    public void Dispose()
    {
        activitySource.Dispose();
        meter.Dispose();
    }
}

internal sealed class McpRequestState
{
    public string Category { get; set; } = AuditCategories.Success;
}
