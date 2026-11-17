using System.ComponentModel;
using System.Diagnostics;
using KubeMcp.Audit;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Http.Timeouts;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace KubeMcp.Mcp;

public sealed class KubernetesTools
{
    private readonly IKubernetesReader reader;
    private readonly IAuditLogger auditLogger;
    private readonly ILogger<KubernetesTools> logger;
    private readonly IHttpContextAccessor? httpContextAccessor;

    public KubernetesTools(
        IKubernetesReader reader,
        IAuditLogger auditLogger,
        ILogger<KubernetesTools> logger,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        this.reader = reader;
        this.auditLogger = auditLogger;
        this.logger = logger;
        this.httpContextAccessor = httpContextAccessor;
    }

    [McpServerTool(
        Name = "k8s_get",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = false)]
    [Description("Gets one namespaced Kubernetes resource, or lists compact resource summaries when name is omitted.")]
    public Task<string> GetAsync(
        [Description("Configured Kubernetes resource name from the server allowlist.")]
        string resource,
        [Description("Kubernetes namespace. All-namespace requests are not supported.")]
        string @namespace,
        [Description("Optional object name. Omit it to list resources in the namespace.")]
        string? name = null,
        CancellationToken cancellationToken = default) =>
        // Never copy an oversized caller-controlled resource into audit records.
        // The reader rejects it before resolving the explicit resource mapping.
        RunAsync(
            name is null ? "LIST" : "GET",
            KubernetesNameValidator.BoundedResourceForDiagnostics(resource),
            @namespace,
            name,
            () => reader.ReadAsync(resource, @namespace, name, cancellationToken),
            cancellationToken);

    [McpServerTool(
        Name = "k8s_list_namespaces",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = false)]
    [Description("Lists a bounded snapshot of Kubernetes namespaces admitted by the server namespace policy.")]
    public Task<string> ListAsync(CancellationToken cancellationToken = default) =>
        RunAsync(
            "LIST",
            "namespaces",
            "-",
            "-",
            () => reader.ListNamespacesAsync(cancellationToken),
            cancellationToken);

    private async Task<string> RunAsync(
        string operation,
        string resource,
        string @namespace,
        string? name,
        Func<Task<KubernetesReadResult>> read,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = "failed";
        var category = AuditCategories.InternalError;
        int? objectCount = null;

        try
        {
            var response = await read();
            result = "success";
            category = AuditCategories.Success;
            objectCount = response.ObjectCount;
            return response.Json;
        }
        catch (KubernetesReadException exception)
        {
            var safeError = KubernetesErrorDetails.Get(exception.Category);
            category = safeError.Category;
            throw new McpException(safeError.Message);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (IsServerDeadlineExpired())
            {
                result = "timeout";
                category = AuditCategories.ServerTimeout;
            }
            else
            {
                result = "cancelled";
                category = AuditCategories.ClientCancelled;
            }

            // Preserve cancellation propagation. ASP.NET's request-timeout
            // middleware writes its configured 504 when the response has not
            // started; Streamable HTTP may already be streaming, in which case
            // cancellation safely terminates it. Caller cancellation remains an
            // OperationCanceledException.
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                "Kubernetes {Operation} failed. Exception type: {ExceptionType}",
                operation,
                exception.GetType().Name);
            throw new McpException(KubernetesErrorDetails.Get(KubernetesErrorCategory.Internal).Message);
        }
        finally
        {
            stopwatch.Stop();

            try
            {
                auditLogger.LogKubernetesAccess(new KubernetesAuditEvent(
                    operation,
                    resource,
                    @namespace,
                    name,
                    result,
                    objectCount,
                    stopwatch.Elapsed,
                    category));
            }
            catch (Exception exception)
            {
                // A custom audit implementation must not replace the tool response
                // or hide the original failure. Do not include provider details.
                logger.LogWarning(
                    "Kubernetes audit publication failed with exception type {ExceptionType}.",
                    exception.GetType().Name);
            }
        }
    }

    private bool IsServerDeadlineExpired() =>
        httpContextAccessor?.HttpContext?.Features
            .Get<IHttpRequestTimeoutFeature>()?
            .RequestTimeoutToken.IsCancellationRequested == true;
}
