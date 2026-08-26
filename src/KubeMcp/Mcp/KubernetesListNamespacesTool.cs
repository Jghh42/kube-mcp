using System.ComponentModel;
using System.Diagnostics;
using KubeMcp.Audit;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Http.Timeouts;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace KubeMcp.Mcp;

public sealed class KubernetesListNamespacesTool
{
    private readonly IKubernetesReader reader;
    private readonly IAuditLogger auditLogger;
    private readonly ILogger<KubernetesListNamespacesTool> logger;
    private readonly IHttpContextAccessor? httpContextAccessor;

    public KubernetesListNamespacesTool(
        IKubernetesReader reader,
        IAuditLogger auditLogger,
        ILogger<KubernetesListNamespacesTool> logger,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        this.reader = reader;
        this.auditLogger = auditLogger;
        this.logger = logger;
        this.httpContextAccessor = httpContextAccessor;
    }

    [McpServerTool(
        Name = "k8s_list_namespaces",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = false)]
    [Description("Lists a bounded snapshot of Kubernetes namespaces admitted by the server namespace policy.")]
    public async Task<string> ListAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = "failed";
        var category = AuditCategories.InternalError;
        int? objectCount = null;

        try
        {
            var response = await reader.ListNamespacesAsync(cancellationToken);
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

            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                "Kubernetes namespace LIST failed. Exception type: {ExceptionType}",
                exception.GetType().Name);
            throw new McpException(KubernetesErrorDetails.Get(KubernetesErrorCategory.Internal).Message);
        }
        finally
        {
            stopwatch.Stop();
            try
            {
                auditLogger.LogKubernetesAccess(new KubernetesAuditEvent(
                    "LIST",
                    "namespaces",
                    "-",
                    "-",
                    result,
                    objectCount,
                    stopwatch.Elapsed,
                    category));
            }
            catch (Exception exception)
            {
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
