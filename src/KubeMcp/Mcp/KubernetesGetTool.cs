using System.ComponentModel;
using System.Diagnostics;
using KubeMcp.Audit;
using KubeMcp.Kubernetes;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace KubeMcp.Mcp;

public sealed class KubernetesGetTool(
    IKubernetesReader reader,
    IAuditLogger auditLogger,
    ILogger<KubernetesGetTool> logger)
{
    [McpServerTool(
        Name = "k8s_get",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = false)]
    [Description("Gets one namespaced Kubernetes resource, or lists compact resource summaries when name is omitted.")]
    public async Task<string> GetAsync(
        [Description("Configured Kubernetes resource name from the server allowlist.")]
        string resource,
        [Description("Kubernetes namespace. All-namespace requests are not supported.")]
        string @namespace,
        [Description("Optional object name. Omit it to list resources in the namespace.")]
        string? name = null,
        CancellationToken cancellationToken = default)
    {
        var operation = name is null ? "LIST" : "GET";
        var stopwatch = Stopwatch.StartNew();
        var result = "failed";
        int? objectCount = null;

        try
        {
            var response = await reader.ReadAsync(resource, @namespace, name, cancellationToken);
            result = "success";
            objectCount = response.ObjectCount;
            return response.Json;
        }
        catch (KubernetesReadException exception)
        {
            throw new McpException(exception.Message);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            result = "cancelled";
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                "Kubernetes {Operation} failed for resource {Resource} in namespace {Namespace}. Exception type: {ExceptionType}",
                operation,
                resource,
                @namespace,
                exception.GetType().Name);
            throw new McpException("The Kubernetes API request failed.");
        }
        finally
        {
            stopwatch.Stop();
            auditLogger.LogKubernetesAccess(new KubernetesAuditEvent(
                operation,
                resource,
                @namespace,
                name,
                result,
                objectCount,
                stopwatch.Elapsed));
        }
    }
}
