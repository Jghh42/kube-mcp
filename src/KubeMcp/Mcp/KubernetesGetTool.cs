using System.ComponentModel;
using KubeMcp.Kubernetes;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace KubeMcp.Mcp;

public sealed class KubernetesGetTool(
    IKubernetesReader reader,
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
        [Description("Kubernetes resource name, kind, short name, or resource.group name.")]
        string resource,
        [Description("Kubernetes namespace. All-namespace requests are not supported.")]
        string @namespace,
        [Description("Optional object name. Omit it to list resources in the namespace.")]
        string? name = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await reader.ReadAsync(resource, @namespace, name, cancellationToken);
        }
        catch (KubernetesReadException exception)
        {
            throw new McpException(exception.Message);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                "Kubernetes {Operation} failed for resource {Resource} in namespace {Namespace}. Exception type: {ExceptionType}",
                name is null ? "LIST" : "GET",
                resource,
                @namespace,
                exception.GetType().Name);
            throw new McpException("The Kubernetes API request failed.");
        }
    }
}
