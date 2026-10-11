using System.ComponentModel;
using System.Diagnostics;
using KubeMcp.Audit;
using KubeMcp.CredentialGate;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Http.Timeouts;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace KubeMcp.Mcp;

public sealed class KubernetesGetTool
{
    private readonly IKubernetesReader reader;
    private readonly IAuditLogger auditLogger;
    private readonly ILogger<KubernetesGetTool> logger;
    private readonly IHttpContextAccessor? httpContextAccessor;
    private readonly ICredentialGate credentialGate;

    public KubernetesGetTool(
        IKubernetesReader reader,
        IAuditLogger auditLogger,
        ILogger<KubernetesGetTool> logger,
        ICredentialGate credentialGate,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        this.reader = reader;
        this.auditLogger = auditLogger;
        this.logger = logger;
        this.httpContextAccessor = httpContextAccessor;
        this.credentialGate = credentialGate ?? throw new ArgumentNullException(nameof(credentialGate));
    }

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
        // Never copy an oversized caller-controlled resource into policy errors,
        // logs, or audit records. The validator below rejects it before the
        // reader can resolve the explicit resource mapping.
        var diagnosticResource = KubernetesNameValidator.BoundedResourceForDiagnostics(resource);
        var operation = name is null ? "LIST" : "GET";
        var stopwatch = Stopwatch.StartNew();
        var result = "failed";
        var category = AuditCategories.InternalError;
        int? objectCount = null;

        try
        {
            KubernetesNameValidator.ValidateResourceIdentifierLength(resource);
            var response = await reader.ReadAsync(resource, @namespace, name, cancellationToken);
            if (name is not null)
            {
                var gateDecision = await credentialGate.EvaluateAsync(response.Json, cancellationToken);
                if (gateDecision != CredentialGateDecision.Clear)
                {
                    result = "blocked";
                    category = gateDecision == CredentialGateDecision.Detected
                        ? AuditCategories.CredentialDetected
                        : AuditCategories.CredentialGateUnavailable;
                    throw new McpException(CredentialGateErrorMessage);
                }
            }

            result = "success";
            category = AuditCategories.Success;
            objectCount = response.ObjectCount;
            return response.Json;
        }
        catch (McpException) when (category is AuditCategories.CredentialDetected or AuditCategories.CredentialGateUnavailable)
        {
            throw;
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
            category = AuditCategories.InternalError;
            logger.LogWarning(
                "Kubernetes {Operation} failed for resource {Resource} in namespace {Namespace}. Exception type: {ExceptionType}",
                operation,
                diagnosticResource,
                @namespace,
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
                    diagnosticResource,
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

    internal const string CredentialGateErrorMessage =
        "The requested resource could not be returned because credential screening did not clear it.";

    private bool IsServerDeadlineExpired() =>
        httpContextAccessor?.HttpContext?.Features
            .Get<IHttpRequestTimeoutFeature>()?
            .RequestTimeoutToken.IsCancellationRequested == true;
}
