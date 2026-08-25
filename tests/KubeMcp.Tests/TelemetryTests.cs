using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using KubeMcp.Audit;
using KubeMcp.Observability;
using Microsoft.AspNetCore.Http;

namespace KubeMcp.Tests;

public sealed class TelemetryTests
{
    private static readonly string[] ForbiddenTagFragments =
        ["resource.name", "namespace", "token", "body", "fingerprint", "exception"];

    [Fact]
    public void EmitsRequiredLowCardinalityMetricsWithSharedSafeCategory()
    {
        using var listener = new MeterListener();
        var measurements = new ConcurrentBag<Measurement>();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == KubeMcpTelemetry.InstrumentationName)
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            measurements.Add(new Measurement(instrument.Name, CopyTags(tags))));
        listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) =>
            measurements.Add(new Measurement(instrument.Name, CopyTags(tags))));
        listener.Start();

        using var telemetry = new KubeMcpTelemetry(new HttpContextAccessor());
        telemetry.RecordMcpRequest(
            TimeSpan.FromMilliseconds(10),
            StatusCodes.Status401Unauthorized,
            AuditCategories.AuthenticationDenied);
        telemetry.RecordKubernetesRequest(
            "GET",
            TimeSpan.FromMilliseconds(20),
            "upstream_timeout",
            responseBytes: null,
            objectCount: null,
            secretGet: false);
        telemetry.RecordKubernetesRequest(
            "GET",
            TimeSpan.FromMilliseconds(5),
            AuditCategories.Success,
            responseBytes: 128,
            objectCount: 1,
            secretGet: true);
        telemetry.RecordKubernetesRequest(
            "LIST",
            TimeSpan.FromMilliseconds(6),
            AuditCategories.Success,
            responseBytes: 256,
            objectCount: 4,
            secretGet: false);

        Assert.Contains(measurements, measurement => measurement.Name == "kube_mcp.mcp.requests");
        Assert.Contains(measurements, measurement => measurement.Name == "kube_mcp.mcp.request.duration");
        Assert.Contains(measurements, measurement =>
            measurement.Name == "kube_mcp.mcp.denials" &&
            Equals(measurement.Tags["mcp.error.category"], AuditCategories.AuthenticationDenied));
        Assert.Contains(measurements, measurement => measurement.Name == "kube_mcp.kubernetes.request.duration");
        Assert.Contains(measurements, measurement =>
            measurement.Name == "kube_mcp.kubernetes.errors" &&
            Equals(measurement.Tags["mcp.error.category"], "upstream_timeout"));
        Assert.Contains(measurements, measurement => measurement.Name == "kube_mcp.response.size");
        Assert.Contains(measurements, measurement => measurement.Name == "kube_mcp.list.count");
        Assert.Contains(measurements, measurement => measurement.Name == "kube_mcp.secret.gets");
        Assert.Contains(measurements, measurement =>
            measurement.Name == "kube_mcp.timeouts" &&
            Equals(measurement.Tags["timeout.scope"], "kubernetes"));

        Assert.All(measurements, measurement => Assert.All(measurement.Tags.Keys, key =>
            Assert.DoesNotContain(ForbiddenTagFragments, fragment =>
                key.Contains(fragment, StringComparison.OrdinalIgnoreCase))));
    }

    [Fact]
    public void CustomTracesContainOnlyFixedOperationOutcomeAndCategory()
    {
        var stopped = new ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == KubeMcpTelemetry.InstrumentationName,
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = stopped.Add
        };
        ActivitySource.AddActivityListener(listener);
        using var telemetry = new KubeMcpTelemetry(new HttpContextAccessor());

        ActivityTraceId mcpTraceId = default;
        using (var hostingActivity = new Activity("Microsoft.AspNetCore.Hosting.HttpRequestIn")
                   .SetParentId("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                   .AddTag("url.query", "?token=must-not-propagate")
                   .AddTag("user_agent.original", "caller-controlled-value")
                   .Start())
        {
            hostingActivity.TraceStateString = "vendor=caller-controlled-sensitive-value";
            hostingActivity.AddBaggage("token", "caller-controlled-sensitive-value");
            using var mcpActivity = telemetry.StartMcpRequest();
            mcpTraceId = mcpActivity?.TraceId ?? default;
            Assert.Null(mcpActivity?.TraceStateString);
            Assert.Empty(mcpActivity?.Baggage ?? []);
            KubeMcpTelemetry.CompleteActivity(mcpActivity, AuditCategories.Success);
        }

        ActivityTraceId kubernetesTraceId;
        using (var activity = telemetry.StartKubernetesRequest("GET"))
        {
            kubernetesTraceId = activity?.TraceId ?? default;
            KubeMcpTelemetry.CompleteActivity(activity, "kubernetes_access_denied");
        }

        var mcpTrace = Assert.Single(stopped, activity =>
            activity.OperationName == "mcp.request" && activity.TraceId == mcpTraceId);
        Assert.DoesNotContain(mcpTrace.TagObjects, tag =>
            tag.Key is "url.query" or "user_agent.original");

        var trace = Assert.Single(stopped, activity =>
            activity.OperationName == "kubernetes.read" && activity.TraceId == kubernetesTraceId);
        Assert.Equal("GET", trace.GetTagItem("kubernetes.operation"));
        Assert.Equal("kubernetes_access_denied", trace.GetTagItem("mcp.error.category"));
        Assert.Equal(ActivityStatusCode.Error, trace.Status);
        Assert.All(trace.TagObjects, tag => Assert.DoesNotContain(
            ForbiddenTagFragments,
            fragment => tag.Key.Contains(fragment, StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain(trace.TagObjects, tag =>
            tag.Value?.ToString()?.Contains("secret-object-name", StringComparison.Ordinal) == true);
    }

    [Fact]
    public void RootMcpTraceDetachesFromUnsampledHostingActivity()
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == KubeMcpTelemetry.InstrumentationName,
            Sample = static (ref ActivityCreationOptions<ActivityContext> options) =>
                options.Parent.TraceId == default || options.Parent.TraceFlags.HasFlag(ActivityTraceFlags.Recorded)
                    ? ActivitySamplingResult.AllData
                    : ActivitySamplingResult.None
        };
        ActivitySource.AddActivityListener(listener);
        using var telemetry = new KubeMcpTelemetry(new HttpContextAccessor());
        using var unsampledHostingActivity = new Activity("Microsoft.AspNetCore.Hosting.HttpRequestIn").Start();

        using var mcpActivity = telemetry.StartMcpRequest();

        Assert.NotNull(mcpActivity);
        Assert.Equal(default, mcpActivity.ParentSpanId);
    }

    private static IReadOnlyDictionary<string, object?> CopyTags(
        ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var copy = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var tag in tags)
        {
            copy[tag.Key] = tag.Value;
        }

        return copy;
    }

    private sealed record Measurement(
        string Name,
        IReadOnlyDictionary<string, object?> Tags);
}
