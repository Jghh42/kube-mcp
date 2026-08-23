using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Security;

namespace KubeMcp.Kubernetes;

public sealed class KubernetesListSummarizer(
    SecretSanitizer secretSanitizer,
    TimeProvider timeProvider)
{
    internal JsonObject Summarize(
        DynamicKubernetesObject item,
        KubernetesResourceDescriptor descriptor)
    {
        var resource = descriptor.Resource.ToLowerInvariant();
        var group = descriptor.Group.ToLowerInvariant();

        if (group.Length == 0)
        {
            return resource switch
            {
                "pods" => SummarizePod(item),
                "services" => SummarizeService(item),
                "configmaps" => SummarizeConfigMap(item),
                "secrets" => SummarizeSecret(item),
                _ => SummarizeFallback(item, descriptor)
            };
        }

        if (group == "apps")
        {
            return resource switch
            {
                "deployments" or "statefulsets" or "replicasets" => SummarizeReplicaWorkload(item),
                "daemonsets" => SummarizeDaemonSet(item),
                _ => SummarizeFallback(item, descriptor)
            };
        }

        if (group == "batch")
        {
            return resource switch
            {
                "jobs" => SummarizeJob(item),
                "cronjobs" => SummarizeCronJob(item),
                _ => SummarizeFallback(item, descriptor)
            };
        }

        return SummarizeFallback(item, descriptor);
    }

    private JsonObject SummarizePod(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var containerStatuses = ObjectProperty(status, "containerStatuses");
        var containerCount = ArrayLength(ObjectProperty(spec, "containers"));
        if (containerCount == 0)
        {
            containerCount = ArrayLength(containerStatuses);
        }

        var readyCount = containerStatuses?.ValueKind == JsonValueKind.Array
            ? containerStatuses.Value.EnumerateArray().Count(containerStatus =>
                BooleanProperty(containerStatus, "ready") == true)
            : 0;

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["ready"] = $"{readyCount}/{containerCount}",
            ["status"] = PodStatus(item, status),
            ["restarts"] = RestartCount(status),
            ["ip"] = StringProperty(status, "podIP"),
            ["node"] = StringProperty(spec, "nodeName")
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeReplicaWorkload(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var desired = IntegerProperty(spec, "replicas") ?? 1;
        var ready = IntegerProperty(status, "readyReplicas") ?? 0;

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["ready"] = $"{ready}/{desired}",
            ["replicas"] = desired,
            ["available"] = IntegerProperty(status, "availableReplicas") ?? 0
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeDaemonSet(DynamicKubernetesObject item)
    {
        var status = ObjectProperty(item, "status");
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["desired"] = IntegerProperty(status, "desiredNumberScheduled") ?? 0,
            ["current"] = IntegerProperty(status, "currentNumberScheduled") ?? 0,
            ["ready"] = IntegerProperty(status, "numberReady") ?? 0,
            ["available"] = IntegerProperty(status, "numberAvailable") ?? 0
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeService(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var externalIps = new SortedSet<string>(StringComparer.Ordinal);
        AddStrings(externalIps, ObjectProperty(spec, "externalIPs"));

        var loadBalancer = ObjectProperty(status, "loadBalancer");
        var ingress = ObjectProperty(loadBalancer, "ingress");
        if (ingress?.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in ingress.Value.EnumerateArray())
            {
                AddIfPresent(externalIps, StringProperty(entry, "ip"));
                AddIfPresent(externalIps, StringProperty(entry, "hostname"));
            }
        }

        var ports = new JsonArray();
        var sourcePorts = ObjectProperty(spec, "ports");
        if (sourcePorts?.ValueKind == JsonValueKind.Array)
        {
            foreach (var port in sourcePorts.Value.EnumerateArray())
            {
                var summary = new JsonObject();
                AddString(summary, "name", StringProperty(port, "name"));
                AddInteger(summary, "port", IntegerProperty(port, "port"));
                summary["protocol"] = StringProperty(port, "protocol") ?? "TCP";
                AddJsonValue(summary, "targetPort", Property(port, "targetPort"));
                AddInteger(summary, "nodePort", IntegerProperty(port, "nodePort"));
                ports.Add(summary);
            }
        }

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["type"] = StringProperty(spec, "type") ?? "ClusterIP",
            ["clusterIp"] = StringProperty(spec, "clusterIP"),
            ["externalIps"] = ToJsonArray(externalIps),
            ["ports"] = ports
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeConfigMap(DynamicKubernetesObject item)
    {
        var keys = new SortedSet<string>(StringComparer.Ordinal);
        AddPropertyNames(keys, ObjectProperty(item, "data"));
        AddPropertyNames(keys, ObjectProperty(item, "binaryData"));

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["keys"] = ToJsonArray(keys),
            ["keyCount"] = keys.Count
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeSecret(DynamicKubernetesObject item)
    {
        var result = secretSanitizer.SanitizeListItem(item);
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeJob(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var desired = IntegerProperty(spec, "completions") ?? 1;
        var succeeded = IntegerProperty(status, "succeeded") ?? 0;
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["completions"] = $"{succeeded}/{desired}",
            ["active"] = IntegerProperty(status, "active") ?? 0,
            ["failed"] = IntegerProperty(status, "failed") ?? 0
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeCronJob(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["schedule"] = StringProperty(spec, "schedule"),
            ["suspend"] = BooleanProperty(spec, "suspend") ?? false,
            ["active"] = ArrayLength(ObjectProperty(status, "active")),
            ["lastSchedule"] = StringProperty(status, "lastScheduleTime")
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeFallback(
        DynamicKubernetesObject item,
        KubernetesResourceDescriptor descriptor)
    {
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["namespace"] = MetadataString(item, "namespace"),
            ["kind"] = string.IsNullOrWhiteSpace(item.Kind) ? descriptor.Kind : item.Kind
        };
        AddAge(result, item);
        return result;
    }

    private void AddAge(JsonObject result, DynamicKubernetesObject item)
    {
        var creationTimestamp = MetadataString(item, "creationTimestamp");
        if (DateTimeOffset.TryParse(
                creationTimestamp,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out var created))
        {
            result["age"] = FormatAge(timeProvider.GetUtcNow() - created);
        }
        else
        {
            result["age"] = null;
        }
    }

    private static string FormatAge(TimeSpan age)
    {
        if (age < TimeSpan.Zero)
        {
            age = TimeSpan.Zero;
        }

        if (age.TotalSeconds < 60)
        {
            return $"{(long)age.TotalSeconds}s";
        }

        if (age.TotalMinutes < 60)
        {
            return $"{(long)age.TotalMinutes}m";
        }

        if (age.TotalHours < 24)
        {
            return $"{(long)age.TotalHours}h";
        }

        return $"{(long)age.TotalDays}d";
    }

    private static string PodStatus(DynamicKubernetesObject item, JsonElement? status)
    {
        if (MetadataString(item, "deletionTimestamp") is not null)
        {
            return "Terminating";
        }

        var phase = StringProperty(status, "reason") ??
                    StringProperty(status, "phase") ??
                    "Unknown";
        var initStatuses = ObjectProperty(status, "initContainerStatuses");
        if (initStatuses?.ValueKind == JsonValueKind.Array)
        {
            var statuses = initStatuses.Value.EnumerateArray().ToArray();
            for (var index = 0; index < statuses.Length; index++)
            {
                var state = Property(statuses[index], "state");
                var terminated = ObjectProperty(state, "terminated");
                if (IntegerProperty(terminated, "exitCode") == 0)
                {
                    continue;
                }

                if (StringProperty(terminated, "reason") is { } terminatedReason)
                {
                    return $"Init:{terminatedReason}";
                }

                var waiting = ObjectProperty(state, "waiting");
                if (StringProperty(waiting, "reason") is { } waitingReason &&
                    waitingReason != "PodInitializing")
                {
                    return $"Init:{waitingReason}";
                }

                return $"Init:{index}/{statuses.Length}";
            }
        }

        var containerStatuses = ObjectProperty(status, "containerStatuses");
        if (containerStatuses?.ValueKind == JsonValueKind.Array)
        {
            foreach (var containerStatus in containerStatuses.Value.EnumerateArray().Reverse())
            {
                var state = Property(containerStatus, "state");
                var waitingReason = StringProperty(ObjectProperty(state, "waiting"), "reason");
                if (!string.IsNullOrWhiteSpace(waitingReason))
                {
                    return waitingReason;
                }

                var terminatedReason = StringProperty(ObjectProperty(state, "terminated"), "reason");
                if (!string.IsNullOrWhiteSpace(terminatedReason))
                {
                    return terminatedReason;
                }
            }
        }

        return phase;
    }

    private static long RestartCount(JsonElement? status)
    {
        long total = 0;
        foreach (var propertyName in new[]
                 {
                     "initContainerStatuses",
                     "containerStatuses",
                     "ephemeralContainerStatuses"
                 })
        {
            var statuses = ObjectProperty(status, propertyName);
            if (statuses?.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var containerStatus in statuses.Value.EnumerateArray())
            {
                total += IntegerProperty(containerStatus, "restartCount") ?? 0;
            }
        }

        return total;
    }

    private static JsonElement? ObjectProperty(DynamicKubernetesObject item, string name) =>
        item.Properties.TryGetValue(name, out var value) ? value : null;

    private static JsonElement? ObjectProperty(JsonElement? source, string name) =>
        source is { ValueKind: JsonValueKind.Object } value && value.TryGetProperty(name, out var property)
            ? property
            : null;

    private static JsonElement? Property(JsonElement source, string name) =>
        source.ValueKind == JsonValueKind.Object && source.TryGetProperty(name, out var property)
            ? property
            : null;

    private static string? MetadataString(DynamicKubernetesObject item, string name) =>
        StringProperty(ObjectProperty(item, "metadata"), name);

    private static string? StringProperty(JsonElement? source, string name) =>
        ObjectProperty(source, name) is { ValueKind: JsonValueKind.String } value
            ? value.GetString()
            : null;

    private static string? StringProperty(JsonElement source, string name) =>
        Property(source, name) is { ValueKind: JsonValueKind.String } value
            ? value.GetString()
            : null;

    private static long? IntegerProperty(JsonElement? source, string name) =>
        ObjectProperty(source, name) is { ValueKind: JsonValueKind.Number } value && value.TryGetInt64(out var number)
            ? number
            : null;

    private static long? IntegerProperty(JsonElement source, string name) =>
        Property(source, name) is { ValueKind: JsonValueKind.Number } value && value.TryGetInt64(out var number)
            ? number
            : null;

    private static bool? BooleanProperty(JsonElement? source, string name) =>
        ObjectProperty(source, name) is { } value ? BooleanValue(value) : null;

    private static bool? BooleanProperty(JsonElement source, string name) =>
        Property(source, name) is { } value ? BooleanValue(value) : null;

    private static bool? BooleanValue(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null
    };

    private static int ArrayLength(JsonElement? value) =>
        value?.ValueKind == JsonValueKind.Array ? value.Value.GetArrayLength() : 0;

    private static void AddPropertyNames(ISet<string> destination, JsonElement? value)
    {
        if (value?.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var property in value.Value.EnumerateObject())
        {
            destination.Add(property.Name);
        }
    }

    private static void AddStrings(ISet<string> destination, JsonElement? value)
    {
        if (value?.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var entry in value.Value.EnumerateArray())
        {
            if (entry.ValueKind == JsonValueKind.String)
            {
                AddIfPresent(destination, entry.GetString());
            }
        }
    }

    private static void AddIfPresent(ISet<string> destination, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            destination.Add(value);
        }
    }

    private static JsonArray ToJsonArray(IEnumerable<string> values)
    {
        var result = new JsonArray();
        foreach (var value in values)
        {
            result.Add(value);
        }

        return result;
    }

    private static void AddString(JsonObject target, string name, string? value)
    {
        if (value is not null)
        {
            target[name] = value;
        }
    }

    private static void AddInteger(JsonObject target, string name, long? value)
    {
        if (value is not null)
        {
            target[name] = value.Value;
        }
    }

    private static void AddJsonValue(JsonObject target, string name, JsonElement? value)
    {
        if (value is { ValueKind: not JsonValueKind.Null and not JsonValueKind.Undefined })
        {
            target[name] = JsonNode.Parse(value.Value.GetRawText());
        }
    }
}
