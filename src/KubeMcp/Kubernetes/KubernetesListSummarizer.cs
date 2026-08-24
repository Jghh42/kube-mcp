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
                "endpoints" => SummarizeEndpoints(item),
                "configmaps" => SummarizeConfigMap(item),
                "secrets" => SummarizeSecret(item),
                "events" => SummarizeEvent(item),
                "persistentvolumeclaims" => SummarizePersistentVolumeClaim(item),
                "replicationcontrollers" => SummarizeReplicationController(item),
                "limitranges" => SummarizeLimitRange(item),
                "resourcequotas" => SummarizeResourceQuota(item),
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

        if (group == "discovery.k8s.io" && resource == "endpointslices")
        {
            return SummarizeEndpointSlice(item);
        }

        if (group == "networking.k8s.io")
        {
            return resource switch
            {
                "ingresses" => SummarizeIngress(item),
                "networkpolicies" => SummarizeNetworkPolicy(item),
                _ => SummarizeFallback(item, descriptor)
            };
        }

        if (group == "autoscaling" && resource == "horizontalpodautoscalers")
        {
            return SummarizeHorizontalPodAutoscaler(item);
        }

        if (group == "policy" && resource == "poddisruptionbudgets")
        {
            return SummarizePodDisruptionBudget(item);
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

    private JsonObject SummarizeEndpoints(DynamicKubernetesObject item)
    {
        long readyAddresses = 0;
        long notReadyAddresses = 0;
        var ports = new SortedDictionary<string, JsonObject>(StringComparer.Ordinal);
        var subsets = ObjectProperty(item, "subsets");
        if (subsets?.ValueKind == JsonValueKind.Array)
        {
            foreach (var subset in subsets.Value.EnumerateArray())
            {
                readyAddresses += ArrayLength(ObjectProperty(subset, "addresses"));
                notReadyAddresses += ArrayLength(ObjectProperty(subset, "notReadyAddresses"));
                AddEndpointPorts(ports, ObjectProperty(subset, "ports"));
            }
        }

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["readyAddresses"] = readyAddresses,
            ["notReadyAddresses"] = notReadyAddresses,
            ["ports"] = ToJsonArray(ports.Values)
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeEndpointSlice(DynamicKubernetesObject item)
    {
        long ready = 0;
        long terminating = 0;
        long addressCount = 0;
        var endpoints = ObjectProperty(item, "endpoints");
        if (endpoints?.ValueKind == JsonValueKind.Array)
        {
            foreach (var endpoint in endpoints.Value.EnumerateArray())
            {
                addressCount += ArrayLength(ObjectProperty(endpoint, "addresses"));
                var conditions = ObjectProperty(endpoint, "conditions");
                if (BooleanProperty(conditions, "ready") != false)
                {
                    ready++;
                }

                if (BooleanProperty(conditions, "terminating") == true)
                {
                    terminating++;
                }
            }
        }

        var ports = new SortedDictionary<string, JsonObject>(StringComparer.Ordinal);
        AddEndpointPorts(ports, ObjectProperty(item, "ports"));
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["service"] = MetadataStringMapValue(item, "labels", "kubernetes.io/service-name"),
            ["addressType"] = StringValue(ObjectProperty(item, "addressType")),
            ["endpoints"] = ArrayLength(endpoints),
            ["ready"] = ready,
            ["terminating"] = terminating,
            ["addresses"] = addressCount,
            ["ports"] = ToJsonArray(ports.Values)
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeEvent(DynamicKubernetesObject item)
    {
        var series = ObjectProperty(item, "series");
        var source = ObjectProperty(item, "source");
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["type"] = StringValue(ObjectProperty(item, "type")),
            ["reason"] = StringValue(ObjectProperty(item, "reason")),
            ["object"] = FormatObjectReference(ObjectProperty(item, "involvedObject") ?? ObjectProperty(item, "regarding")),
            ["message"] = StringValue(ObjectProperty(item, "message")) ?? StringValue(ObjectProperty(item, "note")),
            ["count"] = IntegerProperty(series, "count") ?? IntegerValue(ObjectProperty(item, "count")) ?? 1,
            ["lastSeen"] = StringProperty(series, "lastObservedTime") ??
                           StringValue(ObjectProperty(item, "eventTime")) ??
                           StringValue(ObjectProperty(item, "lastTimestamp")),
            ["reporting"] = StringValue(ObjectProperty(item, "reportingController")) ??
                            StringProperty(source, "component")
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizePersistentVolumeClaim(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["status"] = StringProperty(status, "phase"),
            ["volume"] = StringProperty(spec, "volumeName"),
            ["capacity"] = StringProperty(ObjectProperty(status, "capacity"), "storage"),
            ["accessModes"] = StringArray(ObjectProperty(spec, "accessModes")),
            ["storageClass"] = StringProperty(spec, "storageClassName") ??
                               MetadataStringMapValue(item, "annotations", "volume.beta.kubernetes.io/storage-class"),
            ["volumeMode"] = StringProperty(spec, "volumeMode") ?? "Filesystem"
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeReplicationController(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["desired"] = IntegerProperty(spec, "replicas") ?? 1,
            ["current"] = IntegerProperty(status, "replicas") ?? 0,
            ["ready"] = IntegerProperty(status, "readyReplicas") ?? 0,
            ["available"] = IntegerProperty(status, "availableReplicas") ?? 0
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

    private JsonObject SummarizeIngress(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var hosts = new SortedSet<string>(StringComparer.Ordinal);
        var rules = ObjectProperty(spec, "rules");
        if (rules?.ValueKind == JsonValueKind.Array)
        {
            foreach (var rule in rules.Value.EnumerateArray())
            {
                hosts.Add(StringProperty(rule, "host") ?? "*");
            }
        }

        var addresses = new SortedSet<string>(StringComparer.Ordinal);
        var loadBalancer = ObjectProperty(ObjectProperty(item, "status"), "loadBalancer");
        var ingress = ObjectProperty(loadBalancer, "ingress");
        if (ingress?.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in ingress.Value.EnumerateArray())
            {
                AddIfPresent(addresses, StringProperty(entry, "ip"));
                AddIfPresent(addresses, StringProperty(entry, "hostname"));
            }
        }

        var ports = new JsonArray(80);
        if (ArrayLength(ObjectProperty(spec, "tls")) > 0)
        {
            ports.Add(443);
        }

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["class"] = StringProperty(spec, "ingressClassName") ??
                        MetadataStringMapValue(item, "annotations", "kubernetes.io/ingress.class"),
            ["hosts"] = ToJsonArray(hosts),
            ["addresses"] = ToJsonArray(addresses),
            ["ports"] = ports
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeNetworkPolicy(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var policyTypes = new SortedSet<string>(StringComparer.Ordinal);
        AddStrings(policyTypes, ObjectProperty(spec, "policyTypes"));
        if (policyTypes.Count == 0)
        {
            policyTypes.Add("Ingress");
            if (ObjectProperty(spec, "egress") is not null)
            {
                policyTypes.Add("Egress");
            }
        }

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["podSelector"] = FormatLabelSelector(ObjectProperty(spec, "podSelector")),
            ["policyTypes"] = ToJsonArray(policyTypes),
            ["ingressRules"] = ArrayLength(ObjectProperty(spec, "ingress")),
            ["egressRules"] = ArrayLength(ObjectProperty(spec, "egress"))
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeHorizontalPodAutoscaler(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var target = ObjectProperty(spec, "scaleTargetRef");
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["target"] = FormatObjectReference(target),
            ["minReplicas"] = IntegerProperty(spec, "minReplicas") ?? 1,
            ["maxReplicas"] = IntegerProperty(spec, "maxReplicas"),
            ["currentReplicas"] = IntegerProperty(status, "currentReplicas") ?? 0,
            ["desiredReplicas"] = IntegerProperty(status, "desiredReplicas") ?? 0,
            ["metrics"] = ArrayLength(ObjectProperty(spec, "metrics"))
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizePodDisruptionBudget(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["minAvailable"] = ScalarNode(ObjectProperty(spec, "minAvailable")),
            ["maxUnavailable"] = ScalarNode(ObjectProperty(spec, "maxUnavailable")),
            ["disruptionsAllowed"] = IntegerProperty(status, "disruptionsAllowed") ?? 0,
            ["currentHealthy"] = IntegerProperty(status, "currentHealthy") ?? 0,
            ["desiredHealthy"] = IntegerProperty(status, "desiredHealthy") ?? 0,
            ["expectedPods"] = IntegerProperty(status, "expectedPods") ?? 0
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeLimitRange(DynamicKubernetesObject item)
    {
        var summaries = new JsonArray();
        var limits = ObjectProperty(ObjectProperty(item, "spec"), "limits");
        if (limits?.ValueKind == JsonValueKind.Array)
        {
            foreach (var limit in limits.Value.EnumerateArray())
            {
                AddLimitSummaries(summaries, limit);
            }
        }

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["limits"] = summaries,
            ["limitCount"] = summaries.Count
        };
        AddAge(result, item);
        return result;
    }

    private JsonObject SummarizeResourceQuota(DynamicKubernetesObject item)
    {
        var spec = ObjectProperty(item, "spec");
        var status = ObjectProperty(item, "status");
        var hard = ObjectProperty(status, "hard") ?? ObjectProperty(spec, "hard");
        var used = ObjectProperty(status, "used");
        var resourceNames = new SortedSet<string>(StringComparer.Ordinal);
        AddPropertyNames(resourceNames, hard);
        AddPropertyNames(resourceNames, used);

        var resources = new JsonArray();
        foreach (var resourceName in resourceNames)
        {
            var summary = new JsonObject
            {
                ["name"] = resourceName
            };
            AddScalar(summary, "used", ObjectProperty(used, resourceName));
            AddScalar(summary, "hard", ObjectProperty(hard, resourceName));
            resources.Add(summary);
        }

        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["scopes"] = StringArray(ObjectProperty(spec, "scopes")),
            ["resources"] = resources,
            ["resourceCount"] = resources.Count
        };
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

    private static void AddEndpointPorts(
        IDictionary<string, JsonObject> destination,
        JsonElement? sourcePorts)
    {
        if (sourcePorts?.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var port in sourcePorts.Value.EnumerateArray())
        {
            var name = StringProperty(port, "name");
            var number = IntegerProperty(port, "port");
            var protocol = StringProperty(port, "protocol") ?? "TCP";
            var appProtocol = StringProperty(port, "appProtocol");
            var key = $"{name}\u001f{number?.ToString(CultureInfo.InvariantCulture)}\u001f{protocol}\u001f{appProtocol}";
            if (destination.ContainsKey(key))
            {
                continue;
            }

            var summary = new JsonObject
            {
                ["protocol"] = protocol
            };
            AddString(summary, "name", name);
            AddInteger(summary, "port", number);
            AddString(summary, "appProtocol", appProtocol);
            destination[key] = summary;
        }
    }

    private static void AddLimitSummaries(JsonArray destination, JsonElement limit)
    {
        var type = StringProperty(limit, "type");
        var valueNames = new[]
        {
            "min",
            "max",
            "default",
            "defaultRequest",
            "maxLimitRequestRatio"
        };
        var resources = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var valueName in valueNames)
        {
            AddPropertyNames(resources, ObjectProperty(limit, valueName));
        }

        if (resources.Count == 0)
        {
            var typeOnly = new JsonObject();
            AddString(typeOnly, "type", type);
            destination.Add(typeOnly);
            return;
        }

        foreach (var resource in resources)
        {
            var summary = new JsonObject
            {
                ["resource"] = resource
            };
            AddString(summary, "type", type);
            foreach (var valueName in valueNames)
            {
                AddScalar(summary, valueName, ObjectProperty(ObjectProperty(limit, valueName), resource));
            }

            destination.Add(summary);
        }
    }

    private static string? FormatObjectReference(JsonElement? reference)
    {
        var name = StringProperty(reference, "name");
        var kind = StringProperty(reference, "kind");
        if (name is null)
        {
            return kind;
        }

        return kind is null ? name : $"{kind}/{name}";
    }

    private static string? FormatLabelSelector(JsonElement? selector)
    {
        if (selector?.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var parts = new SortedSet<string>(StringComparer.Ordinal);
        var matchLabels = ObjectProperty(selector, "matchLabels");
        if (matchLabels?.ValueKind == JsonValueKind.Object)
        {
            foreach (var label in matchLabels.Value.EnumerateObject())
            {
                if (label.Value.ValueKind == JsonValueKind.String)
                {
                    parts.Add($"{label.Name}={label.Value.GetString()}");
                }
            }
        }

        var expressions = ObjectProperty(selector, "matchExpressions");
        if (expressions?.ValueKind == JsonValueKind.Array)
        {
            foreach (var expression in expressions.Value.EnumerateArray())
            {
                var key = StringProperty(expression, "key");
                var operation = StringProperty(expression, "operator");
                if (key is null || operation is null)
                {
                    continue;
                }

                var values = new SortedSet<string>(StringComparer.Ordinal);
                AddStrings(values, ObjectProperty(expression, "values"));
                parts.Add(operation switch
                {
                    "Exists" => key,
                    "DoesNotExist" => $"!{key}",
                    "In" => $"{key} in ({string.Join(',', values)})",
                    "NotIn" => $"{key} notin ({string.Join(',', values)})",
                    _ => $"{key} {operation} ({string.Join(',', values)})"
                });
            }
        }

        return parts.Count == 0 ? "<all>" : string.Join(',', parts);
    }

    private static string? MetadataStringMapValue(
        DynamicKubernetesObject item,
        string mapName,
        string key) =>
        StringProperty(ObjectProperty(ObjectProperty(item, "metadata"), mapName), key);

    private static JsonArray StringArray(JsonElement? value)
    {
        var result = new JsonArray();
        if (value?.ValueKind != JsonValueKind.Array)
        {
            return result;
        }

        foreach (var entry in value.Value.EnumerateArray())
        {
            if (entry.ValueKind == JsonValueKind.String)
            {
                result.Add(entry.GetString());
            }
        }

        return result;
    }

    private static string? StringValue(JsonElement? value) =>
        value is { ValueKind: JsonValueKind.String } element ? element.GetString() : null;

    private static long? IntegerValue(JsonElement? value) =>
        value is { ValueKind: JsonValueKind.Number } element && element.TryGetInt64(out var number)
            ? number
            : null;

    private static JsonNode? ScalarNode(JsonElement? value) => value?.ValueKind switch
    {
        JsonValueKind.String => JsonValue.Create(value.Value.GetString()),
        JsonValueKind.Number => JsonNode.Parse(value.Value.GetRawText()),
        JsonValueKind.True => JsonValue.Create(true),
        JsonValueKind.False => JsonValue.Create(false),
        _ => null
    };

    private static void AddScalar(JsonObject target, string name, JsonElement? value)
    {
        if (ScalarNode(value) is { } node)
        {
            target[name] = node;
        }
    }

    private static JsonArray ToJsonArray(IEnumerable<JsonObject> values)
    {
        var result = new JsonArray();
        foreach (var value in values)
        {
            result.Add(value);
        }

        return result;
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
