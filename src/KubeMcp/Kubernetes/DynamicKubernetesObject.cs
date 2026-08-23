using System.Text.Json;
using System.Text.Json.Serialization;
using k8s;

namespace KubeMcp.Kubernetes;

public sealed class DynamicKubernetesObject : IKubernetesObject
{
    [JsonPropertyName("apiVersion")]
    public string ApiVersion { get; set; } = string.Empty;

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = string.Empty;

    [JsonExtensionData]
    public Dictionary<string, JsonElement> Properties { get; set; } = [];
}

public sealed class DynamicKubernetesObjectList : IKubernetesObject
{
    [JsonPropertyName("apiVersion")]
    public string ApiVersion { get; set; } = string.Empty;

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = string.Empty;

    [JsonPropertyName("metadata")]
    public JsonElement Metadata { get; set; }

    [JsonPropertyName("items")]
    public List<DynamicKubernetesObject> Items { get; set; } = [];
}
