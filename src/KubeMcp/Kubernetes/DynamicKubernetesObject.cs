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

// LIST responses are parsed directly from the capped raw JSON body and are not
// deserialized into a typed list object, so no DynamicKubernetesObjectList is
// needed. Keeping raw Secret lists out of a long-lived typed object bounds the
// raw-secret memory lifetime to a single small page.
