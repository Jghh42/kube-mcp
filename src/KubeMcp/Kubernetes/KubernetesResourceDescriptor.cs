namespace KubeMcp.Kubernetes;

public sealed record KubernetesResourceDescriptor(
    string Group,
    string Version,
    string Resource,
    string Kind)
{
    public string ApiVersion => string.IsNullOrEmpty(Group)
        ? Version
        : $"{Group}/{Version}";

    public string QualifiedName => string.IsNullOrEmpty(Group)
        ? Resource
        : $"{Resource}.{Group}";

    public bool IsSecret => string.IsNullOrEmpty(Group) &&
                            Resource.Equals("secrets", StringComparison.OrdinalIgnoreCase);
}
