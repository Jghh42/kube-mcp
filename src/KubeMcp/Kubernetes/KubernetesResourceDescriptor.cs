namespace KubeMcp.Kubernetes;

internal sealed record KubernetesResourceDescriptor(
    string Group,
    string Version,
    string Resource,
    string Kind,
    IReadOnlyList<string> Aliases,
    IReadOnlyList<string> Verbs)
{
    public string QualifiedName => string.IsNullOrEmpty(Group)
        ? Resource
        : $"{Resource}.{Group}";

    public bool IsSecret => string.IsNullOrEmpty(Group) &&
                            Resource.Equals("secrets", StringComparison.OrdinalIgnoreCase);
}
