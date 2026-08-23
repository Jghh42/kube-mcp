using System.Text;
using System.Text.Json;
using KubeMcp.Kubernetes;
using KubeMcp.Security;

namespace KubeMcp.Tests;

public sealed class SecretSanitizerTests : IDisposable
{
    private const string RawValue = "correct-horse-battery-staple";
    private const string DangerousAnnotation = "embedded-secret-value";
    private readonly SecretFingerprinter fingerprinter = new(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray());
    private readonly SecretSanitizer sanitizer;

    public SecretSanitizerTests()
    {
        sanitizer = new SecretSanitizer(fingerprinter);
    }

    [Fact]
    public void GetReplacesDataAndStringDataWithFingerprints()
    {
        var secret = ParseSecret($$"""
            {
              "apiVersion": "v1",
              "kind": "Secret",
              "metadata": {
                "name": "database",
                "namespace": "integration",
                "annotations": {
                  "dangerous": "{{DangerousAnnotation}}"
                }
              },
              "type": "Opaque",
              "data": {
                "password": "{{Convert.ToBase64String(Encoding.UTF8.GetBytes(RawValue))}}",
                "binary": "AP+A"
              },
              "stringData": {
                "duplicate": "{{RawValue}}"
              }
            }
            """);

        var result = sanitizer.SanitizeGet(secret).ToJsonString();
        using var json = JsonDocument.Parse(result);
        var data = json.RootElement.GetProperty("data");

        Assert.DoesNotContain(RawValue, result);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(RawValue)), result);
        Assert.DoesNotContain(DangerousAnnotation, result);
        Assert.DoesNotContain("annotations", result);
        Assert.StartsWith("hmac-sha256:", data.GetProperty("password").GetString());
        Assert.Equal(
            data.GetProperty("password").GetString(),
            data.GetProperty("duplicate").GetString());
        Assert.Equal(
            fingerprinter.Fingerprint(Encoding.UTF8.GetBytes(RawValue)),
            data.GetProperty("password").GetString());
        Assert.Equal(
            fingerprinter.Fingerprint([0x00, 0xff, 0x80]),
            data.GetProperty("binary").GetString());
    }

    [Fact]
    public void ListReturnsOnlySafeDiscoveryFieldsAndKeyNames()
    {
        var secret = ParseSecret($$"""
            {
              "apiVersion": "v1",
              "kind": "Secret",
              "metadata": {
                "name": "database",
                "namespace": "integration",
                "annotations": { "dangerous": "{{DangerousAnnotation}}" }
              },
              "type": "kubernetes.io/basic-auth",
              "data": {
                "username": "{{Convert.ToBase64String("admin"u8)}}",
                "password": "{{Convert.ToBase64String(Encoding.UTF8.GetBytes(RawValue))}}"
              }
            }
            """);

        var result = sanitizer.SanitizeListItem(secret).ToJsonString();

        Assert.Contains("database", result);
        Assert.Contains("password", result);
        Assert.Contains("username", result);
        Assert.DoesNotContain(RawValue, result);
        Assert.DoesNotContain(DangerousAnnotation, result);
        Assert.DoesNotContain("hmac-sha256:", result);
        Assert.DoesNotContain("annotations", result);
    }

    [Fact]
    public void InvalidBase64ProducesSafeError()
    {
        var secret = ParseSecret("""
            {
              "apiVersion": "v1",
              "kind": "Secret",
              "metadata": { "name": "bad", "namespace": "integration" },
              "data": { "password": "not base64!" }
            }
            """);

        var exception = Assert.Throws<KubernetesReadException>(() => sanitizer.SanitizeGet(secret));

        Assert.DoesNotContain("not base64!", exception.Message);
    }

    private static DynamicKubernetesObject ParseSecret(string json)
    {
        return JsonSerializer.Deserialize<DynamicKubernetesObject>(json)!;
    }

    public void Dispose()
    {
        fingerprinter.Dispose();
    }
}
