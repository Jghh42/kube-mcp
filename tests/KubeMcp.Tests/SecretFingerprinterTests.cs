using System.Text;
using KubeMcp.Security;

namespace KubeMcp.Tests;

public sealed class SecretFingerprinterTests
{
    private static readonly byte[] KeyA = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
    private static readonly byte[] KeyB = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();

    [Fact]
    public void SameKeyAndValueProduceSameFingerprint()
    {
        using var fingerprinter = new SecretFingerprinter(KeyA);
        var value = Encoding.UTF8.GetBytes("secret-value");

        Assert.Equal(fingerprinter.Fingerprint(value), fingerprinter.Fingerprint(value));
    }

    [Fact]
    public void DifferentValuesProduceDifferentFingerprints()
    {
        using var fingerprinter = new SecretFingerprinter(KeyA);

        Assert.NotEqual(
            fingerprinter.Fingerprint("first"u8),
            fingerprinter.Fingerprint("second"u8));
    }

    [Fact]
    public void DifferentKeysProduceDifferentFingerprints()
    {
        using var first = new SecretFingerprinter(KeyA);
        using var second = new SecretFingerprinter(KeyB);

        Assert.NotEqual(
            first.Fingerprint("same-value"u8),
            second.Fingerprint("same-value"u8));
    }

    [Fact]
    public void RejectsShortKeys()
    {
        Assert.Throws<ArgumentException>(() => new SecretFingerprinter(new byte[31]));
    }
}
