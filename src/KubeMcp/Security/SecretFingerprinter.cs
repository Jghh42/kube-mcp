using System.Security.Cryptography;
using KubeMcp.Configuration;
using Microsoft.Extensions.Options;

namespace KubeMcp.Security;

public sealed class SecretFingerprinter : IDisposable
{
    private const int FingerprintBytes = 16;
    private readonly byte[] key;

    public SecretFingerprinter(IOptions<KubeMcpOptions> options)
    {
        var decodedKey = Convert.FromBase64String(options.Value.SecretHmacKey);
        try
        {
            key = CopyValidatedKey(decodedKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decodedKey);
        }
    }

    public SecretFingerprinter(byte[] key)
    {
        this.key = CopyValidatedKey(key);
    }

    private static byte[] CopyValidatedKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length < 32)
        {
            throw new ArgumentException("The HMAC key must contain at least 32 bytes.", nameof(key));
        }

        return key.ToArray();
    }

    public string Fingerprint(ReadOnlySpan<byte> value)
    {
        var hash = HMACSHA256.HashData(key, value);
        try
        {
            return $"hmac-sha256:{Convert.ToHexString(hash.AsSpan(0, FingerprintBytes)).ToLowerInvariant()}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(key);
    }
}
