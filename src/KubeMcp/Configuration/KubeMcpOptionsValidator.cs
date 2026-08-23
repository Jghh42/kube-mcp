using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace KubeMcp.Configuration;

public sealed class KubeMcpOptionsValidator : IValidateOptions<KubeMcpOptions>
{
    private const int MinimumHmacKeyBytes = 32;

    public ValidateOptionsResult Validate(string? name, KubeMcpOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.SecretHmacKey))
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:SecretHmacKey is required.");
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(options.SecretHmacKey);
        }
        catch (FormatException)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:SecretHmacKey must be a valid base64 value.");
        }

        try
        {
            return key.Length >= MinimumHmacKeyBytes
                ? ValidateOptionsResult.Success
                : ValidateOptionsResult.Fail(
                    $"{KubeMcpOptions.SectionName}:SecretHmacKey must contain at least {MinimumHmacKeyBytes} bytes.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
