using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using KubeMcp.Kubernetes;

namespace KubeMcp.Security;

/// <summary>
/// Proof-of-concept deterministic scanner for credentials in known formats that
/// remain in already-sanitized tool output. It inspects JSON string values only
/// (never property names or raw text), parses string values that are themselves
/// JSON documents, and reports the JSONPath of each match.
/// </summary>
/// <remarks>
/// Most value patterns are a curated port of rules from Gitleaks
/// (https://github.com/gitleaks/gitleaks, config/gitleaks.toml, MIT License,
/// Copyright (c) 2019 Zachary Rice). Each ported rule names its Gitleaks rule id.
/// The keyword, keyed-field, base64 private-key, and validation logic is local.
/// </remarks>
internal static partial class KnownFormatSecretScanner
{
    internal const double DefaultGenericMinEntropy = 3.0;
    internal const string KeyedFieldRuleId = "generic-keyed-field";
    internal const string AwsSecretRuleId = "aws-secret-access-key";
    private const int MatchTimeoutMilliseconds = 250;
    private const int MaxGenericValueLength = 256;

    internal readonly record struct ScanMatch(JsonNode Node, string RuleId)
    {
        public string Path => Node.GetPath();
    }

    /// <param name="Accept">
    /// Validates the <c>value</c> group (or whole match); the second argument is the
    /// Shannon-entropy threshold that only the generic rules apply.
    /// </param>
    internal sealed record ValueRule(
        string Id,
        Regex Pattern,
        Func<string, double, bool> Accept);

    internal static readonly ValueRule[] ValueRules =
    [
        // gitleaks: private-key (header plus the start of a base64 body).
        new("private-key", PrivateKeyRegex(), static (_, _) => true),
        new("private-key-base64", Base64PemRegex(), static (value, _) => IsBase64PrivateKey(value)),
        // gitleaks: aws-access-token
        new("aws-access-key-id", AwsAccessKeyIdRegex(),
            static (value, _) => !value.EndsWith("EXAMPLE", StringComparison.Ordinal)),
        new(AwsSecretRuleId, AwsSecretAssignmentRegex(), static (value, _) => !IsPlaceholder(value)),
        // gitleaks: github-pat, github-oauth, github-app-token, github-refresh-token
        new("github-token", GitHubTokenRegex(), static (_, _) => true),
        // gitleaks: github-fine-grained-pat
        new("github-fine-grained-pat", GitHubFineGrainedPatRegex(), static (_, _) => true),
        // gitleaks: gitlab-pat, gitlab-pat-routable
        new("gitlab-pat", GitLabPatRegex(), static (_, _) => true),
        // gitleaks: slack-bot-token, slack-user-token, slack-app-token, slack-legacy-*
        new("slack-token", SlackTokenRegex(), static (_, _) => true),
        // gitleaks: slack-webhook-url
        new("slack-webhook-url", SlackWebhookRegex(), static (_, _) => true),
        // gitleaks: stripe-access-token (secret and restricted keys only)
        new("stripe-secret-key", StripeKeyRegex(), static (_, _) => true),
        // gitleaks: gcp-api-key
        new("google-api-key", GoogleApiKeyRegex(), static (value, _) => !IsPlaceholder(value)),
        // gitleaks: jwt, plus a decoded-header check.
        new("jwt", JwtRegex(), static (value, _) => HasJwtHeader(value)),
        new("url-credentials", UrlCredentialsRegex(),
            static (value, _) => value.Length >= 3 && !IsPlaceholder(value)),
        // gitleaks: age-secret-key
        new("age-secret-key", AgeSecretKeyRegex(), static (_, _) => true),
        new("bearer-token", BearerTokenRegex(), IsNonTrivialGenericValue),
        // gitleaks: generic-api-key (simplified: keyword must end the key token).
        new("generic-assignment", GenericAssignmentRegex(), IsNonTrivialGenericValue),
    ];

    internal static IEnumerable<string> RuleIds =>
        ValueRules.Select(rule => rule.Id).Append(KeyedFieldRuleId).Distinct(StringComparer.Ordinal);

    /// <summary>
    /// Returns at most one match per rule per string value. A regex timeout fails
    /// closed with a fixed safe category.
    /// </summary>
    internal static List<ScanMatch> Scan(
        JsonNode? root,
        CancellationToken cancellationToken,
        double genericMinEntropy = DefaultGenericMinEntropy,
        IReadOnlyList<ValueRule>? rules = null,
        IReadOnlySet<string>? disabledRules = null)
    {
        var matches = new List<ScanMatch>();
        var context = new ScanContext(
            (rules ?? ValueRules).Where(rule => disabledRules?.Contains(rule.Id) != true).ToArray(),
            disabledRules?.Contains(AwsSecretRuleId) != true,
            disabledRules?.Contains(KeyedFieldRuleId) != true,
            genericMinEntropy,
            matches);
        try
        {
            Visit(root, keyContext: null, owner: null, context, cancellationToken);
        }
        catch (RegexMatchTimeoutException)
        {
            throw new KubernetesReadException(
                "The credential scan did not complete.",
                KubernetesErrorCategory.CredentialScanFailed);
        }

        return matches;
    }

    /// <param name="owner">
    /// The outer string value when visiting a JSON document embedded in a string;
    /// matches are reported against, and redact, that outer value.
    /// </param>
    private static void Visit(
        JsonNode? node,
        string? keyContext,
        JsonNode? owner,
        ScanContext context,
        CancellationToken cancellationToken)
    {
        switch (node)
        {
            case JsonObject jsonObject:
                foreach (var (name, child) in jsonObject)
                {
                    // `{name: X, value: Y}` (env vars, Helm `set` lists) keys Y by X.
                    var childKey = name == "value" && StringValue(jsonObject["name"]) is { } siblingName
                        ? siblingName
                        : name;
                    Visit(child, childKey, owner, context, cancellationToken);
                }

                break;
            case JsonArray jsonArray:
                string? previous = null;
                foreach (var child in jsonArray)
                {
                    // `["--client-secret", Y]` container args key Y by the preceding flag.
                    var childKey = previous is { Length: > 1 } flag && flag[0] == '-' && !flag.Contains('=')
                        ? flag.TrimStart('-')
                        : null;
                    Visit(child, childKey, owner, context, cancellationToken);
                    previous = StringValue(child);
                }

                break;
            case JsonValue when StringValue(node) is { } value:
                cancellationToken.ThrowIfCancellationRequested();
                if (ParseEmbeddedJson(value) is { } embedded)
                {
                    // For example kubectl.kubernetes.io/last-applied-configuration:
                    // scan it as a tree so keys and escaped newlines are decoded.
                    Visit(embedded, keyContext: null, owner ?? node, context, cancellationToken);
                }
                else
                {
                    ScanString(owner ?? node, value, keyContext, context, cancellationToken);
                }

                break;
        }
    }

    private static void ScanString(
        JsonNode node,
        string value,
        string? keyContext,
        ScanContext context,
        CancellationToken cancellationToken)
    {
        if (IsKubeMcpSafeValue(value))
        {
            return;
        }

        foreach (var rule in context.Rules)
        {
            for (var match = rule.Pattern.Match(value); match.Success; match = match.NextMatch())
            {
                // Each match call is bounded by the regex timeout; the request
                // deadline bounds the number of rejected candidates.
                cancellationToken.ThrowIfCancellationRequested();
                var group = match.Groups["value"];
                if (rule.Accept(group.Success ? group.Value : match.Value, context.MinEntropy))
                {
                    context.Matches.Add(new ScanMatch(node, rule.Id));
                    break;
                }
            }
        }

        if (keyContext is null)
        {
            return;
        }

        if (context.AwsKeyedRule && AwsSecretKeyNameRegex().IsMatch(keyContext) && AwsSecretValueRegex().IsMatch(value))
        {
            context.Matches.Add(new ScanMatch(node, AwsSecretRuleId));
        }

        if (context.KeyedFieldRule &&
            KeyedSecretNameRegex().IsMatch(keyContext) &&
            !DigestKeyNameRegex().IsMatch(keyContext) &&
            IsNonTrivialGenericValue(value, context.MinEntropy))
        {
            context.Matches.Add(new ScanMatch(node, KeyedFieldRuleId));
        }
    }

    private static JsonNode? ParseEmbeddedJson(string value)
    {
        var trimmed = value.AsSpan().Trim();
        if (trimmed.Length < 2 || !(trimmed[0] == '{' && trimmed[^1] == '}' || trimmed[0] == '[' && trimmed[^1] == ']'))
        {
            return null;
        }

        try
        {
            return JsonNode.Parse(value);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private sealed record ScanContext(
        ValueRule[] Rules,
        bool AwsKeyedRule,
        bool KeyedFieldRule,
        double MinEntropy,
        List<ScanMatch> Matches);

    private static string? StringValue(JsonNode? node) =>
        node is JsonValue value && value.GetValueKind() == JsonValueKind.String
            ? value.GetValue<string>()
            : null;

    /// <summary>
    /// Values kube-mcp itself produces: Secret HMAC fingerprints and redaction markers.
    /// </summary>
    internal static bool IsKubeMcpSafeValue(string value) =>
        FingerprintRegex().IsMatch(value) || RedactionMarkerRegex().IsMatch(value);

    internal static string RedactionMarker(string ruleId) => $"[redacted:{ruleId}]";

    internal static bool IsNonTrivialGenericValue(string value, double minEntropy)
    {
        if (value.Length is < 8 or > MaxGenericValueLength ||
            value.Any(char.IsWhiteSpace) ||
            IsPlaceholder(value) ||
            NonSecretShapeRegex().IsMatch(value))
        {
            return false;
        }

        // Kubernetes object names and namespace/name references commonly follow
        // secret-like keys; UUID-shaped tokens do not get this exemption.
        if (KubernetesNameShapeRegex().IsMatch(value) && !UuidRegex().IsMatch(value))
        {
            return false;
        }

        var classes = 0;
        classes += value.Any(char.IsAsciiLetterLower) ? 1 : 0;
        classes += value.Any(char.IsAsciiLetterUpper) ? 1 : 0;
        classes += value.Any(char.IsAsciiDigit) ? 1 : 0;
        classes += value.Any(static c => !char.IsAsciiLetterOrDigit(c)) ? 1 : 0;
        return classes >= 2 && ShannonEntropy(value) >= minEntropy;
    }

    internal static double ShannonEntropy(string value)
    {
        if (value.Length == 0)
        {
            return 0;
        }

        var counts = new Dictionary<char, int>();
        foreach (var c in value)
        {
            counts[c] = counts.GetValueOrDefault(c) + 1;
        }

        var entropy = 0.0;
        foreach (var count in counts.Values)
        {
            var p = (double)count / value.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static bool IsPlaceholder(string value)
    {
        if (value.StartsWith('$') || value.Contains("${", StringComparison.Ordinal) ||
            value.Contains("$(", StringComparison.Ordinal) || value.Contains("{{", StringComparison.Ordinal) ||
            value.Contains("%s", StringComparison.Ordinal) || (value.StartsWith('<') && value.EndsWith('>')))
        {
            return true;
        }

        if (value.All(c => c == value[0]))
        {
            return true;
        }

        return PlaceholderWordRegex().IsMatch(value);
    }

    private static bool IsBase64PrivateKey(string value)
    {
        var length = value.Length - (value.Length % 4);
        var buffer = new byte[length / 4 * 3];
        return Convert.TryFromBase64String(value[..length], buffer, out var written) &&
            Encoding.ASCII.GetString(buffer, 0, written).Contains("PRIVATE KEY-----", StringComparison.Ordinal);
    }

    private static bool HasJwtHeader(string token)
    {
        var header = token[..token.IndexOf('.')];
        var padded = header.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        var buffer = new byte[padded.Length];
        if (!Convert.TryFromBase64String(padded, buffer, out var written) || written == 0 || buffer[0] != (byte)'{')
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(buffer.AsMemory(0, written));
            return document.RootElement.ValueKind == JsonValueKind.Object &&
                (document.RootElement.TryGetProperty("alg", out _) ||
                 document.RootElement.TryGetProperty("typ", out _));
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private const RegexOptions Options = RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;

    // Newlines may appear literally or JSON-escaped (for example inside the
    // kubectl last-applied-configuration annotation).
    [GeneratedRegex(
        @"-----BEGIN[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----(?:\s|\\[rn]){1,4}" +
        @"(?:[A-Za-z-]{1,40}:[^\r\n\\]{1,200}(?:\s|\\[rn]){1,4}){0,4}[A-Za-z0-9+/=]{32}",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex PrivateKeyRegex();

    // Base64 of "-----BEGIN"; the decoded text must name a private key.
    [GeneratedRegex(@"LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}={0,2}", Options, MatchTimeoutMilliseconds)]
    private static partial Regex Base64PemRegex();

    [GeneratedRegex(@"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex AwsAccessKeyIdRegex();

    [GeneratedRegex(
        @"(?i)aws[\w.-]{0,20}?secret[\w.-]{0,20}[""']?[ \t]{0,3}(?:=|:=|=>|:)[ \t]{0,3}[""']?" +
        @"(?<value>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex AwsSecretAssignmentRegex();

    [GeneratedRegex(@"\bgh[pousr]_[A-Za-z0-9]{36}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex GitHubTokenRegex();

    [GeneratedRegex(@"\bgithub_pat_\w{82}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex GitHubFineGrainedPatRegex();

    [GeneratedRegex(@"\bglpat-[\w.-]{20,64}", Options, MatchTimeoutMilliseconds)]
    private static partial Regex GitLabPatRegex();

    [GeneratedRegex(
        @"\b(?:xox[abposr]-(?:[0-9]{10,13}-){1,3}[A-Za-z0-9-]{8,64}|xapp-\d-[A-Z0-9]{9,12}-\d{10,14}-[a-f0-9]{32,80})",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex SlackTokenRegex();

    [GeneratedRegex(
        @"https?://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex SlackWebhookRegex();

    [GeneratedRegex(@"\b(?:sk|rk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex StripeKeyRegex();

    [GeneratedRegex(@"\bAIza[\w-]{35}(?![\w-])", Options, MatchTimeoutMilliseconds)]
    private static partial Regex GoogleApiKeyRegex();

    [GeneratedRegex(
        @"\bey[A-Za-z0-9_-]{15,1024}\.ey[A-Za-z0-9_-]{15,8192}\.[A-Za-z0-9_-]{0,1024}",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex JwtRegex();

    [GeneratedRegex(
        @"(?i)\b[a-z][a-z0-9+.-]{1,30}://[^\s:@/?#]{0,128}:(?<value>[^\s@/?#]{1,256})@[a-z0-9\[]",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex UrlCredentialsRegex();

    [GeneratedRegex(@"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b", Options, MatchTimeoutMilliseconds)]
    private static partial Regex AgeSecretKeyRegex();

    [GeneratedRegex(@"(?i)\bbearer[ \t]+(?<value>[A-Za-z0-9._~+/-]{8,4096}=*)", Options, MatchTimeoutMilliseconds)]
    private static partial Regex BearerTokenRegex();

    // The keyword must end the key token (`DB_PASSWORD=`, `"apiKey":`, `--token=`),
    // so `secretName:` or `tokenTTL=` do not match.
    [GeneratedRegex(
        @"(?i)(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_.-]?key|access[_.-]?key|auth[_.-]?key|" +
        @"private[_.-]?key|credentials?)[""']?[ \t]{0,3}(?:=|:=|=>|:)[ \t]{0,3}[""'`]?" +
        @"(?<value>[^\s""'`;,&|<>(){}\[\]]{8,256})",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex GenericAssignmentRegex();

    [GeneratedRegex(
        @"(?i)(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_.-]?key|access[_.-]?key|auth[_.-]?key|" +
        @"private[_.-]?key|credentials?)$",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex KeyedSecretNameRegex();

    // Helm `checksum/secret` and similar keys hold digests of secrets, not secrets.
    [GeneratedRegex(@"(?i)checksum|hash|digest|fingerprint", Options, MatchTimeoutMilliseconds)]
    private static partial Regex DigestKeyNameRegex();

    [GeneratedRegex(@"(?i)(?:aws[_.-]?)?secret[_.-]?access[_.-]?key$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex AwsSecretKeyNameRegex();

    [GeneratedRegex(@"^[A-Za-z0-9/+]{40}$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex AwsSecretValueRegex();

    [GeneratedRegex(@"^hmac-sha256:[0-9a-f]{32}$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex FingerprintRegex();

    [GeneratedRegex(@"^\[redacted:[a-z0-9-]{1,64}\]$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex RedactionMarkerRegex();

    [GeneratedRegex(
        @"(?i)example|placeholder|redacted|changeit|your[_-]|replace[_-]?me|xxxx|\*\*\*|\.\.\.",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex PlaceholderWordRegex();

    // Paths, URLs without credentials, digests, booleans, numbers, and
    // environment-variable name references (`AUTHELIA_OIDC_CLIENT_SECRET`).
    [GeneratedRegex(
        @"^(?:[/~.]|[a-z][a-z0-9+.-]*://|(?:sha1|sha256|sha512|md5):[0-9a-f]+$|(?i:true|false|null)$|[0-9.]+$|" +
        @"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$)",
        Options, MatchTimeoutMilliseconds)]
    private static partial Regex NonSecretShapeRegex();

    [GeneratedRegex(@"^[a-z0-9]+(?:[-./][a-z0-9]+)+$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex KubernetesNameShapeRegex();

    [GeneratedRegex(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", Options, MatchTimeoutMilliseconds)]
    private static partial Regex UuidRegex();
}
